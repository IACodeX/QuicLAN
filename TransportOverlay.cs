using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace QuicLan;

internal static partial class Program
{
    private enum PacketType : byte { Hello = 1, IpPacket = 2, Control = 3 }

    private readonly record struct DecodedPacket(PacketType Type, ulong Sequence, ulong SessionId, PeerId Sender, byte[] Payload);
    private readonly record struct PacketHeader(PacketType Type, ulong Sequence, ulong SessionId, PeerId Sender);
    private readonly record struct SendJob(PeerState Peer, byte[] Payload, bool PreferQuic);
    private readonly record struct Ipv4Info(uint Source, uint Destination);

    private readonly struct PeerId : IEquatable<PeerId>, IComparable<PeerId>
    {
        public readonly ulong A;
        public readonly ulong B;
        public PeerId(ulong a, ulong b) { A = a; B = b; }
        public static PeerId FromSpan(ReadOnlySpan<byte> bytes) => new(BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]), BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8, 8)));
        public static PeerId FromPublicKey(byte[] publicKey) => FromSpan(SHA256.HashData(publicKey).AsSpan(0, 16));
        public void WriteTo(Span<byte> dest)
        {
            BinaryPrimitives.WriteUInt64BigEndian(dest[..8], A);
            BinaryPrimitives.WriteUInt64BigEndian(dest.Slice(8, 8), B);
        }
        public bool Equals(PeerId other) => A == other.A && B == other.B;
        public override bool Equals(object? obj) => obj is PeerId other && Equals(other);
        public override int GetHashCode() => HashCode.Combine(A, B);
        public int CompareTo(PeerId other)
        {
            int c = A.CompareTo(other.A);
            return c != 0 ? c : B.CompareTo(other.B);
        }
        public string ToFullString()
        {
            Span<byte> b = stackalloc byte[16];
            WriteTo(b);
            return Convert.ToHexString(b).ToLowerInvariant();
        }

        public override string ToString()
        {
            Span<byte> b = stackalloc byte[16];
            WriteTo(b);
            return Convert.ToHexString(b[..6]).ToLowerInvariant();
        }
    }

    private sealed class PeerState : IDisposable
    {
        private readonly object _cryptoLock = new();
        private readonly ConcurrentDictionary<ulong, ReplayState> _replayBySession = new();
        private readonly List<CryptoBox> _retiredCrypto = [];
        private int _online;
        private int _lanReady;
        private int _lobbyState;
        private byte[]? _dhPublicFingerprint;
        private CryptoBox? _dataCrypto;

        public PeerState(PeerId id, IPEndPoint ep)
        {
            Id = id;
            EndPoint = ep;
        }

        public PeerId Id { get; }
        public string Name { get; set; } = "peer";
        public uint VirtualIp { get; set; }
        public int Mtu { get; set; } = DefaultMtu;
        public IPEndPoint EndPoint { get; set; }
        public IPEndPoint? QuicEndPoint { get; set; }
        public byte[]? IdentityPublicKey { get; set; }
        public QuicPeerLink? QuicLink { get; set; }
        public long LastSeenMs { get; set; } = Environment.TickCount64;
        public CryptoBox? DataCrypto => Volatile.Read(ref _dataCrypto);
        public bool IsOnline => Volatile.Read(ref _online) == 1;
        public bool IsLanReady => Volatile.Read(ref _lanReady) == 1;
        public LobbyMemberState LobbyState => (LobbyMemberState)Volatile.Read(ref _lobbyState);
        public bool IsHost { get; set; }
        public string LanSessionId { get; set; } = "";
        public LanMode LanMode { get; set; } = LanMode.None;
        public string IpMode { get; set; } = "auto";
        public bool MarkOnline() => Interlocked.Exchange(ref _online, 1) == 0;
        public bool MarkDisconnected()
        {
            Volatile.Write(ref _lanReady, 0);
            Volatile.Write(ref _lobbyState, (int)LobbyMemberState.Reconnecting);
            return Interlocked.Exchange(ref _online, 0) == 1;
        }
        public void SetLanReady(bool ready)
        {
            Volatile.Write(ref _lanReady, ready ? 1 : 0);
            Volatile.Write(ref _lobbyState, ready ? (int)LobbyMemberState.InLan : (int)LobbyMemberState.Lobby);
        }
        public void SetLobbyState(LobbyMemberState state)
        {
            Volatile.Write(ref _lobbyState, (int)state);
            Volatile.Write(ref _lanReady, state == LobbyMemberState.InLan ? 1 : 0);
            if (state is LobbyMemberState.Lobby or LobbyMemberState.Reconnecting)
                LanSessionId = "";
        }

        public bool AcceptReplay(ulong sessionId, ulong seq)
        {
            long now = Environment.TickCount64;
            var replay = _replayBySession.GetOrAdd(sessionId, _ => new ReplayState());
            replay.LastSeenMs = now;
            if (_replayBySession.Count > 8)
            {
                foreach (var key in _replayBySession.OrderByDescending(kv => kv.Value.LastSeenMs).Skip(8).Select(kv => kv.Key).ToArray())
                    _replayBySession.TryRemove(key, out _);
            }
            return replay.Window.Accept(seq);
        }

        public bool HasSameDhPublicKey(byte[] sessionDhPublicKey, out byte[] fingerprint)
        {
            fingerprint = SHA256.HashData(sessionDhPublicKey);
            lock (_cryptoLock)
                return _dhPublicFingerprint is not null && _dhPublicFingerprint.AsSpan().SequenceEqual(fingerprint);
        }

        public void SetDataCrypto(CryptoBox crypto, byte[] fingerprint)
        {
            lock (_cryptoLock)
            {
                if (_dhPublicFingerprint is not null && _dhPublicFingerprint.AsSpan().SequenceEqual(fingerprint))
                {
                    crypto.Dispose();
                    return;
                }

                var old = _dataCrypto;
                _dataCrypto = crypto;
                _dhPublicFingerprint = fingerprint;

                // No se dispone inmediatamente: otros hilos pueden estar cifrando/descifrando con la clave anterior.
                // Se retira en Dispose(), evitando carreras raras durante rotaciones de sesion.
                if (old is not null) _retiredCrypto.Add(old);
            }
        }

        public void ReplaceQuicLink(QuicPeerLink link, CancellationToken ct)
        {
            lock (_cryptoLock)
            {
                var old = QuicLink;
                QuicLink = link;
                old?.Dispose();
                link.Start(ct);
            }
        }

        public void Dispose()
        {
            QuicLink?.Dispose();
            _dataCrypto?.Dispose();
            lock (_cryptoLock)
            {
                foreach (var crypto in _retiredCrypto) crypto.Dispose();
                _retiredCrypto.Clear();
            }
        }
    }

    private sealed class ReplayState
    {
        public ReplayWindow Window { get; } = new();
        public long LastSeenMs;
    }

    private sealed class ReplayWindow
    {
        private const int Window = 4096;
        private readonly object _lock = new();
        private ulong _max;
        private readonly HashSet<ulong> _recent = [];
        public bool Accept(ulong seq)
        {
            if (seq == 0) return false;
            lock (_lock)
            {
                if (_max > Window && seq < _max - Window) return false;
                if (!_recent.Add(seq)) return false;
                if (seq > _max) _max = seq;
                if (_recent.Count > Window * 2)
                {
                    ulong floor = _max > Window ? _max - Window : 0;
                    _recent.RemoveWhere(x => x < floor);
                }
                return true;
            }
        }
    }

    private sealed class CryptoBox : IDisposable
    {
        private const int TagSize = 16;
        private readonly byte[] _key;
        private readonly AesGcm _aes;
        public CryptoBox(byte[] key)
        {
            _key = key.ToArray();
            _aes = new AesGcm(_key, TagSize);
        }

        public void WriteNonce(PeerId sender, ulong sessionId, ulong seq, Span<byte> nonce)
        {
            // Calculado sin cache no acotada: evita DoS de memoria con sender/sessionId falsos.
            Span<byte> input = stackalloc byte[24];
            sender.WriteTo(input[..16]);
            BinaryPrimitives.WriteUInt64BigEndian(input.Slice(16, 8), sessionId);

            Span<byte> hash = stackalloc byte[32];
            using var h = new HMACSHA256(_key);
            h.TryComputeHash(input, hash, out _);

            BinaryPrimitives.WriteUInt32BigEndian(nonce[..4], BinaryPrimitives.ReadUInt32BigEndian(hash[..4]));
            BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4, 8), seq);
        }

        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad) =>
            _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
        {
            try { _aes.Decrypt(nonce, ciphertext, tag, plaintext, aad); return true; }
            catch (CryptographicException) { return false; }
        }

        public void Dispose()
        {
            _aes.Dispose();
            CryptographicOperations.ZeroMemory(_key);
        }
    }

    private static class PacketCodec
    {
        private const uint Magic = 0x514C414E; // QLAN
        private const byte Version = 5;
        public const int HeaderLength = 40;
        public const int TagLength = 16;

        public static bool LooksLikeOverlayPacket(ReadOnlySpan<byte> b) =>
            b.Length >= HeaderLength + TagLength && BinaryPrimitives.ReadUInt32BigEndian(b) == Magic && b[4] == Version;

        public static byte[] Encode(PacketType type, ulong seq, ulong sessionId, PeerId senderId, ReadOnlySpan<byte> payload, CryptoBox crypto)
        {
            var packet = new byte[HeaderLength + payload.Length + TagLength];
            var header = packet.AsSpan(0, HeaderLength);
            BinaryPrimitives.WriteUInt32BigEndian(header, Magic);
            header[4] = Version;
            header[5] = (byte)type;
            header[6] = 0;
            header[7] = 0;
            BinaryPrimitives.WriteUInt64BigEndian(header.Slice(8, 8), seq);
            BinaryPrimitives.WriteUInt64BigEndian(header.Slice(16, 8), sessionId);
            senderId.WriteTo(header.Slice(24, 16));
            Span<byte> nonce = stackalloc byte[12];
            crypto.WriteNonce(senderId, sessionId, seq, nonce);
            crypto.Encrypt(nonce, payload, packet.AsSpan(HeaderLength, payload.Length), packet.AsSpan(HeaderLength + payload.Length, TagLength), header);
            return packet;
        }

        public static bool TryReadHeader(byte[] packet, out PacketHeader header)
        {
            header = default;
            if (!LooksLikeOverlayPacket(packet)) return false;
            var span = packet.AsSpan(0, HeaderLength);
            var type = (PacketType)span[5];
            if (type is not (PacketType.Hello or PacketType.IpPacket or PacketType.Control)) return false;
            ulong seq = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(8, 8));
            ulong sessionId = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(16, 8));
            var sender = PeerId.FromSpan(span.Slice(24, 16));
            header = new PacketHeader(type, seq, sessionId, sender);
            return true;
        }

        public static bool TryDecode(byte[] packet, CryptoBox crypto, PacketHeader header, out DecodedPacket decoded)
        {
            decoded = default;
            int cipherLen = packet.Length - HeaderLength - TagLength;
            if (cipherLen < 0) return false;
            var span = packet.AsSpan();
            var plaintext = new byte[cipherLen];
            Span<byte> nonce = stackalloc byte[12];
            crypto.WriteNonce(header.Sender, header.SessionId, header.Sequence, nonce);
            if (!crypto.TryDecrypt(nonce, span.Slice(HeaderLength, cipherLen), span.Slice(HeaderLength + cipherLen, TagLength), plaintext, span.Slice(0, HeaderLength)))
                return false;
            decoded = new DecodedPacket(header.Type, header.Sequence, header.SessionId, header.Sender, plaintext);
            return true;
        }
    }

    private sealed record HelloInfo(
        uint VirtualIp,
        ushort IpSalt,
        int Mtu,
        ushort QuicPort,
        long TimestampMs,
        byte[] IdentityPublicKey,
        byte[] SessionDhPublicKey,
        byte[] Signature,
        string Name)
    {
        public bool Verify(PeerId expectedId, ulong sessionId)
        {
            try
            {
                if (!PeerId.FromPublicKey(IdentityPublicKey).Equals(expectedId)) return false;
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(IdentityPublicKey, out _);
                byte[] data = HelloPayload.BuildSignedData(sessionId, VirtualIp, IpSalt, Mtu, QuicPort, TimestampMs, IdentityPublicKey, SessionDhPublicKey, Name);
                return ecdsa.VerifyData(data, Signature, HashAlgorithmName.SHA256);
            }
            catch
            {
                return false;
            }
        }
    }

    private static class HelloPayload
    {
        private static readonly byte[] Domain = Encoding.ASCII.GetBytes("QuicLAN hello v5\0");

        public static byte[] Create(ulong sessionId, uint virtualIp, ushort ipSalt, int mtu, ushort quicPort, string name, byte[] identityPublicKey, byte[] sessionDhPublicKey, ECDsa signer)
        {
            name = string.IsNullOrWhiteSpace(name) ? "peer" : name.Trim();
            var nameBytes = Encoding.UTF8.GetBytes(name);
            if (nameBytes.Length > 80)
            {
                nameBytes = nameBytes.AsSpan(0, 80).ToArray();
                name = Encoding.UTF8.GetString(nameBytes);
            }

            long timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            byte[] signedData = BuildSignedData(sessionId, virtualIp, ipSalt, mtu, quicPort, timestampMs, identityPublicKey, sessionDhPublicKey, name);
            byte[] signature = signer.SignData(signedData, HashAlgorithmName.SHA256);
            if (identityPublicKey.Length > ushort.MaxValue || sessionDhPublicKey.Length > ushort.MaxValue || signature.Length > ushort.MaxValue)
                throw new InvalidOperationException("Material criptografico demasiado grande.");

            var b = new byte[25 + identityPublicKey.Length + sessionDhPublicKey.Length + signature.Length + nameBytes.Length];
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(0, 4), virtualIp);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4, 2), (ushort)mtu);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6, 2), ipSalt);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(8, 2), quicPort);
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(10, 8), timestampMs);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(18, 2), (ushort)identityPublicKey.Length);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20, 2), (ushort)sessionDhPublicKey.Length);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22, 2), (ushort)signature.Length);
            b[24] = (byte)nameBytes.Length;
            int o = 25;
            identityPublicKey.CopyTo(b.AsSpan(o)); o += identityPublicKey.Length;
            sessionDhPublicKey.CopyTo(b.AsSpan(o)); o += sessionDhPublicKey.Length;
            signature.CopyTo(b.AsSpan(o)); o += signature.Length;
            nameBytes.CopyTo(b.AsSpan(o));
            return b;
        }

        public static bool TryParse(ReadOnlySpan<byte> b, out HelloInfo hello)
        {
            hello = default!;
            if (b.Length < 25) return false;
            uint ip = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(0, 4));
            int mtu = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(4, 2));
            ushort ipSalt = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(6, 2));
            ushort quicPort = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(8, 2));
            long timestamp = BinaryPrimitives.ReadInt64BigEndian(b.Slice(10, 8));
            int idLen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(18, 2));
            int dhLen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(20, 2));
            int sigLen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(22, 2));
            int nameLen = b[24];
            if (idLen is < 64 or > 512 || dhLen is < 64 or > 512 || sigLen is < 32 or > 256 || quicPort == 0) return false;
            if (b.Length != 25 + idLen + dhLen + sigLen + nameLen) return false;
            int o = 25;
            byte[] idPub = b.Slice(o, idLen).ToArray(); o += idLen;
            byte[] dhPub = b.Slice(o, dhLen).ToArray(); o += dhLen;
            byte[] sig = b.Slice(o, sigLen).ToArray(); o += sigLen;
            string name = Encoding.UTF8.GetString(b.Slice(o, nameLen));
            hello = new HelloInfo(ip, ipSalt, mtu, quicPort, timestamp, idPub, dhPub, sig, string.IsNullOrWhiteSpace(name) ? "peer" : name);
            return true;
        }

        public static byte[] BuildSignedData(ulong sessionId, uint virtualIp, ushort ipSalt, int mtu, ushort quicPort, long timestampMs, byte[] identityPublicKey, byte[] sessionDhPublicKey, string name)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            var b = new byte[Domain.Length + 8 + 4 + 2 + 2 + 2 + 8 + 2 + 2 + 1 + identityPublicKey.Length + sessionDhPublicKey.Length + nameBytes.Length];
            int o = 0;
            Domain.CopyTo(b.AsSpan(o)); o += Domain.Length;
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(o, 8), sessionId); o += 8;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o, 4), virtualIp); o += 4;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)mtu); o += 2;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), ipSalt); o += 2;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), quicPort); o += 2;
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(o, 8), timestampMs); o += 8;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)identityPublicKey.Length); o += 2;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)sessionDhPublicKey.Length); o += 2;
            b[o++] = (byte)nameBytes.Length;
            identityPublicKey.CopyTo(b.AsSpan(o)); o += identityPublicKey.Length;
            sessionDhPublicKey.CopyTo(b.AsSpan(o)); o += sessionDhPublicKey.Length;
            nameBytes.CopyTo(b.AsSpan(o));
            return b;
        }
    }

    private sealed class TrackerClient : IDisposable
    {
        private const long ProtocolId = 0x0000041727101980;
        private readonly UdpClient _udp;
        private readonly StunClient _stun;
        private readonly byte[] _infoHash;
        private readonly byte[] _peerId;
        private readonly int _localPort;
        private readonly TrackerEndpoint[] _trackers;
        private readonly bool _verbose;
        private readonly ConcurrentDictionary<int, PendingTrackerRequest> _pending = new();
        public event Action<IPEndPoint>? PeerDiscovered;

        public TrackerClient(UdpClient udp, StunClient stun, byte[] infoHash, byte[] peerId, int localPort, string[] trackers, bool verbose)
        {
            if (infoHash.Length != 20) throw new ArgumentException("infoHash debe tener 20 bytes.", nameof(infoHash));
            _udp = udp;
            _stun = stun;
            _infoHash = infoHash.ToArray();
            _peerId = peerId;
            _localPort = localPort;
            _verbose = verbose;
            _trackers = trackers.Select(TrackerEndpoint.TryParse).Where(x => x is not null).Cast<TrackerEndpoint>().ToArray();
        }

        public async Task RunAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                IPEndPoint? publicEp = await _stun.GetMappedEndpointAsync(ct);
                ushort announcePort = (ushort)(publicEp?.Port ?? _localPort);
                await Task.WhenAll(_trackers.Select(async tracker =>
                {
                    try { await AnnounceAsync(tracker, announcePort, ct); }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex) { if (_verbose) Console.WriteLine($"Tracker {tracker}: {ex.Message}"); }
                }));
                await Task.Delay(TimeSpan.FromMinutes(2), ct);
            }
        }

        public bool TryHandleResponse(byte[] data, IPEndPoint remote)
        {
            if (data.Length < 8) return false;
            int action = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(0, 4));
            int tx = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(4, 4));
            if (!_pending.TryGetValue(tx, out var pending)) return false;
            if (!pending.Remote.Equals(remote)) return true;
            if (action == 3)
            {
                _pending.TryRemove(tx, out _);
                pending.Tcs.TrySetException(new InvalidDataException("Tracker devolvio error."));
                return true;
            }
            if (action != pending.ExpectedAction) return true;
            _pending.TryRemove(tx, out _);
            pending.Tcs.TrySetResult(data);
            return true;
        }

        private async Task AnnounceAsync(TrackerEndpoint tracker, ushort port, CancellationToken ct)
        {
            var remote = await tracker.ResolveAsync(ct);
            long connectionId = await ConnectAsync(remote, ct);
            int tx = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
            var req = new byte[98];
            BinaryPrimitives.WriteInt64BigEndian(req.AsSpan(0, 8), connectionId);
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(8, 4), 1);
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(12, 4), tx);
            _infoHash.CopyTo(req.AsSpan(16, 20));
            _peerId.CopyTo(req.AsSpan(36, 20));
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(80, 4), 0); // event none
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(84, 4), 0); // default IP
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(88, 4), RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue));
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(92, 4), 50);
            BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(96, 2), port);
            var response = await RequestAsync(remote, tx, 1, req, ct);
            ParseAnnounce(response);
        }

        private async Task<long> ConnectAsync(IPEndPoint remote, CancellationToken ct)
        {
            int tx = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
            var req = new byte[16];
            BinaryPrimitives.WriteInt64BigEndian(req.AsSpan(0, 8), ProtocolId);
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(8, 4), 0);
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(12, 4), tx);
            var response = await RequestAsync(remote, tx, 0, req, ct);
            if (response.Length < 16) throw new InvalidDataException("Respuesta connect invalida.");
            return BinaryPrimitives.ReadInt64BigEndian(response.AsSpan(8, 8));
        }

        private async Task<byte[]> RequestAsync(IPEndPoint remote, int tx, int expectedAction, byte[] request, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[tx] = new PendingTrackerRequest(remote, expectedAction, tcs);
            try
            {
                await _udp.SendAsync(request.AsMemory(), remote, ct);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                using (linked.Token.Register(() => tcs.TrySetCanceled(linked.Token)))
                    return await tcs.Task;
            }
            finally
            {
                _pending.TryRemove(tx, out _);
            }
        }

        private void ParseAnnounce(byte[] response)
        {
            if (response.Length < 20) return;
            for (int i = 20; i + 6 <= response.Length; i += 6)
            {
                var ip = new IPAddress(response.AsSpan(i, 4));
                ushort port = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(i + 4, 2));
                if (port == 0 || !IsPublicishIPv4(ip)) continue;
                PeerDiscovered?.Invoke(new IPEndPoint(ip, port));
            }
        }

        private static bool IsPublicishIPv4(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return b.Length == 4 && b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 &&
                   !(b[0] == 192 && b[1] == 168) && !(b[0] == 172 && b[1] >= 16 && b[1] <= 31) &&
                   !(b[0] == 169 && b[1] == 254) && !(b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_infoHash);
            CryptographicOperations.ZeroMemory(_peerId);
        }

        private readonly record struct PendingTrackerRequest(IPEndPoint Remote, int ExpectedAction, TaskCompletionSource<byte[]> Tcs);
    }

    private sealed class TrackerEndpoint
    {
        private readonly string _host;
        private readonly int _port;
        private IPEndPoint? _cached;
        private TrackerEndpoint(string host, int port) { _host = host; _port = port; }
        public static TrackerEndpoint? TryParse(string uriText)
        {
            if (!Uri.TryCreate(uriText, UriKind.Absolute, out var uri) || uri.Scheme != "udp" || uri.Port <= 0) return null;
            return new TrackerEndpoint(uri.Host, uri.Port);
        }
        public async Task<IPEndPoint> ResolveAsync(CancellationToken ct)
        {
            if (_cached is not null) return _cached;
            var addresses = await Dns.GetHostAddressesAsync(_host, ct);
            var address = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
            _cached = new IPEndPoint(address, _port);
            return _cached;
        }
        public override string ToString() => $"udp://{_host}:{_port}";
    }

    private sealed class StunClient
    {
        private static readonly (string Host, int Port)[] Servers =
        [
            ("stun.l.google.com", 19302),
            ("stun.cloudflare.com", 3478)
        ];
        private readonly UdpClient _udp;
        private readonly bool _verbose;
        private readonly ConcurrentDictionary<string, PendingStunRequest> _pending = new();
        public StunClient(UdpClient udp, bool verbose) { _udp = udp; _verbose = verbose; }

        public async Task<IPEndPoint?> GetMappedEndpointAsync(CancellationToken ct)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var tasks = Servers.Select(server => TryMappedEndpointFromServerAsync(server, linked.Token)).ToArray();

            while (tasks.Length > 0)
            {
                var done = await Task.WhenAny(tasks);
                try
                {
                    var endpoint = await done;
                    if (endpoint is not null)
                    {
                        linked.Cancel();
                        return endpoint;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { }

                tasks = tasks.Where(t => !ReferenceEquals(t, done)).ToArray();
            }

            return null;
        }

        private async Task<IPEndPoint?> TryMappedEndpointFromServerAsync((string Host, int Port) serverInfo, CancellationToken ct)
        {
            IPEndPoint? server = null;
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(serverInfo.Host, ct);
                var addr = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (addr is null) return null;
                server = new IPEndPoint(addr, serverInfo.Port);
                var tx = RandomNumberGenerator.GetBytes(12);
                var req = new byte[20];
                BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(0, 2), 0x0001);
                BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(2, 2), 0);
                BinaryPrimitives.WriteUInt32BigEndian(req.AsSpan(4, 4), 0x2112A442);
                tx.CopyTo(req.AsSpan(8, 12));
                var key = Convert.ToHexString(tx);
                var tcs = new TaskCompletionSource<IPEndPoint?>(TaskCreationOptions.RunContinuationsAsynchronously);
                _pending[key] = new PendingStunRequest(server, tcs);
                try
                {
                    await _udp.SendAsync(req.AsMemory(), server, ct);
                    using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                    using (linked.Token.Register(() => tcs.TrySetCanceled(linked.Token)))
                        return await tcs.Task;
                }
                finally { _pending.TryRemove(key, out _); }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                if (_verbose) Console.WriteLine($"STUN {server}: {ex.Message}");
                return null;
            }
        }

        public bool TryHandleResponse(byte[] data, IPEndPoint remote)
        {
            if (data.Length < 20) return false;
            if (BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(0, 2)) != 0x0101) return false;
            if (BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4, 4)) != 0x2112A442) return false;
            var key = Convert.ToHexString(data.AsSpan(8, 12));
            if (!_pending.TryGetValue(key, out var pending)) return true;
            if (!pending.Remote.Equals(remote)) return true;
            _pending.TryRemove(key, out _);
            pending.Tcs.TrySetResult(ParseXorMappedAddress(data));
            return true;
        }

        private static IPEndPoint? ParseXorMappedAddress(ReadOnlySpan<byte> data)
        {
            int length = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2, 2));
            int offset = 20;
            int end = Math.Min(data.Length, 20 + length);
            while (offset + 4 <= end)
            {
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
                ushort len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
                offset += 4;
                if (offset + len > end) break;
                if (type == 0x0020 && len >= 8 && data[offset + 1] == 0x01)
                {
                    ushort xPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
                    ushort port = (ushort)(xPort ^ 0x2112);
                    uint xAddr = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset + 4, 4));
                    uint addr = xAddr ^ 0x2112A442;
                    Span<byte> bytes = stackalloc byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(bytes, addr);
                    return new IPEndPoint(new IPAddress(bytes), port);
                }
                offset += (len + 3) & ~3;
            }
            return null;
        }

        private readonly record struct PendingStunRequest(IPEndPoint Remote, TaskCompletionSource<IPEndPoint?> Tcs);
    }
}
