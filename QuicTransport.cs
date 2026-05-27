using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

namespace QuicLan;

internal static partial class Program
{
    private static readonly SslApplicationProtocol QuicLanApplicationProtocol = new("quiclan-v5");
    private static readonly byte[] QuicLinkSignatureDomain = "QuicLAN QUIC link v5\0"u8.ToArray();

    private static X509Certificate2 BuildQuicCertificate(ECDsa identityKey, string name, PeerId localId)
    {
        string safeName = string.IsNullOrWhiteSpace(name) ? localId.ToString() : name.Trim();
        safeName = safeName.Replace(",", " ").Replace("=", " ").Replace("\"", " ");
        var req = new CertificateRequest($"CN=QuicLAN {safeName} {localId}", identityKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([
            new Oid("1.3.6.1.5.5.7.3.1"), // server auth
            new Oid("1.3.6.1.5.5.7.3.2")  // client auth
        ], false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
        return new X509Certificate2(cert.Export(X509ContentType.Pfx));
    }

    private sealed partial class QuicLanNode
    {
        private readonly ConcurrentDictionary<PeerId, byte> _quicConnecting = new();

        private async Task RunQuicListenerAsync(CancellationToken ct)
        {
            if (!QuicListener.IsSupported || !QuicConnection.IsSupported)
            {
                _quicReady.TrySetResult();
                Console.WriteLine("QUIC no está soportado por este runtime/sistema. Se usará fallback UDP si está habilitado.");
                return;
            }

            var listenerOptions = new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Any, _options.DataPort),
                ApplicationProtocols = [QuicLanApplicationProtocol],
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(BuildServerOptions())
            };

            await using var listener = await QuicListener.ListenAsync(listenerOptions, ct);
            _quicReady.TrySetResult();
            LogVerbose($"QUIC listener activo en 0.0.0.0:{_options.DataPort}");

            while (!ct.IsCancellationRequested)
            {
                QuicConnection connection;
                try { connection = await listener.AcceptConnectionAsync(ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { LogVerbose($"QUIC accept: {ex.Message}"); continue; }
                _ = RunQuicAcceptedConnectionAsync(connection, ct);
            }
        }

        private QuicServerConnectionOptions BuildServerOptions() => new()
        {
            DefaultStreamErrorCode = 0x514C0001,
            DefaultCloseErrorCode = 0x514C0002,
            IdleTimeout = TimeSpan.FromMinutes(3),
            KeepAliveInterval = TimeSpan.FromSeconds(20),
            MaxInboundBidirectionalStreams = 8,
            MaxInboundUnidirectionalStreams = 0,
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [QuicLanApplicationProtocol],
                ServerCertificate = _quicCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    TryGetPeerIdFromCertificate(certificate, out var peerId) && _peers.ContainsKey(peerId)
            }
        };

        private QuicClientConnectionOptions BuildClientOptions(PeerState peer) => new()
        {
            RemoteEndPoint = peer.QuicEndPoint!,
            DefaultStreamErrorCode = 0x514C0001,
            DefaultCloseErrorCode = 0x514C0002,
            IdleTimeout = TimeSpan.FromMinutes(3),
            KeepAliveInterval = TimeSpan.FromSeconds(20),
            MaxInboundBidirectionalStreams = 8,
            MaxInboundUnidirectionalStreams = 0,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [QuicLanApplicationProtocol],
                TargetHost = "quiclan-v5",
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = new X509CertificateCollection { _quicCertificate },
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    TryGetPeerIdFromCertificate(certificate, out var peerId) && peerId.Equals(peer.Id)
            }
        };

        private async Task EnsureQuicConnectionAsync(PeerState peer, CancellationToken ct)
        {
            if (_options.DisableQuic || peer.QuicLink is { IsOpen: true }) return;
            if (peer.QuicEndPoint is null || !IsUsableTransportEndpoint(peer.QuicEndPoint)) return;
            if (!_quicConnecting.TryAdd(peer.Id, 0)) return;

            try
            {
                if (!QuicConnection.IsSupported) return;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                var connection = await QuicConnection.ConnectAsync(BuildClientOptions(peer), timeout.Token);
                var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, timeout.Token);
                await WriteQuicIdentityFrameAsync(stream, timeout.Token);
                if (!await ReadAndValidateQuicIdentityFrameAsync(stream, peer, timeout.Token))
                    throw new AuthenticationException("El peer QUIC no coincide con la identidad esperada.");
                RegisterQuicLink(peer, connection, stream, _shutdown.Token);
                LogVerbose($"QUIC conectado con {peer.Name} en {peer.QuicEndPoint}");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex) { LogVerbose($"QUIC connect {peer.Name}: {ex.Message}"); }
            finally { _quicConnecting.TryRemove(peer.Id, out _); }
        }

        private async Task RunQuicAcceptedConnectionAsync(QuicConnection connection, CancellationToken outerCt)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(outerCt);
                timeout.CancelAfter(TimeSpan.FromSeconds(15));
                var stream = await connection.AcceptInboundStreamAsync(timeout.Token);
                await WriteQuicIdentityFrameAsync(stream, timeout.Token);
                var remoteIdentity = await ReadQuicIdentityFrameAsync(stream, timeout.Token);
                if (remoteIdentity is null)
                    throw new AuthenticationException("Preface QUIC inválido.");
                if (!_peers.TryGetValue(remoteIdentity.Value.PeerId, out var peer))
                    throw new AuthenticationException("Peer QUIC desconocido.");
                if (!VerifyQuicIdentityFrame(remoteIdentity.Value, peer))
                    throw new AuthenticationException("Firma QUIC inválida.");
                RegisterQuicLink(peer, connection, stream, _shutdown.Token);
                LogVerbose($"QUIC entrante de {peer.Name}");
            }
            catch (OperationCanceledException) when (outerCt.IsCancellationRequested) { }
            catch (Exception ex)
            {
                LogVerbose($"QUIC incoming: {ex.Message}");
                await connection.DisposeAsync();
            }
        }

        private void RegisterQuicLink(PeerState peer, QuicConnection connection, QuicStream stream, CancellationToken ct)
        {
            var link = new QuicPeerLink(this, peer, connection, stream);
            peer.ReplaceQuicLink(link, ct);
        }

        private async Task WriteQuicIdentityFrameAsync(Stream stream, CancellationToken ct)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            byte[] signed = BuildQuicIdentitySignedData(_localId, _sessionId, timestamp, GetLocalIp());
            byte[] signature = _identityKey.SignData(signed, HashAlgorithmName.SHA256);
            var frame = new byte[4 + 16 + 8 + 8 + 4 + 2 + signature.Length];
            "QLQ5"u8.CopyTo(frame);
            _localId.WriteTo(frame.AsSpan(4, 16));
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(20, 8), _sessionId);
            BinaryPrimitives.WriteInt64BigEndian(frame.AsSpan(28, 8), timestamp);
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(36, 4), GetLocalIp());
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(40, 2), (ushort)signature.Length);
            signature.CopyTo(frame.AsSpan(42));
            await stream.WriteAsync(frame, ct);
            await stream.FlushAsync(ct);
        }

        private async Task<bool> ReadAndValidateQuicIdentityFrameAsync(Stream stream, PeerState expectedPeer, CancellationToken ct)
        {
            var frame = await ReadQuicIdentityFrameAsync(stream, ct);
            return frame is not null && frame.Value.PeerId.Equals(expectedPeer.Id) && VerifyQuicIdentityFrame(frame.Value, expectedPeer);
        }

        private async Task<QuicIdentityFrame?> ReadQuicIdentityFrameAsync(Stream stream, CancellationToken ct)
        {
            byte[] fixedPart = new byte[42];
            if (!await ReadExactAsync(stream, fixedPart, ct)) return null;
            if (!fixedPart.AsSpan(0, 4).SequenceEqual("QLQ5"u8)) return null;
            var peerId = PeerId.FromSpan(fixedPart.AsSpan(4, 16));
            ulong sessionId = BinaryPrimitives.ReadUInt64BigEndian(fixedPart.AsSpan(20, 8));
            long timestamp = BinaryPrimitives.ReadInt64BigEndian(fixedPart.AsSpan(28, 8));
            uint virtualIp = BinaryPrimitives.ReadUInt32BigEndian(fixedPart.AsSpan(36, 4));
            int sigLen = BinaryPrimitives.ReadUInt16BigEndian(fixedPart.AsSpan(40, 2));
            if (sigLen is < 32 or > 256) return null;
            byte[] sig = new byte[sigLen];
            if (!await ReadExactAsync(stream, sig, ct)) return null;
            return new QuicIdentityFrame(peerId, sessionId, timestamp, virtualIp, sig);
        }

        private bool VerifyQuicIdentityFrame(QuicIdentityFrame frame, PeerState peer)
        {
            if (!frame.PeerId.Equals(peer.Id)) return false;
            if (peer.IdentityPublicKey is null) return false;
            if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - frame.TimestampMs) > TimeSpan.FromMinutes(30).TotalMilliseconds) return false;
            if (peer.VirtualIp != 0 && frame.VirtualIp != peer.VirtualIp) return false;
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(peer.IdentityPublicKey, out _);
                byte[] signed = BuildQuicIdentitySignedData(frame.PeerId, frame.SessionId, frame.TimestampMs, frame.VirtualIp);
                return ecdsa.VerifyData(signed, frame.Signature, HashAlgorithmName.SHA256);
            }
            catch { return false; }
        }

        private static byte[] BuildQuicIdentitySignedData(PeerId peerId, ulong sessionId, long timestampMs, uint virtualIp)
        {
            var b = new byte[QuicLinkSignatureDomain.Length + 16 + 8 + 8 + 4];
            int o = 0;
            QuicLinkSignatureDomain.CopyTo(b.AsSpan(o)); o += QuicLinkSignatureDomain.Length;
            peerId.WriteTo(b.AsSpan(o, 16)); o += 16;
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(o, 8), sessionId); o += 8;
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(o, 8), timestampMs); o += 8;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o, 4), virtualIp);
            return b;
        }

        private static bool TryGetPeerIdFromCertificate(X509Certificate? certificate, out PeerId peerId)
        {
            peerId = default;
            if (certificate is null) return false;
            try
            {
                using var cert = new X509Certificate2(certificate);
                using var ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa is null) return false;
                peerId = PeerId.FromPublicKey(ecdsa.ExportSubjectPublicKeyInfo());
                return true;
            }
            catch { return false; }
        }

        internal static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(offset), ct);
                if (read == 0) return false;
                offset += read;
            }
            return true;
        }

        private readonly record struct QuicIdentityFrame(PeerId PeerId, ulong SessionId, long TimestampMs, uint VirtualIp, byte[] Signature);
    }

    private sealed class QuicPeerLink : IDisposable
    {
        private readonly QuicLanNode _node;
        private readonly PeerState _peer;
        private readonly QuicConnection _connection;
        private readonly QuicStream _stream;
        private readonly Channel<byte[]> _outbound;
        private readonly CancellationTokenSource _cts = new();
        private Task? _sender;
        private Task? _receiver;
        private CancellationTokenRegistration _parentRegistration;
        private int _closed;

        public QuicPeerLink(QuicLanNode node, PeerState peer, QuicConnection connection, QuicStream stream)
        {
            _node = node;
            _peer = peer;
            _connection = connection;
            _stream = stream;
            _outbound = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(SendQueueSize)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });
        }

        public bool IsOpen => Volatile.Read(ref _closed) == 0 && !_cts.IsCancellationRequested;

        public bool TryQueue(byte[] packet)
        {
            if (!IsOpen) return false;
            return _outbound.Writer.TryWrite(packet);
        }

        public void Start(CancellationToken parent)
        {
            _parentRegistration = parent.Register(static state => ((QuicPeerLink)state!).Dispose(), this);
            _sender = Task.Run(SenderLoopAsync);
            _receiver = Task.Run(ReceiverLoopAsync);
        }

        private async Task SenderLoopAsync()
        {
            byte[] lenBytes = new byte[4];
            try
            {
                while (await _outbound.Reader.WaitToReadAsync(_cts.Token))
                {
                    int batch = 0;
                    while (batch++ < 16 && _outbound.Reader.TryRead(out var packet))
                    {
                        BinaryPrimitives.WriteInt32BigEndian(lenBytes, packet.Length);
                        await _stream.WriteAsync(lenBytes, _cts.Token);
                        await _stream.WriteAsync(packet, _cts.Token);
                    }
                    await _stream.FlushAsync(_cts.Token);
                }
            }
            catch { Dispose(); }
        }

        private async Task ReceiverLoopAsync()
        {
            byte[] len = new byte[4];
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    if (!await QuicLanNode.ReadExactAsync(_stream, len, _cts.Token)) break;
                    int size = BinaryPrimitives.ReadInt32BigEndian(len);
                    int limit = Math.Min(_node._settings.Current.EffectivePacketLimit, Math.Clamp(_peer.Mtu, MinMtu, MaxMtu));
                    if (size <= 0 || size > limit)
                    {
                        Interlocked.Increment(ref _node._droppedPackets);
                        break;
                    }
                    byte[] packet = new byte[size];
                    if (!await QuicLanNode.ReadExactAsync(_stream, packet, _cts.Token)) break;
                    _peer.LastSeenMs = Environment.TickCount64;
                    _node.HandleIncomingIpPacket(_peer, packet);
                }
            }
            catch { }
            finally { Dispose(); }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0) return;
            _cts.Cancel();
            _outbound.Writer.TryComplete();
            _parentRegistration.Dispose();
            try { _stream.Dispose(); } catch { }
            try { _connection.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
            _cts.Dispose();
            if (ReferenceEquals(_peer.QuicLink, this)) _peer.QuicLink = null;
        }
    }
}
