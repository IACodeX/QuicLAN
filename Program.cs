using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

namespace QuicLan;

internal static partial class Program
{
    private const string AppName = "QuicLAN";
    private const string DefaultAdapter = "QuicLAN";
    private const int DefaultPort = 51888;
    private const int DefaultDataPort = DefaultPort + 1;
    private const int DefaultMtu = 1280;
    private const int MinMtu = 576;
    private const int MaxMtu = 1400;
    private const int DefaultPak = DefaultMtu;
    private const int MinPak = MinMtu;
    private const int MaxPak = MaxMtu;
    private const int DefaultBurst = 16;
    private const int MinBurst = 1;
    private const int MaxBurst = 256;
    private const int MaxControlPayload = 8192;
    private const int MaxPeers = 128;
    private const int MaxCandidates = 512;
    private const int SendQueueSize = 1024;
    private const uint DefaultPrefix = 0x0A580000; // 10.88.0.0
    private const int DefaultPrefixBits = 16;
    private static readonly TimeSpan PeerTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan StalePeerTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan[] FastHelloDelays =
    [
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(100),
        TimeSpan.FromMilliseconds(300),
        TimeSpan.FromMilliseconds(700),
        TimeSpan.FromMilliseconds(1500),
        TimeSpan.FromSeconds(3)
    ];
    private static readonly TimeSpan SettingsClockSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SeenControlTtl = TimeSpan.FromMinutes(10);
    private const int MaxSeenControlMessages = 2048;

    private static readonly string[] DefaultTrackers =
    [
        "udp://tracker.opentrackr.org:1337/announce",
        "udp://open.demonii.com:1337/announce",
        "udp://open.stealth.si:80/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "udp://tracker.srv00.com:6969/announce",
        "udp://tracker.qu.ax:6969/announce",
        "udp://tracker.dler.org:6969/announce",
        "udp://tracker.theoks.net:6969/announce"
    ];

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Options options;
        try { options = args.Length == 0 ? Options.PromptInteractive() : Options.Parse(args); }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine(Options.HelpText);
            PauseIfInteractive(args);
            return 1;
        }

        if (options.ShowHelp)
        {
            Console.WriteLine(Options.HelpText);
            return 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("QuicLAN usa Wintun. Esta versión es sólo para Windows.");
            PauseIfInteractive(args);
            return 1;
        }

        if (!IsAdministrator())
        {
            Console.WriteLine("Se requieren permisos de administrador para crear/configurar Wintun.");
            if (!options.NoElevate && TryRelaunchAsAdmin(args.Length == 0 ? options.ToArgs() : args)) return 0;
            PauseIfInteractive(args);
            return 1;
        }

        using var appCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; appCts.Cancel(); };

        try
        {
            await using var node = await QuicLanNode.StartAsync(options, appCts.Token);
            var waitTask = node.WaitAsync(appCts.Token);
            var consoleTask = node.RunConsoleAsync(appCts.Token);
            await Task.WhenAny(waitTask, consoleTask);
            appCts.Cancel();
            await waitTask;
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            if (options.Verbose) Console.Error.WriteLine(ex);
            PauseIfInteractive(args);
            return 2;
        }
    }

    private static void PauseIfInteractive(string[] args)
    {
        if (args.Length == 0 && Environment.UserInteractive)
        {
            Console.WriteLine("Pulsa Enter para cerrar...");
            Console.ReadLine();
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool TryRelaunchAsAdmin(string[] args)
    {
        try
        {
            var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
            if (exe is null) return false;
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = string.Join(" ", args.Select(QuoteArg))
            };
            Process.Start(psi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string QuoteArg(string value) => value.Any(char.IsWhiteSpace) || value.Contains('"')
        ? "\"" + value.Replace("\"", "\\\"") + "\""
        : value;

    private sealed partial class QuicLanNode : IAsyncDisposable
    {
        internal readonly Options _options;
        private readonly byte[] _roomKey;
        private readonly ECDsa _identityKey;
        private readonly byte[] _identityPublicKey;
        private readonly ECDiffieHellman _sessionDh;
        private readonly byte[] _sessionDhPublicKey;
        private readonly PeerId _localId;
        private readonly ulong _sessionId;
        private readonly X509Certificate2 _quicCertificate;
        private readonly UdpClient _udp;
        private readonly CryptoBox _helloCrypto;
        private readonly WintunAdapter _adapter;
        private readonly WintunSession _session;
        private readonly StunClient _stun;
        private readonly TrackerClient _trackers;
        internal readonly RuntimeSettingsStore _settings;
        private readonly TaskCompletionSource _quicReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentDictionary<string, long> _seenControlMessages = new();
        private readonly ConcurrentDictionary<PeerId, (uint Ip, ushort Salt)> _ipClaims = new();
        private readonly ConcurrentDictionary<PeerId, PeerState> _peers = new();
        private readonly ConcurrentDictionary<uint, PeerState> _routes = new();
        private readonly ConcurrentDictionary<string, IPEndPoint> _candidates = new();
        private readonly Channel<SendJob> _sendQueue;
        private readonly CancellationTokenSource _shutdown;
        private readonly List<Task> _tasks = [];
        private readonly object _ipLock = new();
        private Exception? _fatal;
        private uint _localIp;
        private ushort _ipSalt;
        private long _seq;
        private long _txPackets;
        private long _rxPackets;
        internal long _droppedPackets;
        private long _quicPackets;
        private long _legacyUdpPackets;

        private QuicLanNode(
            Options options,
            byte[] roomKey,
            ECDsa identityKey,
            byte[] identityPublicKey,
            ECDiffieHellman sessionDh,
            byte[] sessionDhPublicKey,
            PeerId localId,
            ulong sessionId,
            X509Certificate2 quicCertificate,
            ushort ipSalt,
            uint localIp,
            UdpClient udp,
            WintunAdapter adapter,
            WintunSession session,
            CancellationToken parentToken)
        {
            _options = options;
            _roomKey = roomKey;
            _identityKey = identityKey;
            _identityPublicKey = identityPublicKey;
            _sessionDh = sessionDh;
            _sessionDhPublicKey = sessionDhPublicKey;
            _localId = localId;
            _sessionId = sessionId;
            _quicCertificate = quicCertificate;
            _ipSalt = ipSalt;
            _localIp = localIp;
            _udp = udp;
            _adapter = adapter;
            _session = session;
            _shutdown = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
            _helloCrypto = new CryptoBox(DeriveSubKey(roomKey, "hello-v5"));
            _stun = new StunClient(_udp, options.Verbose);
            _trackers = new TrackerClient(_udp, _stun, DeriveTrackerInfoHash(roomKey), MakeTrackerPeerId(localId), options.Port, options.Trackers, options.Verbose);
            _trackers.PeerDiscovered += ep =>
            {
                if (AddCandidate(ep, "tracker"))
                    _ = SendHelloAsync(ep, _shutdown.Token);
            };
            _settings = new RuntimeSettingsStore(new RuntimeSettings(options.Pak, options.Burst, options.Mtu), localId);
            _sendQueue = Channel.CreateBounded<SendJob>(new BoundedChannelOptions(SendQueueSize)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });
        }

        public static async Task<QuicLanNode> StartAsync(Options options, CancellationToken ct)
        {
            Directory.CreateDirectory(AppDataDir);
            var roomKey = DeriveRoomKey(options.Room);
            using var identityForLoad = LoadOrCreateIdentityKey(options.Room);
            var identityPublic = identityForLoad.ExportSubjectPublicKeyInfo();
            var localId = PeerId.FromPublicKey(identityPublic);
            var sessionDh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var sessionDhPublic = sessionDh.ExportSubjectPublicKeyInfo();
            ulong sessionId = RandomUInt64();
            ushort salt = LoadOrCreateIpSalt(options.Room);
            if (OverlayPrefixConflictsWithLocalNetworks(options.Prefix))
                Console.WriteLine($"Aviso: el rango virtual {IpToString(options.Prefix)}/{DefaultPrefixBits} se solapa con una red/ruta IPv4 local real. Usa --prefix para elegir otro /16 si tienes problemas de rutas.");
            uint localIp = AllocateVirtualIp(roomKey, localId, ref salt, options.Prefix, []);
            SaveIpSalt(options.Room, salt);
            string localIpText = IpToString(localIp);

            UdpClient? udp = null;
            WintunAdapter? adapter = null;
            WintunSession? session = null;
            QuicLanNode node;
            try
            {
                udp = new UdpClient(AddressFamily.InterNetwork);
                udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, false);
                udp.Client.ReceiveBufferSize = 1 << 20;
                udp.Client.SendBufferSize = 1 << 20;
                udp.EnableBroadcast = true;
                udp.Client.Bind(new IPEndPoint(IPAddress.Any, options.Port));

                adapter = WintunAdapter.CreateOrOpen(options.AdapterName);
                ConfigureAdapter(options.AdapterName, localIpText, Math.Min(options.Mtu, options.Pak));
                session = adapter.StartSession();

                // Transfer ownership of cryptographic handles into the node.
                var identity = ECDsa.Create();
                identity.ImportPkcs8PrivateKey(identityForLoad.ExportPkcs8PrivateKey(), out _);
                var quicCertificate = BuildQuicCertificate(identity, options.Name, localId);
                node = new QuicLanNode(options, roomKey, identity, identityPublic, sessionDh, sessionDhPublic,
                    localId, sessionId, quicCertificate, salt, localIp, udp, adapter, session, ct);
                sessionDh = null!;
                udp = null; adapter = null; session = null;
            }
            finally
            {
                session?.Dispose();
                adapter?.Dispose();
                udp?.Dispose();
                sessionDh?.Dispose();
            }

            Console.WriteLine($"{AppName} iniciado");
            Console.WriteLine($"  Sala       : sha256:{Fingerprint(roomKey)}");
            Console.WriteLine($"  Identidad  : {localId}");
            Console.WriteLine($"  IP virtual : {localIpText}/{DefaultPrefixBits}");
            Console.WriteLine($"  UDP discr. : 0.0.0.0:{options.Port}");
            Console.WriteLine($"  QUIC datos : 0.0.0.0:{options.DataPort}" + (options.DisableQuic ? " (desactivado)" : ""));
            Console.WriteLine($"  Ajustes    : mtu={options.Mtu} pak={options.Pak} bst={options.Burst} efectiva={Math.Min(options.Mtu, options.Pak)}");
            Console.WriteLine("  Control    : terminal local");
            Console.WriteLine($"  Descubr.   : LAN broadcast" + (options.Trackers.Length == 0 ? "" : $" + {options.Trackers.Length} trackers UDP"));
            Console.WriteLine("  Transporte : " + (options.DisableQuic
                ? "UDP legacy cifrado"
                : "QUIC real para unicast" + (options.LegacyUdpData ? " + UDP fallback/broadcast" : "")));
            Console.WriteLine("Esperando peers... Ctrl+C para salir.\n");

            node.StartTasks();
            await node.WaitQuicReadyOrTimeoutAsync(TimeSpan.FromMilliseconds(500), node._shutdown.Token);
            node._tasks.Add(node.RunGuardedAsync("fast-discovery", node.SendFastInitialDiscoveryAsync));
            return node;
        }

        private void StartTasks()
        {
            _tasks.Add(RunGuardedAsync("udp", ReceiveUdpLoopAsync));
            if (!_options.DisableQuic)
                _tasks.Add(RunGuardedAsync("quic", RunQuicListenerAsync));
            _tasks.Add(RunGuardedAsync("tun-read", ct => Task.Run(() => ReadTunLoop(ct), ct)));
            _tasks.Add(RunGuardedAsync("send", SendLoopAsync));
            _tasks.Add(RunGuardedAsync("hello", HelloLoopAsync));
            _tasks.Add(RunGuardedAsync("status", StatusLoopAsync));
            if (_options.Trackers.Length > 0)
                _tasks.Add(RunGuardedAsync("trackers", _trackers.RunAsync));
        }

        private async Task WaitQuicReadyOrTimeoutAsync(TimeSpan timeout, CancellationToken ct)
        {
            if (_options.DisableQuic) return;
            using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            Task delay = Task.Delay(timeout, delayCts.Token);
            Task completed = await Task.WhenAny(_quicReady.Task, delay);
            delayCts.Cancel();
            if (completed == _quicReady.Task)
                await _quicReady.Task;
        }

        private Task RunGuardedAsync(string name, Func<CancellationToken, Task> body) => Task.Run(async () =>
        {
            try { await body(_shutdown.Token); }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (_shutdown.IsCancellationRequested) { }
            catch (Exception ex)
            {
                _fatal = ex;
                Console.Error.WriteLine($"Tarea '{name}' falló: {ex.Message}");
                _shutdown.Cancel();
            }
        });

        public async Task WaitAsync(CancellationToken externalToken)
        {
            using var externalReg = externalToken.Register(() => _shutdown.Cancel());
            try { await Task.WhenAll(_tasks); }
            finally { Console.WriteLine("\nCerrando..."); }
            if (_fatal is not null) throw new InvalidOperationException("QuicLAN se detuvo por un error interno.", _fatal);
        }

        private async Task ReceiveUdpLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try { result = await _udp.ReceiveAsync(ct); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { LogVerbose($"UDP receive: {ex.Message}"); continue; }

                var data = result.Buffer;
                if (PacketCodec.LooksLikeOverlayPacket(data))
                {
                    if (IsOverlayTransportEndpoint(result.RemoteEndPoint))
                    {
                        Interlocked.Increment(ref _droppedPackets);
                        LogVerbose($"Overlay recibido desde IP virtual ignorado: {result.RemoteEndPoint}");
                        continue;
                    }
                    HandleOverlayPacket(data, result.RemoteEndPoint);
                }
                else if (!_stun.TryHandleResponse(data, result.RemoteEndPoint))
                {
                    _trackers.TryHandleResponse(data, result.RemoteEndPoint);
                }
            }
        }

        private unsafe void ReadTunLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                _session.ReadWaitEvent.WaitOne(250);
                while (!ct.IsCancellationRequested)
                {
                    byte* packet = WintunNative.WintunReceivePacket(_session.Handle, out uint size);
                    if (packet == null)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 259) break; // ERROR_NO_MORE_ITEMS
                        LogVerbose($"Wintun receive: {new Win32Exception(error).Message}");
                        break;
                    }

                    byte[]? copy = null;
                    PeerState[]? targets = null;
                    uint destination = 0;
                    try
                    {
                        if (size > _settings.Current.EffectivePacketLimit)
                        {
                            Interlocked.Increment(ref _droppedPackets);
                            continue;
                        }

                        var span = new ReadOnlySpan<byte>(packet, (int)size);
                        if (!TryParseIpv4Packet(span, out var ip) || ip.Source != GetLocalIp())
                        {
                            Interlocked.Increment(ref _droppedPackets);
                            continue;
                        }

                        destination = ip.Destination;
                        if (IsOverlayBroadcast(destination) || IsMulticast(destination))
                            targets = _peers.Values.Where(p => p.IsOnline && p.DataCrypto is not null).ToArray();
                        else if (_routes.TryGetValue(destination, out var peer) && peer.IsOnline && peer.DataCrypto is not null)
                            targets = [peer];

                        if (targets is not null)
                            copy = span.ToArray();
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _droppedPackets);
                        LogVerbose($"TUN packet: {ex.Message}");
                    }
                    finally
                    {
                        WintunNative.WintunReleaseReceivePacket(_session.Handle, packet);
                    }

                    if (copy is not null && targets is not null)
                        foreach (var target in targets)
                            QueueOrSendIpPacket(target, copy, destination == target.VirtualIp);
                }
            }
        }

        private async Task SendLoopAsync(CancellationToken ct)
        {
            while (await _sendQueue.Reader.WaitToReadAsync(ct))
            {
                int budget = Math.Clamp(_settings.Current.Burst, MinBurst, MaxBurst);
                while (budget-- > 0 && _sendQueue.Reader.TryRead(out var job))
                    await SendIpJobAsync(job, ct);
            }
        }
        private void QueueOrSendIpPacket(PeerState target, byte[] payload, bool unicastToPeer)
        {
            int mtu = Math.Min(_settings.Current.EffectivePacketLimit, Math.Clamp(target.Mtu, MinMtu, MaxMtu));
            if (payload.Length > mtu)
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            if (!_options.DisableQuic && unicastToPeer && target.QuicLink is { IsOpen: true } quic && quic.TryQueue(payload))
            {
                Interlocked.Increment(ref _txPackets);
                Interlocked.Increment(ref _quicPackets);
                return;
            }

            if (!_sendQueue.Writer.TryWrite(new SendJob(target, payload, unicastToPeer)))
                Interlocked.Increment(ref _droppedPackets);
        }


        private async Task SendIpJobAsync(SendJob job, CancellationToken ct)
        {
            var peer = job.Peer;
            var crypto = peer.DataCrypto;
            if (!peer.IsOnline || crypto is null) return;
            int limit = Math.Min(_settings.Current.EffectivePacketLimit, Math.Clamp(peer.Mtu, MinMtu, MaxMtu));
            if (job.Payload.Length > limit)
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            if (!_options.DisableQuic && job.UnicastToPeer && peer.QuicLink is { IsOpen: true } quic && quic.TryQueue(job.Payload))
            {
                Interlocked.Increment(ref _txPackets);
                Interlocked.Increment(ref _quicPackets);
                return;
            }

            if (!_options.LegacyUdpData)
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            bool sent = await SendPacketCoreAsync(peer.EndPoint, PacketType.IpPacket, job.Payload, crypto, ct);
            if (sent)
            {
                Interlocked.Increment(ref _txPackets);
                Interlocked.Increment(ref _legacyUdpPackets);
            }
            else Interlocked.Increment(ref _droppedPackets);
        }

        private async Task HelloLoopAsync(CancellationToken ct)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (await timer.WaitForNextTickAsync(ct))
            {
                await SendDiscoveryRoundAsync(includeKnownPeers: true, ct);
            }
        }

        private async Task SendFastInitialDiscoveryAsync(CancellationToken ct)
        {
            foreach (var delay in FastHelloDelays)
            {
                if (delay > TimeSpan.Zero)
                    await Task.Delay(delay, ct);
                await SendDiscoveryRoundAsync(includeKnownPeers: false, ct);
            }
        }

        private async Task SendDiscoveryRoundAsync(bool includeKnownPeers, CancellationToken ct)
        {
            var payload = CreateHelloPayload();

            foreach (var ep in GetDiscoveryBroadcastTargets())
                await SendHelloPayloadAsync(ep, payload, ct);

            foreach (var ep in _candidates.Values.Take(MaxCandidates))
                await SendHelloPayloadAsync(ep, payload, ct);

            if (!includeKnownPeers) return;
            foreach (var peer in _peers.Values)
                await SendHelloPayloadAsync(peer.EndPoint, payload, ct);
        }

        private async Task StatusLoopAsync(CancellationToken ct)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (await timer.WaitForNextTickAsync(ct))
            {
                long now = Environment.TickCount64;
                foreach (var peer in _peers.Values)
                {
                    long idleMs = now - peer.LastSeenMs;
                    if (idleMs > PeerTimeout.TotalMilliseconds && peer.MarkDisconnected())
                    {
                        if (peer.VirtualIp != 0) _routes.TryRemove(peer.VirtualIp, out _);
                        _ipClaims.TryRemove(peer.Id, out _);
                        Console.WriteLine($"Peer desconectado: {peer.Name} {IpToString(peer.VirtualIp)}");
                    }
                    if (!peer.IsOnline && idleMs > StalePeerTtl.TotalMilliseconds && _peers.TryRemove(peer.Id, out var removed))
                    {
                        if (removed.VirtualIp != 0) _routes.TryRemove(removed.VirtualIp, out _);
                        _ipClaims.TryRemove(removed.Id, out _);
                        removed.Dispose();
                    }
                }

                if (_options.Verbose)
                    Console.WriteLine($"Estado: peers={_peers.Values.Count(p => p.IsOnline)} tx={Interlocked.Read(ref _txPackets)} rx={Interlocked.Read(ref _rxPackets)} drop={Interlocked.Read(ref _droppedPackets)} quic={Interlocked.Read(ref _quicPackets)} udpLegacy={Interlocked.Read(ref _legacyUdpPackets)} queue={_sendQueue.Reader.Count}");
            }
        }

        private void HandleOverlayPacket(byte[] datagram, IPEndPoint remote)
        {
            if (!PacketCodec.TryReadHeader(datagram, out var header))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }
            if (header.Sender.Equals(_localId)) return;

            if (!PacketSizeAllowed(datagram, header.Type))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            if (header.Type == PacketType.Hello)
            {
                HandleHelloPacket(datagram, header, remote);
                return;
            }

            if (!_peers.TryGetValue(header.Sender, out var peer) || peer.DataCrypto is not { } crypto)
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            if (!PacketCodec.TryDecode(datagram, crypto, header, out var msg) || !peer.AcceptReplay(msg.SessionId, msg.Sequence))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            peer.LastSeenMs = Environment.TickCount64;
            if (msg.Type == PacketType.IpPacket) HandleIncomingIpPacket(peer, msg.Payload);
            else if (msg.Type == PacketType.Control) HandleControlPacket(peer, msg.Payload);
        }

        private void HandleHelloPacket(byte[] datagram, PacketHeader header, IPEndPoint remote)
        {
            if (!PacketCodec.TryDecode(datagram, _helloCrypto, header, out var msg) ||
                !TryValidateHello(header, msg.Payload, out var hello))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            PeerState? peer;
            if (!_peers.TryGetValue(header.Sender, out peer))
            {
                if (_peers.Count >= MaxPeers)
                {
                    Interlocked.Increment(ref _droppedPackets);
                    return;
                }
                peer = _peers.GetOrAdd(header.Sender, id => new PeerState(id, remote));
            }

            if (!peer.AcceptReplay(header.SessionId, header.Sequence))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            ApplyHello(peer, hello, remote);
        }

        private bool TryValidateHello(PacketHeader header, ReadOnlySpan<byte> payload, out HelloInfo hello)
        {
            if (!HelloPayload.TryParse(payload, out hello) || !hello.Verify(header.Sender, header.SessionId)) return false;
            if (hello.Mtu is < MinMtu or > MaxMtu) return false;
            if (hello.QuicPort == 0) return false;
            if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - hello.TimestampMs) > TimeSpan.FromMinutes(30).TotalMilliseconds) return false;
            if (!IsOverlayUnicast(hello.VirtualIp) || VirtualIpConflictsWithLocalNetworks(hello.VirtualIp)) return false;
            if (!VirtualIpMatchesSalt(header.Sender, hello.VirtualIp, hello.IpSalt)) return false;
            return true;
        }

        private void ApplyHello(PeerState peer, HelloInfo hello, IPEndPoint remote)
        {
            uint previousIp = peer.VirtualIp;
            peer.Name = SanitizeDisplayText(hello.Name);
            peer.Mtu = hello.Mtu;
            if (IsUsableTransportEndpoint(remote))
            {
                peer.EndPoint = remote;
                peer.QuicEndPoint = new IPEndPoint(remote.Address, hello.QuicPort);
                AddCandidate(remote, "hello");
            }
            else
            {
                LogVerbose($"Hello desde endpoint no físico ignorado para transporte: {remote}");
            }
            peer.IdentityPublicKey = hello.IdentityPublicKey;
            peer.LastSeenMs = Environment.TickCount64;

            if (!peer.HasSameDhPublicKey(hello.SessionDhPublicKey, out var dhFingerprint))
            {
                var dataCrypto = TryCreatePeerCrypto(peer.Id, hello.SessionDhPublicKey);
                if (dataCrypto is null)
                {
                    Interlocked.Increment(ref _droppedPackets);
                    return;
                }
                peer.SetDataCrypto(dataCrypto, dhFingerprint);
            }

            if (IpIsAlreadyClaimed(hello.VirtualIp, peer.Id))
            {
                if (hello.VirtualIp == GetLocalIp() && peer.Id.CompareTo(_localId) < 0)
                    _ = ReselectLocalIpAsync($"conflicto con {peer.Name}", OccupiedVirtualIps(), _shutdown.Token);
                else
                    _ = SendIpRejectAsync(peer, hello.VirtualIp, "ip-en-uso", _shutdown.Token);

                LogVerbose($"IP virtual propuesta en conflicto: {peer.Name} {IpToString(hello.VirtualIp)}.");
                return;
            }

            _ipClaims[peer.Id] = (hello.VirtualIp, hello.IpSalt);

            if (previousIp != 0 && previousIp != hello.VirtualIp)
                _routes.TryRemove(previousIp, out _);

            peer.VirtualIp = hello.VirtualIp;
            _routes[hello.VirtualIp] = peer;

            bool becameOnline = peer.MarkOnline();
            bool ipChanged = previousIp != 0 && previousIp != hello.VirtualIp;
            if (becameOnline)
                Console.WriteLine($"Peer conectado: {peer.Name} {IpToString(peer.VirtualIp)} vía {remote}");
            else if (ipChanged)
                Console.WriteLine($"Peer actualizó IP virtual: {peer.Name} {IpToString(previousIp)} -> {IpToString(peer.VirtualIp)}");

            if (becameOnline || ipChanged)
            {
                _ = SendHelloAsync(peer.EndPoint, _shutdown.Token);
                _ = SendCurrentSettingsAsync(peer, _shutdown.Token);
            }

            if (!_options.DisableQuic)
                _ = EnsureQuicConnectionAsync(peer, _shutdown.Token);
        }

        internal void HandleIncomingIpPacket(PeerState peer, byte[] packet)
        {
            if (packet.Length > Math.Min(_settings.Current.EffectivePacketLimit, Math.Clamp(peer.Mtu, MinMtu, MaxMtu)) || !TryParseIpv4Packet(packet, out var ip))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            if (ip.Source != peer.VirtualIp || !(ip.Destination == GetLocalIp() || IsOverlayBroadcast(ip.Destination) || IsMulticast(ip.Destination)))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            try
            {
                _session.SendPacket(packet);
                Interlocked.Increment(ref _rxPackets);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _droppedPackets);
                LogVerbose($"Wintun send: {ex.Message}");
            }
        }

        private Task SendHelloAsync(IPEndPoint target, CancellationToken ct) =>
            SendHelloPayloadAsync(target, CreateHelloPayload(), ct);

        private byte[] CreateHelloPayload()
        {
            (uint ip, ushort salt) = GetLocalIpAndSalt();
            return HelloPayload.Create(_sessionId, ip, salt, _settings.Current.EffectivePacketLimit, (ushort)_options.DataPort, _options.Name, _identityPublicKey, _sessionDhPublicKey, _identityKey);
        }

        private async Task SendHelloPayloadAsync(IPEndPoint target, byte[] payload, CancellationToken ct)
        {
            if (!IsAllowedHelloTarget(target)) return;
            await SendPacketCoreAsync(target, PacketType.Hello, payload, _helloCrypto, ct);
        }

        private int PacketPayloadLimit(PacketType type) => type switch
        {
            PacketType.IpPacket => _settings.Current.EffectivePacketLimit,
            PacketType.Control or PacketType.Hello => MaxControlPayload,
            _ => MaxControlPayload
        };

        private bool PacketSizeAllowed(byte[] datagram, PacketType type) =>
            datagram.Length <= PacketCodec.HeaderLength + PacketPayloadLimit(type) + PacketCodec.TagLength;

        private bool VirtualIpMatchesSalt(PeerId id, uint ip, ushort salt) =>
            CalculateVirtualIp(_roomKey, id, salt, _options.Prefix) == ip;

        private async Task<bool> SendPacketCoreAsync(IPEndPoint target, PacketType type, ReadOnlyMemory<byte> payload, CryptoBox crypto, CancellationToken ct)
        {
            if (payload.Length > PacketPayloadLimit(type)) return false;
            if (IsOverlayTransportEndpoint(target)) return false;
            try
            {
                ulong seq = (ulong)Interlocked.Increment(ref _seq);
                byte[] packet = PacketCodec.Encode(type, seq, _sessionId, _localId, payload.Span, crypto);
                await _udp.SendAsync(packet.AsMemory(), target, ct);
                return true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return false; }
            catch (Exception ex)
            {
                LogVerbose($"UDP send to {target}: {ex.Message}");
                return false;
            }
        }

        private CryptoBox? TryCreatePeerCrypto(PeerId remoteId, byte[] remoteDhPublic)
        {
            try
            {
                using var remoteDh = ECDiffieHellman.Create();
                remoteDh.ImportSubjectPublicKeyInfo(remoteDhPublic, out _);
                byte[] shared = _sessionDh.DeriveKeyMaterial(remoteDh.PublicKey);
                byte[] key = [];
                try
                {
                    byte[] context = BuildPairwiseContext(_localId, remoteId);
                    using var h = new HMACSHA256(_roomKey);
                    key = h.ComputeHash(Concat(shared, context));
                    return new CryptoBox(key);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(shared);
                    if (key.Length > 0) CryptographicOperations.ZeroMemory(key);
                }
            }
            catch (Exception ex)
            {
                LogVerbose($"ECDH peer key: {ex.Message}");
                return null;
            }
        }

        private uint GetLocalIp()
        {
            lock (_ipLock) return _localIp;
        }

        private (uint Ip, ushort Salt) GetLocalIpAndSalt()
        {
            lock (_ipLock) return (_localIp, _ipSalt);
        }

        private bool AddCandidate(IPEndPoint ep, string source)
        {
            if (!IsUsableTransportEndpoint(ep)) return false;
            string key = $"{ep.Address}:{ep.Port}";
            bool existed = _candidates.ContainsKey(key);
            if (_candidates.Count >= MaxCandidates && !existed) return false;
            _candidates[key] = ep;
            if (!existed) LogVerbose($"Candidate {source}: {ep}");
            return !existed;
        }

        private static string SanitizeDisplayText(string value, int maxChars = 80)
        {
            var sb = new StringBuilder(Math.Min(Math.Max(value.Length, 1), maxChars));
            foreach (char c in value)
            {
                if (char.IsControl(c)) continue;
                sb.Append(c);
                if (sb.Length >= maxChars) break;
            }
            return sb.Length == 0 ? "peer" : sb.ToString();
        }

        private bool IsUsableTransportEndpoint(IPEndPoint ep)
        {
            if (ep.Port <= 0) return false;
            if (ep.Address.AddressFamily != AddressFamily.InterNetwork) return false;
            if (IPAddress.IsLoopback(ep.Address) || ep.Address.Equals(IPAddress.Any)) return false;
            if (ep.Address.Equals(IPAddress.Broadcast)) return false;
            byte[] bytes = ep.Address.GetAddressBytes();
            if (bytes[0] == 0 || bytes[0] >= 224) return false;
            return !IsOverlayTransportEndpoint(ep);
        }

        private bool IsAllowedHelloTarget(IPEndPoint ep)
        {
            if (ep.Address.Equals(IPAddress.Broadcast)) return true;
            if (ep.Address.AddressFamily != AddressFamily.InterNetwork) return false;
            if (IsOverlayTransportEndpoint(ep)) return false;
            byte[] bytes = ep.Address.GetAddressBytes();
            if (bytes[0] == 0 || bytes[0] >= 224) return false;
            return ep.Port > 0;
        }

        private bool IsOverlayTransportEndpoint(IPEndPoint ep) => IsAddressInOverlayPrefix(ep.Address);

        private bool IsAddressInOverlayPrefix(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork) return false;
            return IsInOverlayPrefix(Ipv4ToUInt32(address.GetAddressBytes()));
        }

        private bool IsInOverlayPrefix(uint ip)
        {
            uint mask = PrefixMask(DefaultPrefixBits);
            return (ip & mask) == (_options.Prefix & mask);
        }

        private IEnumerable<IPEndPoint> GetDiscoveryBroadcastTargets()
        {
            // Do not use 255.255.255.255 here. On Windows it can be emitted through the
            // Wintun interface with the virtual 10.88.x.x address as source, which makes
            // the node receive its own QLAN packets back from the tunnel. Directed
            // broadcasts on physical interfaces plus trackers are enough for discovery.
            foreach (var net in GetLocalIpv4Networks())
            {
                if (IsInOverlayPrefix(net.Address) || IsInOverlayPrefix(net.Network) || IsInOverlayPrefix(net.Broadcast)) continue;
                if (net.Broadcast == 0 || net.Broadcast == uint.MaxValue) continue;
                byte[] b = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(b, net.Broadcast);
                yield return new IPEndPoint(new IPAddress(b), _options.Port);
            }
        }

        private bool IsOverlayUnicast(uint ip)
        {
            uint mask = PrefixMask(DefaultPrefixBits);
            uint host = ip & ~mask;
            return (ip & mask) == (_options.Prefix & mask) && host is not 0 and not 0xFFFF;
        }

        private bool IsOverlayBroadcast(uint ip)
        {
            uint mask = PrefixMask(DefaultPrefixBits);
            return (ip & mask) == (_options.Prefix & mask) && (ip & ~mask) == ~mask;
        }

        private static bool IsMulticast(uint ip) => (byte)(ip >> 24) is >= 224 and <= 239;

        private void LogVerbose(string message)
        {
            if (_options.Verbose) Console.WriteLine(message);
        }

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            try { await Task.WhenAll(_tasks).WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            _sendQueue.Writer.TryComplete();
            _udp.Dispose();
            _session.Dispose();
            _adapter.Dispose();
            _trackers.Dispose();
            _helloCrypto.Dispose();
            foreach (var peer in _peers.Values) peer.Dispose();
            _quicCertificate.Dispose();
            _identityKey.Dispose();
            _sessionDh.Dispose();
            CryptographicOperations.ZeroMemory(_roomKey);
            CryptographicOperations.ZeroMemory(_identityPublicKey);
            CryptographicOperations.ZeroMemory(_sessionDhPublicKey);
            _shutdown.Dispose();
        }
    }

    private sealed record class Options
    {
        public string Room { get; init; } = "";
        public string Name { get; init; } = Environment.MachineName;
        public string AdapterName { get; init; } = DefaultAdapter;
        public int Port { get; init; } = DefaultPort;
        public int DataPort { get; init; } = DefaultDataPort;
        public int Mtu { get; init; } = DefaultMtu;
        public int Pak { get; init; } = DefaultPak;
        public int Burst { get; init; } = DefaultBurst;
        public uint Prefix { get; init; } = DefaultPrefix;
        public string[] Trackers { get; init; } = DefaultTrackers;
        public bool Verbose { get; init; }
        public bool NoElevate { get; init; }
        public bool DisableQuic { get; init; }
        public bool LegacyUdpData { get; init; } = true;
        public bool ShowHelp { get; init; }

        public static Options Parse(string[] args)
        {
            var o = new Options();
            bool dataPortExplicit = false;
            var trackers = new List<string>(DefaultTrackers);
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Falta valor para {a}");
                if (!a.StartsWith('-') && string.IsNullOrWhiteSpace(o.Room))
                {
                    o = o with { Room = a };
                    continue;
                }
                switch (a)
                {
                    case "-h":
                    case "--help": o = o with { ShowHelp = true }; break;
                    case "--room": o = o with { Room = Next() }; break;
                    case "--name": o = o with { Name = Next() }; break;
                    case "--adapter": o = o with { AdapterName = Next() }; break;
                    case "--port": o = o with { Port = ParseRange(Next(), "--port", 1, 65535) }; break;
                    case "--data-port": o = o with { DataPort = ParseRange(Next(), "--data-port", 1, 65535) }; dataPortExplicit = true; break;
                    case "--mtu": o = o with { Mtu = ParseRange(Next(), "--mtu", MinMtu, MaxMtu) }; break;
                    case "--pak": o = o with { Pak = ParseRange(Next(), "--pak", MinPak, MaxPak) }; break;
                    case "--bst": o = o with { Burst = ParseRange(Next(), "--bst", MinBurst, MaxBurst) }; break;
                    case "--prefix": o = o with { Prefix = ParsePrefix16(Next()) }; break;
                    case "--no-trackers": trackers.Clear(); break;
                    case "--tracker": trackers.Add(Next()); break;
                    case "--verbose": o = o with { Verbose = true }; break;
                    case "--no-elevate": o = o with { NoElevate = true }; break;
                    case "--disable-quic": o = o with { DisableQuic = true }; break;
                    case "--no-udp-data-fallback": o = o with { LegacyUdpData = false }; break;
                    default: throw new ArgumentException($"Argumento desconocido: {a}");
                }
            }

            if (o.ShowHelp) return o;
            if (string.IsNullOrWhiteSpace(o.Room)) throw new ArgumentException("Falta --room. Dos o más PCs deben usar la misma sala/clave.");
            if (string.Equals(o.Room, "default", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("No uses 'default' como sala. Elige una clave compartida privada.");
            if (o.Room.Length < 8) Console.Error.WriteLine("Aviso: una sala corta es fácil de adivinar. Usa una frase larga.");
            if (!dataPortExplicit)
            {
                int inferredDataPort = o.Port == 65535 ? 65534 : o.Port + 1;
                o = o with { DataPort = inferredDataPort };
            }
            if (!o.DisableQuic && o.DataPort == o.Port) throw new ArgumentException("--data-port debe ser distinto de --port cuando QUIC está activo.");
            return o with { Trackers = trackers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
        }

        public static Options PromptInteractive()
        {
            Console.WriteLine(HelpText);
            Console.WriteLine("Modo interactivo: deja vacío para usar el valor por defecto.\n");
            string room;
            do
            {
                Console.Write("Sala/clave compartida: ");
                room = (Console.ReadLine() ?? "").Trim();
            } while (string.IsNullOrWhiteSpace(room));

            var args = new List<string> { "--room", room };
            AddText(args, "--name", $"Nombre visible [{Environment.MachineName}]: ");
            AddNumber(args, "--port", $"Puerto UDP discovery [{DefaultPort}]: ");
            AddNumber(args, "--data-port", $"Puerto QUIC datos [{DefaultDataPort}]: ");
            AddNumber(args, "--mtu", $"MTU [{DefaultMtu}]: ");
            AddNumber(args, "--pak", $"Paquete máximo [{DefaultPak}]: ");
            AddNumber(args, "--bst", $"Ráfaga bst [{DefaultBurst}]: ");
            Console.Write("¿Usar trackers públicos? [S/n]: ");
            if ((Console.ReadLine() ?? "").Trim().Equals("n", StringComparison.OrdinalIgnoreCase)) args.Add("--no-trackers");
            return Parse(args.ToArray());
        }

        public string[] ToArgs()
        {
            var args = new List<string>
            {
                "--room", Room, "--name", Name, "--adapter", AdapterName,
                "--port", Port.ToString(), "--data-port", DataPort.ToString(),
                "--mtu", Mtu.ToString(), "--pak", Pak.ToString(), "--bst", Burst.ToString(),
                "--prefix", IpToString(Prefix)
            };
            if (Trackers.Length == 0) args.Add("--no-trackers");
            else if (!Trackers.SequenceEqual(DefaultTrackers, StringComparer.OrdinalIgnoreCase))
                foreach (string tracker in Trackers) { args.Add("--tracker"); args.Add(tracker); }
            if (Verbose) args.Add("--verbose");
            if (NoElevate) args.Add("--no-elevate");
            if (DisableQuic) args.Add("--disable-quic");
            if (!LegacyUdpData) args.Add("--no-udp-data-fallback");
            return args.ToArray();
        }

        private static void AddText(List<string> args, string name, string prompt)
        {
            Console.Write(prompt);
            string? value = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(value)) { args.Add(name); args.Add(value.Trim()); }
        }

        private static void AddNumber(List<string> args, string name, string prompt)
        {
            Console.Write(prompt);
            string? value = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(value)) { args.Add(name); args.Add(value.Trim()); }
        }

        private static int ParseRange(string text, string name, int min, int max)
        {
            if (!int.TryParse(text, out int value) || value < min || value > max)
                throw new ArgumentException($"{name} debe estar entre {min} y {max}.");
            return value;
        }

        public static string HelpText => $"""
{AppName} v5.2 ultra - LAN virtual sobre QUIC real + discovery UDP + Wintun

Uso:
  QuicLan.exe                         Modo interactivo
  QuicLan.exe --room "mi-sala-secreta-larga" [--name Alice]
  QuicLan.exe "mi-sala-secreta-larga"

Opciones:
  --room <texto>       Sala/clave compartida. Debe coincidir en todos los PCs.
  --name <nombre>      Nombre visible del peer. Por defecto: nombre del equipo.
  --port <udp>         Puerto UDP de discovery/STUN/trackers. Por defecto: {DefaultPort}.
  --data-port <udp>    Puerto QUIC real para datos Wintun. Por defecto: {DefaultDataPort}.
  --mtu <bytes>        MTU virtual. Por defecto: {DefaultMtu}. Rango: {MinMtu}-{MaxMtu}.
  --pak <bytes>        Límite de paquete overlay/IP. Por defecto: {DefaultPak}. Rango: {MinPak}-{MaxPak}.
  --bst <n>            Ráfaga de envío interna. Por defecto: {DefaultBurst}. Rango: {MinBurst}-{MaxBurst}.
  --prefix <ipv4>      Red virtual /16. Por defecto: {IpToString(DefaultPrefix)}.
  --no-trackers        Sólo descubrimiento por LAN local; no usa trackers públicos.
  --tracker <url>      Añade tracker UDP estilo udp://host:port/announce.
  --verbose            Muestra diagnóstico resumido.
  --no-elevate         No relanza como administrador.
  --disable-quic       Desactiva QUIC y usa sólo el transporte legacy UDP cifrado.
  --no-udp-data-fallback No usa fallback UDP para datos si QUIC aún no está listo.

Durante la ejecución puedes escribir en la terminal: stat, pak 1000, bst 16, mtu 1200, reset, help o quit.

Ejemplo:
  QuicLan.exe --room "familia-2026-frase-larga" --name "PC-Salon"

""";
    }


}
