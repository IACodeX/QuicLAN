using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;

namespace QuicLan;

internal static partial class Program
{
    private const string InternalPanelArg = "--quiclan-panel";
    private const string InternalPipeArg = "--pipe";
    private static int _lastPanelLineCount;

    private static bool IsPanelProcess(string[] args) => args.Any(a => string.Equals(a, InternalPanelArg, StringComparison.OrdinalIgnoreCase));

    private static async Task<int> RunPanelProcessAsync(string[] args)
    {
        string panel = GetArgValue(args, InternalPanelArg) ?? "panel";
        string? pipeName = GetArgValue(args, InternalPipeArg);
        if (string.IsNullOrWhiteSpace(pipeName))
        {
            Console.Error.WriteLine("Panel interno sin pipe.");
            return 2;
        }

        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        Console.Title = panel.ToLowerInvariant() switch
        {
            "lobby" => "QuicLAN - Estado / Lobby",
            "logs" => "QuicLAN - Logs / Diagnostico",
            "chat" => "QuicLAN - Chat de lobby",
            _ => "QuicLAN - Panel"
        };

        try
        {
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(15000);
            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true) { AutoFlush = true };

            if (panel.Equals("chat", StringComparison.OrdinalIgnoreCase))
                return await RunChatPanelClientAsync(reader, writer);

            while (true)
            {
                string? line = await reader.ReadLineAsync();
                if (line is null) break;
                RenderPanelLine(line);
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Panel {panel} cerrado: {ex.Message}");
            Console.WriteLine("Pulsa Enter para cerrar...");
            Console.ReadLine();
            return 1;
        }
    }

    private static async Task<int> RunChatPanelClientAsync(StreamReader reader, StreamWriter writer)
    {
        Console.WriteLine("Chat de lobby. Escribe un mensaje y pulsa Enter. Comandos: /clear, /quit\n");
        using var cts = new CancellationTokenSource();
        var readTask = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                string? line = await reader.ReadLineAsync();
                if (line is null) break;
                RenderPanelLine(line);
            }
        });

        while (!cts.IsCancellationRequested)
        {
            Task<string?> inputTask = Task.Run(() => Console.ReadLine());
            Task completed = await Task.WhenAny(inputTask, readTask);
            if (completed == readTask) break;

            string? line = await inputTask;
            if (line is null) break;
            line = line.Trim();
            if (line.Length == 0) continue;
            if (line.Equals("/quit", StringComparison.OrdinalIgnoreCase) || line.Equals("/exit", StringComparison.OrdinalIgnoreCase)) break;
            if (line.Equals("/clear", StringComparison.OrdinalIgnoreCase)) { Console.Clear(); continue; }
            await writer.WriteLineAsync(line);
        }

        cts.Cancel();
        try { await readTask.WaitAsync(TimeSpan.FromMilliseconds(500)); } catch { }
        return 0;
    }

    private static void RenderPanelLine(string line)
    {
        bool redraw = line.Length > 0 && line[0] == '\f';
        if (redraw) line = line[1..];
        string text = line.Replace("\\n", Environment.NewLine);

        if (!redraw)
        {
            Console.WriteLine(text);
            return;
        }

        string[] lines = text.Split(Environment.NewLine);
        try { Console.SetCursorPosition(0, 0); }
        catch { Console.Clear(); }

        int width = Math.Max(1, Console.WindowWidth - 1);
        foreach (string row in lines)
        {
            string clean = row.Length > width ? row[..width] : row;
            Console.Write(clean.PadRight(width));
            Console.WriteLine();
        }

        for (int i = lines.Length; i < _lastPanelLineCount; i++)
        {
            Console.Write(new string(' ', width));
            Console.WriteLine();
        }
        _lastPanelLineCount = lines.Length;
    }

    private static string? GetArgValue(string[] args, string key)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (!string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase)) continue;
            return i + 1 < args.Length ? args[i + 1] : null;
        }
        return null;
    }

    private sealed class ConsolePanelManager : IAsyncDisposable
    {
        private readonly QuicLanNode _node;
        private readonly Options _options;
        private readonly CancellationTokenSource _cts;
        private readonly ConcurrentDictionary<string, PanelConnection> _connections = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<Process> _processes = [];
        private readonly List<Task> _tasks = [];

        private ConsolePanelManager(QuicLanNode node, Options options, CancellationToken parentToken)
        {
            _node = node;
            _options = options;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        }

        public static async Task<ConsolePanelManager> StartAsync(QuicLanNode node, Options options, CancellationToken ct)
        {
            var manager = new ConsolePanelManager(node, options, ct);
            ConsolePanelHub.Attach(manager);
            manager.LaunchPanel("lobby", "Estado / Lobby");
            manager.LaunchPanel("logs", "Logs / Diagnostico");
            manager.LaunchPanel("chat", "Chat de lobby");
            manager._tasks.Add(manager.LobbyLoopAsync(manager._cts.Token));
            manager._tasks.Add(manager.LogBootInfoLoopAsync(manager._cts.Token));
            await Task.Delay(250, ct).ContinueWith(_ => { });
            return manager;
        }

        private void LaunchPanel(string panel, string title)
        {
            string exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? throw new InvalidOperationException("No se pudo resolver el ejecutable actual.");
            string pipeName = $"QuicLAN.{Process.GetCurrentProcess().Id}.{panel}.{Guid.NewGuid():N}";
            var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, maxNumberOfServerInstances: 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            _tasks.Add(AcceptPanelAsync(panel, pipe, _cts.Token));

            try
            {
                // start abre una ventana nueva de consola. El usuario no tiene que escribir flags: son internos.
                string cmdArgs = $"/c start \"QuicLAN {title}\" {QuoteArg(exe)} {InternalPanelArg} {panel} {InternalPipeArg} {pipeName}";
                var psi = new ProcessStartInfo("cmd.exe", cmdArgs)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                var process = Process.Start(psi);
                if (process is not null) _processes.Add(process);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"No se pudo abrir panel {panel}: {ex.Message}");
                pipe.Dispose();
            }
        }

        private async Task AcceptPanelAsync(string panel, NamedPipeServerStream pipe, CancellationToken ct)
        {
            try
            {
                await pipe.WaitForConnectionAsync(ct);
                var connection = new PanelConnection(pipe);
                _connections[panel] = connection;
                if (panel.Equals("logs", StringComparison.OrdinalIgnoreCase))
                    await connection.WriteLineAsync(BuildBootLogText(), clear: true);
                else if (panel.Equals("chat", StringComparison.OrdinalIgnoreCase))
                {
                    await connection.WriteLineAsync("Chat conectado. Estas hablando en la sala/lobby.", clear: false);
                    _tasks.Add(ReadChatInputLoopAsync(connection, ct));
                }
                else if (panel.Equals("lobby", StringComparison.OrdinalIgnoreCase))
                    await connection.WriteLineAsync(_node.BuildLobbyPanelText(), clear: true);
            }
            catch (OperationCanceledException) { pipe.Dispose(); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Panel {panel} no conecto: {ex.Message}");
                pipe.Dispose();
            }
        }

        private async Task ReadChatInputLoopAsync(PanelConnection connection, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                string? line;
                try { line = await connection.Reader.ReadLineAsync(); }
                catch { break; }
                if (line is null) break;
                line = line.Trim();
                if (line.Length == 0) continue;
                await _node.SendLocalChatAsync(line, ct);
            }
        }

        private async Task LobbyLoopAsync(CancellationToken ct)
        {
            string? last = null;
            while (!ct.IsCancellationRequested)
            {
                string current = _node.BuildLobbyPanelText();
                if (!string.Equals(current, last, StringComparison.Ordinal))
                {
                    await SendToPanelAsync("lobby", current, clear: true);
                    last = current;
                }
                await Task.Delay(750, ct);
            }
        }

        private async Task LogBootInfoLoopAsync(CancellationToken ct)
        {
            // Reintenta unos segundos porque las ventanas pueden tardar en conectar.
            for (int i = 0; i < 20 && !ct.IsCancellationRequested; i++)
            {
                await SendToPanelAsync("logs", BuildBootLogText(), clear: i == 0);
                await Task.Delay(500, ct);
                if (_connections.ContainsKey("logs")) break;
            }
        }

        public void PublishLog(string message)
        {
            _ = SendToPanelAsync("logs", $"[{DateTime.Now:HH:mm:ss}] {message}", clear: false);
        }

        public void PublishChat(string message)
        {
            _ = SendToPanelAsync("chat", $"[{DateTime.Now:HH:mm:ss}] {message}", clear: false);
        }

        private async Task SendToPanelAsync(string panel, string text, bool clear)
        {
            if (!_connections.TryGetValue(panel, out var connection)) return;
            try { await connection.WriteLineAsync(text, clear); }
            catch { _connections.TryRemove(panel, out _); }
        }

        private string BuildBootLogText()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"QuicLAN v{AppVersion} - logs/diagnostico");
            sb.AppendLine($"Nombre : {_options.Name}");
            sb.AppendLine($"Sala   : sha256:{Fingerprint(Encoding.UTF8.GetBytes(_options.Room))}");
            sb.AppendLine($"UDP    : 0.0.0.0:{_options.Port}");
            sb.AppendLine($"QUIC   : 0.0.0.0:{_options.DataPort}" + (_options.DisableQuic ? " (desactivado)" : ""));
            sb.AppendLine($"Ajustes: mtu={_options.Mtu} pak={_options.Pak} bst={_options.Burst}");
            sb.AppendLine(_options.Trackers.Length == 0 ? "Trackers: desactivados" : $"Trackers activos ({_options.Trackers.Length}):");
            foreach (string tracker in _options.Trackers)
                sb.AppendLine($"  - {tracker}");
            sb.AppendLine();
            sb.AppendLine("Eventos:");
            return sb.ToString();
        }

        public async ValueTask DisposeAsync()
        {
            ConsolePanelHub.Detach(this);
            _cts.Cancel();
            foreach (var connection in _connections.Values) await connection.DisposeAsync();
            foreach (var process in _processes)
            {
                try { if (!process.HasExited) process.CloseMainWindow(); } catch { }
                process.Dispose();
            }
            try { await Task.WhenAll(_tasks).WaitAsync(TimeSpan.FromSeconds(1)); } catch { }
            _cts.Dispose();
        }
    }

    private sealed class PanelConnection : IAsyncDisposable
    {
        private readonly NamedPipeServerStream _pipe;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        public StreamReader Reader { get; }
        private StreamWriter Writer { get; }

        public PanelConnection(NamedPipeServerStream pipe)
        {
            _pipe = pipe;
            Reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
            Writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
        }

        public async Task WriteLineAsync(string text, bool clear)
        {
            await _writeLock.WaitAsync();
            try
            {
                string payload = (clear ? "\f" : "") + text.Replace(Environment.NewLine, "\\n").Replace("\r", "").Replace("\n", "\\n");
                await Writer.WriteLineAsync(payload);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            _writeLock.Dispose();
            Reader.Dispose();
            await Writer.DisposeAsync();
            await _pipe.DisposeAsync();
        }
    }

    private static class ConsolePanelHub
    {
        private static ConsolePanelManager? _manager;
        public static void Attach(ConsolePanelManager manager) => Volatile.Write(ref _manager, manager);
        public static void Detach(ConsolePanelManager manager)
        {
            if (ReferenceEquals(Volatile.Read(ref _manager), manager)) Volatile.Write(ref _manager, null);
        }
        public static void PublishLog(string message) => Volatile.Read(ref _manager)?.PublishLog(message);
        public static void PublishChat(string message) => Volatile.Read(ref _manager)?.PublishChat(message);
    }

    private sealed partial class QuicLanNode
    {
        internal string BuildLobbyPanelText()
        {
            RuntimeSettings s = _settings.Current;
            var peers = _peers.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            LobbyProposal? proposal;
            LanSessionInfo? active;
            LobbyMemberState localState;
            lock (_lobbyLock)
            {
                proposal = _activeProposal ?? _ownedProposal;
                active = _activeLan;
                localState = _localLobbyState;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"QuicLAN v{AppVersion} | ESTADO / LOBBY");
            sb.AppendLine($"Sala        : sha256:{Fingerprint(_roomKey)}");
            sb.AppendLine($"Tu estado   : {MemberStateText(localState)}");
            sb.AppendLine($"LAN activa  : {(active is null ? "no" : $"si - {ModeText(active.Mode)} - {active.SessionId}")}");
            if (active is not null)
                sb.AppendLine($"Host/coord. : {active.HostName} ({active.HostId})");
            sb.AppendLine($"Propuesta   : {(proposal is null ? "ninguna" : $"{ModeText(proposal.Mode)} por {proposal.OwnerName} - {proposal.SessionId}")}");
            sb.AppendLine($"Ajustes     : mtu={s.Mtu} pak={s.Pak} bst={s.Burst} efectivo={s.EffectivePacketLimit}");
            sb.AppendLine($"Contadores  : tx={Interlocked.Read(ref _txPackets)} rx={Interlocked.Read(ref _rxPackets)} drop={Interlocked.Read(ref _droppedPackets)} datos_quic={Interlocked.Read(ref _quicPackets)} datos_udp={Interlocked.Read(ref _legacyUdpPackets)}");
            sb.AppendLine();
            sb.AppendLine("Usuarios en sala:");
            sb.AppendLine("  #  Nombre                 IP LAN         Rol        Estado          Modo IP  Control/Datos          Endpoint");

            string localRole = active is not null && active.HostId.Equals(_localId) ? (active.Mode == LanMode.Server ? "HOST" : "COORD") : "YO";
            sb.AppendLine($"  {0,-2} {TrimForColumn(_options.Name + " (tu)", 20),-20} {IpToString(GetLocalIp()),-14} {localRole,-10} {MemberStateText(localState),-15} {_localIpMode,-8} {"local",-22} {"este PC"}");

            int i = 1;
            foreach (var peer in peers)
            {
                string role = active is not null && active.HostId.Equals(peer.Id) ? (active.Mode == LanMode.Server ? "HOST" : "COORD") : "PEER";
                string transport = PeerTransportText(peer);
                string ipText = peer.VirtualIp == 0 ? "--" : IpToString(peer.VirtualIp);
                string endpoint = peer.IsOnline ? peer.EndPoint.ToString() : "--";
                sb.AppendLine($"  {i,-2} {TrimForColumn(peer.Name, 20),-20} {ipText,-14} {role,-10} {MemberStateText(peer.LobbyState),-15} {peer.IpMode,-8} {transport,-22} {endpoint}");
                i++;
            }

            if (peers.Length == 0)
                sb.AppendLine("\nEsperando mas usuarios en la sala...");

            sb.AppendLine();
            if (active is not null)
                sb.AppendLine("Hay LAN activa: los nuevos solo pueden unirse o quedarse en lobby.");
            else if (proposal is not null)
                sb.AppendLine("Hay propuesta activa: escribe 's' en CONTROL para estar listo; el creador usa 'start'.");
            else
                sb.AppendLine("No hay LAN activa: alguien puede escribir 'create server' o 'create red'.");
            return sb.ToString();
        }


        private string PeerTransportText(PeerState peer)
        {
            if (peer.DataCrypto is null) return "sin crypto";
            string control = "UDP";
            string data;
            if (peer.QuicLink is { IsOpen: true }) data = "QUIC";
            else if (!_options.DisableQuic && _quicConnecting.ContainsKey(peer.Id)) data = "QUIC...";
            else if (_options.DisableQuic) data = "UDP";
            else if (_options.LegacyUdpData) data = "UDP fallback";
            else data = "sin datos";
            return $"{control}/{data}";
        }

        internal async Task SendLocalChatAsync(string text, CancellationToken ct)
        {
            text = SanitizeDisplayText(text, 500);
            if (string.IsNullOrWhiteSpace(text)) return;
            ConsolePanelHub.PublishChat($"{_options.Name}: {text}");
            ConsolePanelHub.PublishLog($"chat enviado: {text}");
            await BroadcastControlPayloadAsync(ControlPayload.CreateChat(text), except: null, ct);
        }
    }

    private static string TrimForColumn(string value, int width)
    {
        value = value.Replace('\r', ' ').Replace('\n', ' ');
        return value.Length <= width ? value : value[..Math.Max(0, width - 1)] + "...";
    }
}
