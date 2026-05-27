using System.Buffers.Binary;
using System.Text;

namespace QuicLan;

internal static partial class Program
{
    private sealed partial class QuicLanNode
    {
        private void HandleControlPacket(PeerState peer, byte[] payload)
        {
            if (!ControlPayload.TryParse(payload, out var message))
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            switch (message.Kind)
            {
                case ControlMessageKind.SettingsUpdate:
                    if (message.SettingsUpdate is not { } update) return;
                    if (!RememberControlMessage(update.MessageKey)) return;
                    if (update.Revision.TimestampMs > DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)SettingsClockSkew.TotalMilliseconds) return;
                    if (_settings.TryApplyRemote(update, out var previous, out var applied))
                    {
                        ApplyRuntimeSettings(previous, applied, $"peer {peer.Name}");
                        Console.WriteLine($"Ajuste recibido de {peer.Name}: mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}");
                        _ = BroadcastControlPayloadAsync(payload, except: peer.Id, _shutdown.Token);
                    }
                    break;


                case ControlMessageKind.IpClaim:
                    if (message.IpClaim is { } claim)
                        HandleIpClaim(peer, claim.Ip, claim.Salt);
                    break;

                case ControlMessageKind.IpReject:
                    if (message.IpReject is { } reject && reject.Ip == GetLocalIp())
                    {
                        Console.WriteLine($"IP virtual rechazada por {peer.Name}: {IpToString(reject.Ip)} ({SanitizeDisplayText(reject.Reason, 120)})");
                        _ = ReselectLocalIpAsync($"rechazo de {peer.Name}", OccupiedVirtualIps(), _shutdown.Token);
                    }
                    break;
            }
        }

        public async Task<string> HandleLocalControlAsync(string path, CancellationToken ct)
        {
            string command = path.Trim('/').Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(command) || command == "help")
                return ControlHelpText();
            if (command == "stat")
                return BuildStatusText();

            RuntimeSettings current = _settings.Current;
            RuntimeSettings next;
            string changedName;

            if (command == "reset")
            {
                next = RuntimeSettings.Default;
                changedName = "reset";
            }
            else
            {
                int dash = command.IndexOf('-');
                if (dash <= 0 || dash == command.Length - 1)
                    return "Comando inválido. Usa pak 1000, bst 16, mtu 1200, stat o reset.\n";

                string name = command[..dash];
                string valueText = command[(dash + 1)..];
                if (!int.TryParse(valueText, out int value))
                    return "Valor inválido: debe ser numérico.\n";

                try
                {
                    next = current.With(name, value);
                    changedName = name;
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    return ex.Message + "\n";
                }
                catch (ArgumentException ex)
                {
                    return ex.Message + "\n";
                }
            }

            if (!_settings.TryApplyLocal(next, out var update, out var previous, out var applied))
                return $"sin cambios: mtu={current.Mtu} pak={current.Pak} bst={current.Burst}\n";

            ApplyRuntimeSettings(previous, applied, "local");
            Console.WriteLine($"Ajuste local ({changedName}): mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}");
            await BroadcastSettingsUpdateAsync(update, ct);
            return $"ok: mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}\n";
        }

        public async Task RunConsoleAsync(CancellationToken ct)
        {
            Console.WriteLine("Comandos en esta ventana: stat, pak 1000, bst 16, mtu 1200, reset, help, quit.\n");
            while (!ct.IsCancellationRequested)
            {
                Console.Write("> ");
                string? line = await Task.Run(() => Console.ReadLine(), CancellationToken.None);
                if (line is null)
                {
                    _shutdown.Cancel();
                    return;
                }
                line = line.Trim();
                if (line.Length == 0) continue;
                if (line.Equals("quit", StringComparison.OrdinalIgnoreCase) || line.Equals("exit", StringComparison.OrdinalIgnoreCase) || line.Equals("salir", StringComparison.OrdinalIgnoreCase))
                {
                    _shutdown.Cancel();
                    return;
                }

                Console.Write(await HandleLocalControlAsync(ConsoleCommandToPath(line), ct));
            }
        }

        private static string ConsoleCommandToPath(string line)
        {
            string c = line.Trim().Trim('/').ToLowerInvariant();
            string[] parts = c.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && parts[0] is "pak" or "bst" or "mtu") return $"{parts[0]}-{parts[1]}";
            return c == "peers" ? "stat" : c;
        }

        private string ControlHelpText() => $"""
QuicLAN control local

Comandos:
  /pak-N       límite numérico de paquete overlay/IP. Rango {MinPak}-{MaxPak}.
  /bst-N       ráfaga de envío desde la cola interna. Rango {MinBurst}-{MaxBurst}.
  /mtu-N       MTU Wintun y MTU anunciada a peers. Rango {MinMtu}-{MaxMtu}.
  /stat        estado actual, peers y contadores.
  /reset       vuelve a los valores seguros por defecto.

Terminal:
  pak 1000
  bst 16
  mtu 1200
""";

        private string BuildStatusText()
        {
            RuntimeSettings s = _settings.Current;
            var sb = new StringBuilder();
            sb.AppendLine($"QuicLAN {AppName}");
            sb.AppendLine($"peer={_localId} ip={IpToString(GetLocalIp())}/{DefaultPrefixBits}");
            sb.AppendLine($"settings: mtu={s.Mtu} pak={s.Pak} bst={s.Burst} effective_packet={s.EffectivePacketLimit}");
            sb.AppendLine($"udp_discovery=0.0.0.0:{_options.Port} quic_data=0.0.0.0:{_options.DataPort} quic_enabled={!_options.DisableQuic} control=terminal");
            sb.AppendLine($"counters: tx={Interlocked.Read(ref _txPackets)} rx={Interlocked.Read(ref _rxPackets)} drop={Interlocked.Read(ref _droppedPackets)} quic={Interlocked.Read(ref _quicPackets)} udp_legacy={Interlocked.Read(ref _legacyUdpPackets)} queue={_sendQueue.Reader.Count}");
            sb.AppendLine($"peers_online={_peers.Values.Count(p => p.IsOnline)} peers_known={_peers.Count}");
            foreach (var peer in _peers.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"- {peer.Name} id={peer.Id} ip={IpToString(peer.VirtualIp)} mtu={peer.Mtu} online={peer.IsOnline} ep={peer.EndPoint} quic={peer.QuicEndPoint} quic_open={peer.QuicLink is { IsOpen: true }}");
            return sb.ToString();
        }

        private void ApplyRuntimeSettings(RuntimeSettings previous, RuntimeSettings next, string source)
        {
            if (previous.Equals(next)) return;
            if (previous.EffectivePacketLimit != next.EffectivePacketLimit)
            {
                try
                {
                    ConfigureAdapter(_options.AdapterName, IpToString(GetLocalIp()), next.EffectivePacketLimit);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"No se pudo aplicar MTU efectiva {next.EffectivePacketLimit} en Wintun: {ex.Message}");
                }
            }
            LogVerbose($"Runtime settings {source}: {previous} -> {next}");
        }

        private async Task BroadcastSettingsUpdateAsync(SettingsUpdate update, CancellationToken ct)
        {
            byte[] payload = ControlPayload.CreateSettingsUpdate(update);
            RememberControlMessage(update.MessageKey);
            await BroadcastControlPayloadAsync(payload, except: null, ct);
        }

        private bool RememberControlMessage(string key)
        {
            long now = Environment.TickCount64;
            if (!_seenControlMessages.TryAdd(key, now)) return false;
            if (_seenControlMessages.Count > MaxSeenControlMessages)
            {
                long cutoff = now - (long)SeenControlTtl.TotalMilliseconds;
                foreach (var kv in _seenControlMessages)
                    if (kv.Value < cutoff || _seenControlMessages.Count > MaxSeenControlMessages)
                        _seenControlMessages.TryRemove(kv.Key, out _);
            }
            return true;
        }

        private Task SendCurrentSettingsAsync(PeerState peer, CancellationToken ct) =>
            SendControlAsync(peer, ControlPayload.CreateSettingsUpdate(_settings.CurrentUpdate), ct);

        private async Task BroadcastControlPayloadAsync(byte[] payload, PeerId? except, CancellationToken ct)
        {
            foreach (var peer in _peers.Values)
            {
                if (!peer.IsOnline || peer.DataCrypto is null) continue;
                if (except.HasValue && peer.Id.Equals(except.Value)) continue;
                await SendControlAsync(peer, payload, ct);
            }
        }

        private async Task SendControlAsync(PeerState peer, byte[] payload, CancellationToken ct)
        {
            var crypto = peer.DataCrypto;
            if (crypto is null) return;
            await SendPacketCoreAsync(peer.EndPoint, PacketType.Control, payload, crypto, ct);
        }

        private async Task SendIpRejectAsync(PeerState peer, uint rejectedIp, string reason, CancellationToken ct)
        {
            await SendControlAsync(peer, ControlPayload.CreateIpReject(rejectedIp, reason), ct);
        }

        private async Task BroadcastIpClaimAsync(CancellationToken ct)
        {
            (uint ip, ushort salt) = GetLocalIpAndSalt();
            await BroadcastControlPayloadAsync(ControlPayload.CreateIpClaim(ip, salt), except: null, ct);
        }

        private void HandleIpClaim(PeerState peer, uint ip, ushort salt)
        {
            if (!IsOverlayUnicast(ip) || VirtualIpConflictsWithLocalNetworks(ip) || !VirtualIpMatchesSalt(peer.Id, ip, salt))
            {
                _ = SendIpRejectAsync(peer, ip, "ip-invalida", _shutdown.Token);
                return;
            }

            if (IpIsAlreadyClaimed(ip, peer.Id))
            {
                if (ip == GetLocalIp() && peer.Id.CompareTo(_localId) < 0)
                    _ = ReselectLocalIpAsync($"conflicto con {peer.Name}", OccupiedVirtualIps(), _shutdown.Token);
                else
                    _ = SendIpRejectAsync(peer, ip, "ip-en-uso", _shutdown.Token);
                return;
            }

            _ipClaims[peer.Id] = (ip, salt);
            uint old = peer.VirtualIp;
            if (old != 0 && old != ip)
                _routes.TryRemove(old, out _);
            peer.VirtualIp = ip;
            _routes[ip] = peer;
            bool becameOnline = peer.MarkOnline();
            Console.WriteLine(old == 0
                ? $"IP virtual aceptada de {peer.Name}: {IpToString(ip)}"
                : $"IP virtual actualizada de {peer.Name}: {IpToString(old)} -> {IpToString(ip)}");
            if (becameOnline || old != ip)
            {
                _ = SendHelloAsync(peer.EndPoint, _shutdown.Token);
                _ = SendCurrentSettingsAsync(peer, _shutdown.Token);
            }
        }

        private bool IpIsAlreadyClaimed(uint ip, PeerId claimant)
        {
            if (ip == 0) return true;
            if (!claimant.Equals(_localId) && ip == GetLocalIp()) return true;
            if (_routes.TryGetValue(ip, out var route) && !route.Id.Equals(claimant)) return true;
            foreach (var kv in _ipClaims)
            {
                if (!kv.Key.Equals(claimant) && kv.Value.Ip == ip)
                    return true;
            }
            return false;
        }

        private uint[] OccupiedVirtualIps(PeerId? except = null)
        {
            var ips = new HashSet<uint>();
            if (!except.HasValue || !except.Value.Equals(_localId)) ips.Add(GetLocalIp());
            foreach (var peer in _peers.Values)
            {
                if (peer.VirtualIp != 0 && (!except.HasValue || !peer.Id.Equals(except.Value)))
                    ips.Add(peer.VirtualIp);
            }
            foreach (var claim in _ipClaims)
            {
                if (claim.Value.Ip != 0 && (!except.HasValue || !claim.Key.Equals(except.Value)))
                    ips.Add(claim.Value.Ip);
            }
            return ips.ToArray();
        }

        private async Task ReselectLocalIpAsync(string reason, IEnumerable<uint> extraOccupied, CancellationToken ct)
        {
            uint oldIp;
            uint nextIp;
            ushort nextSalt;
            lock (_ipLock)
            {
                oldIp = _localIp;
                nextSalt = _ipSalt;
                var occupied = new HashSet<uint>(OccupiedVirtualIps(_localId));
                foreach (uint ip in extraOccupied)
                    if (ip != 0) occupied.Add(ip);
                nextIp = AllocateVirtualIp(_roomKey, _localId, ref nextSalt, _options.Prefix, occupied);
                if (nextIp == _localIp) return;
                _localIp = nextIp;
                _ipSalt = nextSalt;
                SaveIpSalt(_options.Room, _ipSalt);
                ConfigureAdapter(_options.AdapterName, IpToString(_localIp), _settings.Current.EffectivePacketLimit);
            }

            Console.WriteLine($"IP virtual reasignada por {reason}: {IpToString(oldIp)} -> {IpToString(nextIp)}/{DefaultPrefixBits}");
            await BroadcastIpClaimAsync(ct);
            await SendDiscoveryRoundAsync(includeKnownPeers: false, ct);
        }
    }

    private readonly record struct RuntimeSettings(int Pak, int Burst, int Mtu)
    {
        public static RuntimeSettings Default => new(DefaultPak, DefaultBurst, DefaultMtu);
        public int EffectivePacketLimit => Math.Min(Pak, Mtu);

        public RuntimeSettings With(string name, int value) => name switch
        {
            "pak" => value is >= MinPak and <= MaxPak ? this with { Pak = value } : throw new ArgumentOutOfRangeException(nameof(value), $"pak debe estar entre {MinPak} y {MaxPak}."),
            "bst" => value is >= MinBurst and <= MaxBurst ? this with { Burst = value } : throw new ArgumentOutOfRangeException(nameof(value), $"bst debe estar entre {MinBurst} y {MaxBurst}."),
            "mtu" => value is >= MinMtu and <= MaxMtu ? this with { Mtu = value } : throw new ArgumentOutOfRangeException(nameof(value), $"mtu debe estar entre {MinMtu} y {MaxMtu}."),
            _ => throw new ArgumentException("Comando desconocido. Usa pak, bst o mtu.")
        };

        public void Validate()
        {
            _ = With("pak", Pak);
            _ = With("bst", Burst);
            _ = With("mtu", Mtu);
        }

        public override string ToString() => $"mtu={Mtu} pak={Pak} bst={Burst}";
    }

    private readonly record struct SettingsRevision(long TimestampMs, PeerId Origin, ulong Sequence) : IComparable<SettingsRevision>
    {
        public int CompareTo(SettingsRevision other)
        {
            int c = TimestampMs.CompareTo(other.TimestampMs);
            if (c != 0) return c;
            c = Sequence.CompareTo(other.Sequence);
            if (c != 0) return c;
            return Origin.CompareTo(other.Origin);
        }
    }

    private sealed record SettingsUpdate(RuntimeSettings Settings, SettingsRevision Revision)
    {
        public string MessageKey => $"set:{Revision.Origin.ToFullString()}:{Revision.TimestampMs}:{Revision.Sequence}";
    }

    private sealed class RuntimeSettingsStore
    {
        private readonly object _lock = new();
        private readonly PeerId _localId;
        private ulong _localSeq;
        private RuntimeSettings _current;
        private SettingsRevision _revision;

        public RuntimeSettingsStore(RuntimeSettings initial, PeerId localId)
        {
            initial.Validate();
            _localId = localId;
            _current = initial;
            _revision = new SettingsRevision(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), localId, 0);
        }

        public RuntimeSettings Current { get { lock (_lock) return _current; } }
        public SettingsUpdate CurrentUpdate { get { lock (_lock) return new SettingsUpdate(_current, _revision); } }

        public bool TryApplyLocal(RuntimeSettings next, out SettingsUpdate update, out RuntimeSettings previous, out RuntimeSettings applied)
        {
            next.Validate();
            lock (_lock)
            {
                previous = _current;
                applied = next;
                if (previous.Equals(next))
                {
                    update = new SettingsUpdate(_current, _revision);
                    return false;
                }
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                _revision = new SettingsRevision(Math.Max(now, _revision.TimestampMs + 1), _localId, ++_localSeq);
                _current = next;
                update = new SettingsUpdate(_current, _revision);
                return true;
            }
        }

        public bool TryApplyRemote(SettingsUpdate update, out RuntimeSettings previous, out RuntimeSettings applied)
        {
            update.Settings.Validate();
            lock (_lock)
            {
                previous = _current;
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (update.Revision.TimestampMs > now + (long)SettingsClockSkew.TotalMilliseconds || update.Revision.CompareTo(_revision) <= 0)
                {
                    applied = _current;
                    return false;
                }
                _current = update.Settings;
                _revision = update.Revision;
                applied = _current;
                return !previous.Equals(applied);
            }
        }
    }

    private enum ControlMessageKind : byte { SettingsUpdate = 1, IpClaim = 3, IpReject = 4 }

    private sealed record ControlMessage(ControlMessageKind Kind, SettingsUpdate? SettingsUpdate, IpClaimInfo? IpClaim, IpRejectInfo? IpReject);
    private readonly record struct IpClaimInfo(uint Ip, ushort Salt);
    private readonly record struct IpRejectInfo(uint Ip, string Reason);
    private static class ControlPayload
    {
        public static byte[] CreateSettingsUpdate(SettingsUpdate update)
        {
            var b = new byte[1 + 8 + 8 + 16 + 4 + 4 + 4];
            b[0] = (byte)ControlMessageKind.SettingsUpdate;
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(1, 8), update.Revision.TimestampMs);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(9, 8), update.Revision.Sequence);
            update.Revision.Origin.WriteTo(b.AsSpan(17, 16));
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(33, 4), update.Settings.Pak);
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(37, 4), update.Settings.Burst);
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(41, 4), update.Settings.Mtu);
            return b;
        }

        public static byte[] CreateIpClaim(uint ip, ushort salt)
        {
            var b = new byte[1 + 4 + 2];
            b[0] = (byte)ControlMessageKind.IpClaim;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(1, 4), ip);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(5, 2), salt);
            return b;
        }

        public static byte[] CreateIpReject(uint ip, string reason)
        {
            byte[] reasonBytes = Encoding.UTF8.GetBytes(string.IsNullOrWhiteSpace(reason) ? "rechazada" : reason.Trim());
            if (reasonBytes.Length > 120) reasonBytes = reasonBytes.AsSpan(0, 120).ToArray();
            var b = new byte[1 + 4 + 1 + reasonBytes.Length];
            b[0] = (byte)ControlMessageKind.IpReject;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(1, 4), ip);
            b[5] = (byte)reasonBytes.Length;
            reasonBytes.CopyTo(b.AsSpan(6));
            return b;
        }

        public static bool TryParse(ReadOnlySpan<byte> b, out ControlMessage message)
        {
            message = default!;
            if (b.Length < 1) return false;
            var kind = (ControlMessageKind)b[0];
            try
            {
                switch (kind)
                {
                    case ControlMessageKind.SettingsUpdate:
                        if (b.Length != 45) return false;
                        long ts = BinaryPrimitives.ReadInt64BigEndian(b.Slice(1, 8));
                        ulong seq = BinaryPrimitives.ReadUInt64BigEndian(b.Slice(9, 8));
                        var origin = PeerId.FromSpan(b.Slice(17, 16));
                        var settings = new RuntimeSettings(
                            BinaryPrimitives.ReadInt32BigEndian(b.Slice(33, 4)),
                            BinaryPrimitives.ReadInt32BigEndian(b.Slice(37, 4)),
                            BinaryPrimitives.ReadInt32BigEndian(b.Slice(41, 4)));
                        settings.Validate();
                        message = new ControlMessage(kind, new SettingsUpdate(settings, new SettingsRevision(ts, origin, seq)), null, null);
                        return true;

                    case ControlMessageKind.IpClaim:
                        if (b.Length != 7) return false;
                        message = new ControlMessage(kind, null, new IpClaimInfo(BinaryPrimitives.ReadUInt32BigEndian(b.Slice(1, 4)), BinaryPrimitives.ReadUInt16BigEndian(b.Slice(5, 2))), null);
                        return true;

                    case ControlMessageKind.IpReject:
                        if (b.Length < 6) return false;
                        uint rejectedIp = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(1, 4));
                        int len = b[5];
                        if (b.Length != 6 + len) return false;
                        message = new ControlMessage(kind, null, null, new IpRejectInfo(rejectedIp, Encoding.UTF8.GetString(b.Slice(6, len))));
                        return true;
                }
            }
            catch
            {
                return false;
            }
            return false;
        }
    }


}
