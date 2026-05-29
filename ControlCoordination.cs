using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace QuicLan;

internal static partial class Program
{
    private enum LanMode : byte { None = 0, Red = 1, Server = 2 }
    private enum LobbyMemberState : byte { Lobby = 0, Ready = 1, InLan = 2, Reconnecting = 3 }

    private sealed record LobbyProposal(string SessionId, LanMode Mode, PeerId OwnerId, string OwnerName, long CreatedMs)
    {
        public bool IsExpired(long nowMs) => nowMs - CreatedMs > 120_000;
    }

    private sealed record LanSessionInfo(string SessionId, LanMode Mode, PeerId HostId, string HostName, long StartedMs);

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
                        ConsolePanelHub.PublishLog($"ajuste recibido de {peer.Name}: mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}");
                        _ = BroadcastControlPayloadAsync(payload, except: peer.Id, _shutdown.Token);
                    }
                    break;

                case ControlMessageKind.Chat:
                    if (message.Chat is { } chat)
                    {
                        string text = SanitizeDisplayText(chat.Text, 500);
                        ConsolePanelHub.PublishChat($"{peer.Name}: {text}");
                        ConsolePanelHub.PublishLog($"chat recibido de {peer.Name}");
                    }
                    break;

                case ControlMessageKind.LobbyStatus:
                    if (message.LobbyStatus is { } lobby)
                        ApplyRemoteLobbyStatus(peer, lobby);
                    break;

                case ControlMessageKind.LanProposal:
                    if (message.LanProposal is { } proposal)
                        ApplyRemoteLanProposal(peer, proposal);
                    break;

                case ControlMessageKind.LanSession:
                    if (message.LanSession is { } session)
                        ApplyRemoteLanSession(peer, session);
                    break;

                case ControlMessageKind.LanCancel:
                    if (message.LanCancel is { } cancel)
                        ApplyRemoteLanCancel(peer, cancel);
                    break;

                case ControlMessageKind.IpClaim:
                    if (message.IpClaim is { } claim)
                        HandleIpClaim(peer, claim.Ip, claim.Salt);
                    break;

                case ControlMessageKind.IpReject:
                    if (message.IpReject is { } reject && reject.Ip == GetLocalIp())
                    {
                        ConsolePanelHub.PublishLog($"IP virtual rechazada por {peer.Name}: {IpToString(reject.Ip)} ({SanitizeDisplayText(reject.Reason, 120)})");
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
            if (command == "stat" || command == "status" || command == "peers")
                return BuildStatusText();
            if (command is "create-server" or "server" or "host" or "hostear")
                return await CreateLocalProposalAsync(LanMode.Server, ct);
            if (command is "create-red" or "create-network" or "red" or "network" or "mesh")
                return await CreateLocalProposalAsync(LanMode.Red, ct);
            if (command is "start" or "iniciar")
                return await StartLocalProposalAsync(ct);
            if (command is "cancel" or "cancelar")
                return await CancelLocalProposalAsync("cancelada por el creador", ct);
            if (command is "s" or "si" or "ready" or "listo" or "lan" or "join" or "unirme")
                return await ReadyOrJoinLanAsync(ct);
            if (command is "n" or "no" or "lobby" or "notready" or "no-listo" or "salir-lan" or "leave-lan")
                return await LeaveLanOrNotReadyAsync(ct);
            if (command.StartsWith("ip-", StringComparison.Ordinal))
                return await TrySetLocalCustomIpAsync(command[3..], ct);
            if (command is "reset-lobby" or "resetlobby")
                return await ResetLocalLobbyAsync(ct);

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
                    return "Comando invalido. Usa help para ver comandos humanos.\n";

                string name = command[..dash];
                string valueText = command[(dash + 1)..];
                if (!int.TryParse(valueText, out int value))
                    return "Valor invalido: debe ser numerico.\n";

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
            ConsolePanelHub.PublishLog($"ajuste local ({changedName}): mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}");
            await BroadcastSettingsUpdateAsync(update, ct);
            return $"ok: mtu={applied.Mtu} pak={applied.Pak} bst={applied.Burst}\n";
        }

        public async Task RunConsoleAsync(CancellationToken ct)
        {
            Console.WriteLine("\nComando listo. Escribe help si quieres ver opciones.\n");
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
            if (parts.Length == 2 && parts[0] is "pak" or "bst" or "mtu" or "ip") return $"{parts[0]}-{parts[1]}";
            if (parts.Length == 2 && parts[0] == "create" && parts[1] is "server" or "red" or "network") return $"create-{parts[1]}";
            if (parts.Length == 2 && parts[0] == "leave" && parts[1] == "lan") return "leave-lan";
            if (parts.Length == 2 && parts[0] == "reset" && parts[1] == "lobby") return "reset-lobby";
            return c switch
            {
                "peers" => "stat",
                "y" => "s",
                "yes" => "s",
                _ => c.Replace(' ', '-')
            };
        }

        private string ControlHelpText() => $"""
QuicLAN control

Lobby / LAN:
  create server       proponer una LAN modo SERVER/host
  create red          proponer una LAN modo RED completa
  s, ready, listo     marcarte listo o unirte a LAN activa
  start               iniciar la LAN propuesta si tu la creaste
  cancel              cancelar tu propuesta activa
  n, lobby            quitar listo o salir de LAN sin salir de sala
  reset lobby         limpiar tu estado local de lobby/propuesta
  stat, peers         estado resumido

IPs:
  ip 10.88.x.x        reservar IP custom antes de entrar a LAN
                      Si esta ocupada, gana quien la reservo primero.

Ajustes rapidos:
  pak 1000            paquete overlay/IP. Rango {MinPak}-{MaxPak}
  bst 16              rafaga interna. Rango {MinBurst}-{MaxBurst}
  mtu 1200            MTU virtual. Rango {MinMtu}-{MaxMtu}
  reset               vuelve a valores seguros

Sistema:
  help                esta ayuda
  quit                cerrar
""";

        private string BuildStatusText()
        {
            RuntimeSettings s = _settings.Current;
            LanSessionInfo? active;
            LobbyProposal? proposal;
            LobbyMemberState localState;
            lock (_lobbyLock)
            {
                active = _activeLan;
                proposal = _activeProposal ?? _ownedProposal;
                localState = _localLobbyState;
            }

            var sb = new StringBuilder();
            sb.AppendLine("QuicLAN control / estado");
            sb.AppendLine($"nombre={_options.Name}");
            sb.AppendLine($"peer={_localId} ip={IpToString(GetLocalIp())}/{DefaultPrefixBits} modo_ip={_localIpMode}");
            sb.AppendLine($"estado={MemberStateText(localState)} lan={(active is null ? "no activa" : $"{ModeText(active.Mode)} {active.SessionId} host={active.HostName}")}");
            if (proposal is not null)
                sb.AppendLine($"propuesta={ModeText(proposal.Mode)} por {proposal.OwnerName} session={proposal.SessionId}");
            sb.AppendLine($"settings: mtu={s.Mtu} pak={s.Pak} bst={s.Burst} effective_packet={s.EffectivePacketLimit}");
            sb.AppendLine($"udp_discovery=0.0.0.0:{_options.Port} quic_data=0.0.0.0:{_options.DataPort} quic_enabled={!_options.DisableQuic}");
            sb.AppendLine($"counters: tx={Interlocked.Read(ref _txPackets)} rx={Interlocked.Read(ref _rxPackets)} drop={Interlocked.Read(ref _droppedPackets)} quic={Interlocked.Read(ref _quicPackets)} udp_legacy={Interlocked.Read(ref _legacyUdpPackets)} queue={_sendQueue.Reader.Count}");
            sb.AppendLine($"peers_online={_peers.Values.Count(p => p.IsOnline)} peers_known={_peers.Count}");
            foreach (var peer in _peers.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"- {peer.Name} state={MemberStateText(peer.LobbyState)} id={peer.Id} ip={IpToString(peer.VirtualIp)} ipmode={peer.IpMode} mtu={peer.Mtu} online={peer.IsOnline} ep={peer.EndPoint} quic_open={peer.QuicLink is { IsOpen: true }}");
            return sb.ToString();
        }

        private async Task<string> CreateLocalProposalAsync(LanMode mode, CancellationToken ct)
        {
            LobbyProposal proposal;
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                if (_activeLan is not null)
                    return $"Ya hay una LAN activa ({ModeText(_activeLan.Mode)} con {_activeLan.HostName}). Solo puedes unirte o quedarte en lobby.\n";
                if (_activeProposal is not null)
                    return $"Ya hay una propuesta activa de {_activeProposal.OwnerName}: {ModeText(_activeProposal.Mode)}. Usa ready, cancel o espera a que expire.\n";
                if (_ownedProposal is not null)
                    return $"Ya tienes una propuesta local activa: {ModeText(_ownedProposal.Mode)} {_ownedProposal.SessionId}. Usa start o cancel.\n";

                proposal = new LobbyProposal(CreateLanSessionId(), mode, _localId, _options.Name, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                _activeProposal = proposal;
                _ownedProposal = proposal;
                SetLocalMemberStateLocked(LobbyMemberState.Ready);
            }

            ConsolePanelHub.PublishLog($"propuesta creada: {ModeText(mode)} session={proposal.SessionId}");
            await BroadcastControlPayloadAsync(ControlPayload.CreateLanProposal(proposal), except: null, ct);
            await BroadcastLocalLobbyStatusAsync(ct);
            return $"Propuesta creada: {ModeText(mode)}. Tu estas listo. Cuando quieras iniciar con los listos, escribe start.\n";
        }

        private async Task<string> ReadyOrJoinLanAsync(CancellationToken ct)
        {
            LobbyProposal? proposal;
            LanSessionInfo? active;
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                proposal = _activeProposal ?? _ownedProposal;
                active = _activeLan;
                if (active is not null) SetLocalMemberStateLocked(LobbyMemberState.InLan);
                else if (proposal is not null) SetLocalMemberStateLocked(LobbyMemberState.Ready);
                else return "No hay propuesta ni LAN activa todavia. Usa create server o create red, o espera a otro usuario.\n";
            }

            await BroadcastLocalLobbyStatusAsync(ct);
            if (active is not null)
            {
                ConsolePanelHub.PublishLog($"te uniste a LAN activa {active.SessionId} ({ModeText(active.Mode)})");
                KickQuicForLanPeers("union local a LAN");
                return $"Unido a LAN activa {active.SessionId} ({ModeText(active.Mode)}).\n";
            }
            ConsolePanelHub.PublishLog($"estas listo para propuesta {proposal!.SessionId}");
            return $"Listo para entrar cuando se inicie {proposal.SessionId} ({ModeText(proposal.Mode)}).\n";
        }

        private async Task<string> StartLocalProposalAsync(CancellationToken ct)
        {
            LobbyProposal proposal;
            LanSessionInfo session;
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                if (_activeProposal is null && _ownedProposal is null) return "No hay propuesta activa. Usa create server o create red.\n";
                proposal = _activeProposal ?? _ownedProposal!;
                if (proposal.IsExpired(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
                {
                    _activeProposal = null;
                    _ownedProposal = null;
                    return "La propuesta expiro. Usa create server o create red.\n";
                }
                if (!proposal.OwnerId.Equals(_localId)) return $"Solo {proposal.OwnerName} puede iniciar esta propuesta.\n";
                session = new LanSessionInfo(proposal.SessionId, proposal.Mode, proposal.OwnerId, proposal.OwnerName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                _activeLan = session;
                _activeProposal = null;
                _ownedProposal = null;
                SetLocalMemberStateLocked(LobbyMemberState.InLan);
            }

            ConsolePanelHub.PublishLog($"LAN iniciada: {ModeText(session.Mode)} {session.SessionId} host/coordinador={session.HostName}");
            await BroadcastControlPayloadAsync(ControlPayload.CreateLanSession(session, active: true), except: null, ct);
            await BroadcastLocalLobbyStatusAsync(ct);
            KickQuicForLanPeers("LAN iniciada");
            return $"LAN iniciada: {ModeText(session.Mode)} {session.SessionId}. Los listos entran; los demas siguen en lobby.\n";
        }

        private async Task<string> CancelLocalProposalAsync(string reason, CancellationToken ct)
        {
            LobbyProposal? proposal;
            lock (_lobbyLock)
            {
                proposal = _activeProposal ?? _ownedProposal;
                if (proposal is null) return "No hay propuesta que cancelar.\n";
                if (!proposal.OwnerId.Equals(_localId)) return $"Solo {proposal.OwnerName} puede cancelar esta propuesta.\n";
                _activeProposal = null;
                _ownedProposal = null;
                SetLocalMemberStateLocked(LobbyMemberState.Lobby);
            }

            ConsolePanelHub.PublishLog($"propuesta cancelada: {proposal.SessionId}");
            await BroadcastControlPayloadAsync(ControlPayload.CreateLanCancel(proposal.SessionId, reason), except: null, ct);
            await BroadcastLocalLobbyStatusAsync(ct);
            return "Propuesta cancelada. Sigues en lobby.\n";
        }

        private async Task<string> LeaveLanOrNotReadyAsync(CancellationToken ct)
        {
            LanSessionInfo? endedSession = null;
            lock (_lobbyLock)
            {
                if (_activeLan is not null && _activeLan.HostId.Equals(_localId) && _activeLan.Mode == LanMode.Server)
                {
                    endedSession = _activeLan;
                    _activeLan = null;
                    _ownedProposal = null;
                }
                SetLocalMemberStateLocked(LobbyMemberState.Lobby);
            }

            if (endedSession is not null)
            {
                await BroadcastControlPayloadAsync(ControlPayload.CreateLanSession(endedSession, active: false), except: null, ct);
                ConsolePanelHub.PublishLog($"host salio: LAN {endedSession.SessionId} cerrada, todos quedan en lobby");
            }
            await BroadcastLocalLobbyStatusAsync(ct);
            return endedSession is null
                ? "Estas en LOBBY. No sales de la sala; solo pausas/sales de LAN.\n"
                : "Has cerrado la LAN server. La sala sigue viva en lobby.\n";
        }

        private async Task<string> ResetLocalLobbyAsync(CancellationToken ct)
        {
            lock (_lobbyLock)
            {
                _activeProposal = null;
                _ownedProposal = null;
                _activeLan = null;
                SetLocalMemberStateLocked(LobbyMemberState.Lobby);
            }
            await BroadcastLocalLobbyStatusAsync(ct);
            ConsolePanelHub.PublishLog("reset local de lobby: vuelves a sala sin LAN/propuesta local");
            return "Lobby local reseteado. Sigues en la sala.\n";
        }

        private async Task<string> TrySetLocalCustomIpAsync(string ipText, CancellationToken ct)
        {
            if (!IPAddress.TryParse(ipText, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return "IP invalida. Ejemplo: ip 10.88.0.50\n";
            uint wanted = Ipv4ToUInt32(parsed.GetAddressBytes());
            LanSessionInfo? active;
            lock (_lobbyLock) active = _activeLan;
            if (active is not null && IsLocalLanReady)
                return "No puedes cambiar IP mientras estas dentro de una LAN activa. Sal a lobby primero.\n";
            if (!IsOverlayUnicast(wanted) || (wanted & 0xFFFF0000u) != (_options.Prefix & 0xFFFF0000u))
                return $"Esa IP no pertenece a la red virtual {IpToString(_options.Prefix)}/{DefaultPrefixBits}.\n";
            if (IpIsAlreadyClaimed(wanted, _localId))
                return $"Esa IP ya esta ocupada/reservada: {IpToString(wanted)}. Mira el panel de lobby para ver quien la tiene.\n";
            if (!TryFindSaltForVirtualIp(wanted, out ushort salt))
                return "No pude reservar esa IP con tu identidad actual. Prueba otra IP del rango.\n";

            uint old;
            lock (_ipLock)
            {
                old = _localIp;
                _localIp = wanted;
                _ipSalt = salt;
                _localIpMode = "custom";
                SaveIpSalt(_options.Room, _ipSalt);
                ConfigureAdapter(_options.AdapterName, IpToString(_localIp), _settings.Current.EffectivePacketLimit);
            }

            ConsolePanelHub.PublishLog($"IP custom reservada: {IpToString(old)} -> {IpToString(wanted)}");
            await BroadcastIpClaimAsync(ct);
            await BroadcastLocalLobbyStatusAsync(ct);
            await SendDiscoveryRoundAsync(includeKnownPeers: false, ct);
            return $"IP custom reservada: {IpToString(wanted)}. Si alguien ya la reservo primero, te la rechazara.\n";
        }

        private bool TryFindSaltForVirtualIp(uint wanted, out ushort salt)
        {
            for (int i = 1; i <= ushort.MaxValue; i++)
            {
                ushort candidate = (ushort)i;
                if (CalculateVirtualIp(_roomKey, _localId, candidate, _options.Prefix) == wanted)
                {
                    salt = candidate;
                    return true;
                }
            }
            salt = 0;
            return false;
        }

        private void ApplyRemoteLobbyStatus(PeerState peer, LobbyStatusInfo lobby)
        {
            if (!IsValidLobbyState(lobby.State)) return;
            peer.SetLobbyState(lobby.State);
            peer.LanSessionId = lobby.State is LobbyMemberState.Ready or LobbyMemberState.InLan
                ? SanitizeSessionId(lobby.SessionId)
                : "";
            peer.IpMode = string.IsNullOrWhiteSpace(lobby.IpMode) ? "auto" : lobby.IpMode;
            if (lobby.Ip != 0 && lobby.Ip != peer.VirtualIp)
                LogVerbose($"LobbyStatus de {peer.Name} anuncia IP {IpToString(lobby.Ip)}, pero la ruta se mantiene con la IP validada por hello/ip-claim.");
            ConsolePanelHub.PublishLog($"{peer.Name}: {MemberStateText(lobby.State)}" + (string.IsNullOrEmpty(peer.LanSessionId) ? "" : $" en {peer.LanSessionId}"));
            if (lobby.State == LobbyMemberState.InLan || lobby.State == LobbyMemberState.Ready)
                KickQuicForLanPeers($"estado {MemberStateText(lobby.State)} de {peer.Name}");
        }

        private void ApplyRemoteLanProposal(PeerState peer, LanProposalInfo info)
        {
            string sessionId = SanitizeSessionId(info.SessionId);
            if (sessionId.Length == 0 || !IsValidLanMode(info.Mode)) return;
            var proposal = new LobbyProposal(sessionId, info.Mode, info.OwnerId, SanitizeDisplayText(info.OwnerName), info.CreatedMs);
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                if (_activeLan is not null) return;
                if (_ownedProposal is not null && !_ownedProposal.SessionId.Equals(proposal.SessionId, StringComparison.OrdinalIgnoreCase) && !_ownedProposal.IsExpired(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
                {
                    ConsolePanelHub.PublishLog($"propuesta ignorada de {peer.Name}: tu propuesta local {_ownedProposal.SessionId} sigue activa");
                    return;
                }
                if (_activeProposal is not null && !_activeProposal.SessionId.Equals(proposal.SessionId, StringComparison.OrdinalIgnoreCase))
                {
                    ConsolePanelHub.PublishLog($"propuesta ignorada de {peer.Name}: ya existe {_activeProposal.SessionId} de {_activeProposal.OwnerName}");
                    return;
                }
                _activeProposal = proposal;
            }
            if (peer.Id.Equals(proposal.OwnerId))
            {
                peer.LanSessionId = proposal.SessionId;
                if (peer.LobbyState == LobbyMemberState.Lobby)
                    peer.SetLobbyState(LobbyMemberState.Ready);
            }
            ConsolePanelHub.PublishLog($"propuesta recibida: {proposal.OwnerName} quiere crear {ModeText(proposal.Mode)} ({proposal.SessionId}). Escribe ready si quieres entrar.");
        }

        private void ApplyRemoteLanSession(PeerState peer, LanSessionPayloadInfo info)
        {
            string sessionId = SanitizeSessionId(info.SessionId);
            if (sessionId.Length == 0 || !IsValidLanMode(info.Mode)) return;
            var session = new LanSessionInfo(sessionId, info.Mode, info.HostId, SanitizeDisplayText(info.HostName), info.StartedMs);
            bool senderIsHost = peer.Id.Equals(session.HostId);
            bool shouldEnter = false;
            lock (_lobbyLock)
            {
                if (!info.Active)
                {
                    if (senderIsHost)
                    {
                        peer.LanSessionId = "";
                        peer.SetLobbyState(LobbyMemberState.Lobby);
                    }
                    if (_activeLan?.SessionId == session.SessionId) _activeLan = null;
                    if (_activeProposal?.SessionId == session.SessionId) _activeProposal = null;
                    SetLocalMemberStateLocked(LobbyMemberState.Lobby);
                    ConsolePanelHub.PublishLog($"LAN cerrada por host/coordinador: {session.SessionId}");
                    _ = BroadcastLocalLobbyStatusAsync(_shutdown.Token);
                    return;
                }

                if (_activeLan is not null && !_activeLan.SessionId.Equals(session.SessionId, StringComparison.OrdinalIgnoreCase))
                {
                    ConsolePanelHub.PublishLog($"LAN remota ignorada de {peer.Name}: ya existe {_activeLan.SessionId}");
                    return;
                }
                if (_ownedProposal is not null && !_ownedProposal.SessionId.Equals(session.SessionId, StringComparison.OrdinalIgnoreCase) && !_ownedProposal.IsExpired(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
                {
                    ConsolePanelHub.PublishLog($"LAN remota ignorada de {peer.Name}: tienes propuesta local {_ownedProposal.SessionId}");
                    return;
                }
                _activeLan = session;
                if (_activeProposal?.SessionId == session.SessionId) _activeProposal = null;
                if (_ownedProposal?.SessionId == session.SessionId) _ownedProposal = null;
                shouldEnter = _localLobbyState == LobbyMemberState.Ready || session.HostId.Equals(_localId);
                if (shouldEnter) SetLocalMemberStateLocked(LobbyMemberState.InLan);
            }

            if (senderIsHost)
            {
                peer.LanSessionId = session.SessionId;
                peer.SetLobbyState(LobbyMemberState.InLan);
            }

            ConsolePanelHub.PublishLog($"LAN activa: {ModeText(session.Mode)} {session.SessionId} host/coordinador={session.HostName}" + (shouldEnter ? " - entras porque estabas listo" : " - sigues en lobby"));
            if (shouldEnter)
            {
                _ = BroadcastLocalLobbyStatusAsync(_shutdown.Token);
                KickQuicForLanPeers("LAN remota activa");
            }
        }

        private void ApplyRemoteLanCancel(PeerState peer, LanCancelInfo info)
        {
            string sessionId = SanitizeSessionId(info.SessionId);
            if (sessionId.Length == 0) return;
            lock (_lobbyLock)
            {
                if (_ownedProposal?.SessionId == sessionId)
                {
                    ConsolePanelHub.PublishLog($"cancel remoto ignorado para tu propuesta local {sessionId}");
                    return;
                }
                if (_activeProposal?.SessionId == sessionId)
                {
                    _activeProposal = null;
                    if (_localLobbyState == LobbyMemberState.Ready) SetLocalMemberStateLocked(LobbyMemberState.Lobby);
                }
            }
            ConsolePanelHub.PublishLog($"propuesta cancelada: {sessionId} ({SanitizeDisplayText(info.Reason, 120)})");
            _ = BroadcastLocalLobbyStatusAsync(_shutdown.Token);
        }

        private void PruneExpiredProposalLocked()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_activeProposal is not null && _activeProposal.IsExpired(now))
            {
                ConsolePanelHub.PublishLog($"propuesta expirada: {_activeProposal.SessionId}");
                if (_ownedProposal?.SessionId == _activeProposal.SessionId) _ownedProposal = null;
                _activeProposal = null;
                if (_localLobbyState == LobbyMemberState.Ready) SetLocalMemberStateLocked(LobbyMemberState.Lobby);
            }
            if (_ownedProposal is not null && _ownedProposal.IsExpired(now))
            {
                ConsolePanelHub.PublishLog($"propuesta local expirada: {_ownedProposal.SessionId}");
                _ownedProposal = null;
            }
        }

        private void SetLocalMemberStateLocked(LobbyMemberState state)
        {
            _localLobbyState = state;
            Volatile.Write(ref _localLanReady, state == LobbyMemberState.InLan ? 1 : 0);
        }

        private string LocalSessionForStatus()
        {
            lock (_lobbyLock)
                return _activeLan?.SessionId ?? _activeProposal?.SessionId ?? _ownedProposal?.SessionId ?? "";
        }

        private static string CreateLanSessionId()
        {
            Span<byte> b = stackalloc byte[4];
            RandomNumberGenerator.Fill(b);
            return "LAN-" + Convert.ToHexString(b).ToUpperInvariant();
        }

        private static string SanitizeSessionId(string? sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId)) return "";
            var sb = new StringBuilder(Math.Min(sessionId.Length, 32));
            foreach (char c in sessionId)
            {
                if (char.IsLetterOrDigit(c) || c is '-' or '_') sb.Append(c);
                if (sb.Length >= 32) break;
            }
            return sb.ToString();
        }

        private static bool IsValidLanMode(LanMode mode) => mode is LanMode.Red or LanMode.Server;
        private static bool IsValidLobbyState(LobbyMemberState state) =>
            state is LobbyMemberState.Lobby or LobbyMemberState.Ready or LobbyMemberState.InLan or LobbyMemberState.Reconnecting;

        private static string ModeText(LanMode mode) => mode switch
        {
            LanMode.Red => "RED completa",
            LanMode.Server => "SERVER/host",
            _ => "sin LAN"
        };

        private static string MemberStateText(LobbyMemberState state) => state switch
        {
            LobbyMemberState.Ready => "LISTO",
            LobbyMemberState.InLan => "EN LAN",
            LobbyMemberState.Reconnecting => "RECONECTANDO",
            _ => "LOBBY"
        };

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

        private Task SendLocalLobbyStatusAsync(PeerState peer, CancellationToken ct) =>
            SendControlAsync(peer, ControlPayload.CreateLobbyStatus(_localLobbyState, LocalSessionForStatus(), GetLocalIp(), _localIpMode), ct);

        private Task SendCurrentLobbySnapshotAsync(PeerState peer, CancellationToken ct)
        {
            List<Task> tasks = [];
            LobbyProposal? proposal;
            LanSessionInfo? session;
            LobbyMemberState state;
            string sessionId;
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                proposal = _activeProposal ?? _ownedProposal;
                session = _activeLan;
                state = _localLobbyState;
                sessionId = session?.SessionId ?? proposal?.SessionId ?? "";
            }

            tasks.Add(SendControlAsync(peer, ControlPayload.CreateLobbyStatus(state, sessionId, GetLocalIp(), _localIpMode), ct));
            if (proposal is not null && proposal.OwnerId.Equals(_localId)) tasks.Add(SendControlAsync(peer, ControlPayload.CreateLanProposal(proposal), ct));
            if (session is not null && session.HostId.Equals(_localId)) tasks.Add(SendControlAsync(peer, ControlPayload.CreateLanSession(session, active: true), ct));
            return Task.WhenAll(tasks);
        }

        private async Task BroadcastLocalLobbyStatusAsync(CancellationToken ct)
        {
            await BroadcastControlPayloadAsync(ControlPayload.CreateLobbyStatus(_localLobbyState, LocalSessionForStatus(), GetLocalIp(), _localIpMode), except: null, ct);
        }

        private async Task BroadcastCurrentLobbySnapshotAsync(CancellationToken ct)
        {
            LobbyProposal? proposal;
            LanSessionInfo? session;
            LobbyMemberState state;
            string sessionId;
            lock (_lobbyLock)
            {
                PruneExpiredProposalLocked();
                proposal = _activeProposal ?? _ownedProposal;
                session = _activeLan;
                state = _localLobbyState;
                sessionId = session?.SessionId ?? proposal?.SessionId ?? "";
            }

            if (state == LobbyMemberState.Lobby && proposal is null && session is null) return;
            await BroadcastControlPayloadAsync(ControlPayload.CreateLobbyStatus(state, sessionId, GetLocalIp(), _localIpMode), except: null, ct);
            if (proposal is not null && proposal.OwnerId.Equals(_localId))
                await BroadcastControlPayloadAsync(ControlPayload.CreateLanProposal(proposal), except: null, ct);
            if (session is not null && session.HostId.Equals(_localId))
                await BroadcastControlPayloadAsync(ControlPayload.CreateLanSession(session, active: true), except: null, ct);
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
            if (salt == 0 || !IsOverlayUnicast(ip) || VirtualIpConflictsWithLocalNetworks(ip) || !VirtualIpMatchesSalt(peer.Id, ip, salt))
            {
                _ = SendIpRejectAsync(peer, ip, "ip-invalida", _shutdown.Token);
                return;
            }

            if (IpIsAlreadyClaimed(ip, peer.Id))
            {
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
            ConsolePanelHub.PublishLog(old == 0
                ? $"IP virtual aceptada de {peer.Name}: {IpToString(ip)}"
                : $"IP virtual actualizada de {peer.Name}: {IpToString(old)} -> {IpToString(ip)}");
            if (becameOnline || old != ip)
            {
                _ = SendHelloAsync(peer.EndPoint, _shutdown.Token);
                _ = SendCurrentSettingsAsync(peer, _shutdown.Token);
                _ = SendCurrentLobbySnapshotAsync(peer, _shutdown.Token);
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

        private bool ShouldSendLanPacketToPeer(PeerState peer)
        {
            if (!IsLocalLanReady || !peer.IsOnline || !peer.IsLanReady || peer.DataCrypto is null) return false;
            LanSessionInfo? active;
            lock (_lobbyLock) active = _activeLan;
            if (active is null || !PeerSessionMatches(peer, active)) return false;
            if (active.Mode == LanMode.Red) return true;
            if (active.Mode == LanMode.Server)
            {
                if (active.HostId.Equals(_localId)) return true;
                return peer.Id.Equals(active.HostId);
            }
            return false;
        }


        private void KickQuicForLanPeers(string reason)
        {
            if (_options.DisableQuic || !IsLocalLanReady) return;
            LanSessionInfo? active;
            lock (_lobbyLock) active = _activeLan;
            if (active is null) return;

            foreach (var peer in _peers.Values)
            {
                if (peer.QuicLink is { IsOpen: true }) continue;
                if (!ShouldAttemptQuicForLanPeer(peer, active)) continue;
                if (peer.QuicEndPoint is null || !IsUsableTransportEndpoint(peer.QuicEndPoint)) continue;
                ConsolePanelHub.PublishLog($"QUIC intentando con {peer.Name} ({reason}) -> {peer.QuicEndPoint}");
                _ = EnsureQuicConnectionAsync(peer, _shutdown.Token);
            }
        }

        private bool ShouldAttemptQuicForLanPeer(PeerState peer, LanSessionInfo active)
        {
            if (!peer.IsOnline || peer.DataCrypto is null || !PeerSessionMatches(peer, active)) return false;
            if (active.Mode == LanMode.Red)
                return peer.LobbyState is LobbyMemberState.Ready or LobbyMemberState.InLan;
            if (active.Mode == LanMode.Server)
            {
                if (active.HostId.Equals(_localId))
                    return peer.LobbyState is LobbyMemberState.Ready or LobbyMemberState.InLan;
                return peer.Id.Equals(active.HostId) && (peer.LobbyState is LobbyMemberState.Ready or LobbyMemberState.InLan);
            }
            return false;
        }

        private static bool PeerSessionMatches(PeerState peer, LanSessionInfo active) =>
            !string.IsNullOrWhiteSpace(peer.LanSessionId) &&
            peer.LanSessionId.Equals(active.SessionId, StringComparison.OrdinalIgnoreCase);

        private async Task ReselectLocalIpAsync(string reason, IEnumerable<uint> extraOccupied, CancellationToken ct)
        {
            if (_localIpMode.Equals("custom", StringComparison.OrdinalIgnoreCase))
            {
                ConsolePanelHub.PublishLog($"tu IP custom fue rechazada por {reason}; elige otra con: ip 10.88.x.x");
                return;
            }

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
                _localIpMode = "auto";
                SaveIpSalt(_options.Room, _ipSalt);
                ConfigureAdapter(_options.AdapterName, IpToString(_localIp), _settings.Current.EffectivePacketLimit);
            }

            ConsolePanelHub.PublishLog($"IP virtual reasignada por {reason}: {IpToString(oldIp)} -> {IpToString(nextIp)}/{DefaultPrefixBits}");
            await BroadcastIpClaimAsync(ct);
            await BroadcastLocalLobbyStatusAsync(ct);
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

    private enum ControlMessageKind : byte
    {
        SettingsUpdate = 1,
        IpClaim = 3,
        IpReject = 4,
        Chat = 5,
        LobbyStatus = 6,
        LanProposal = 7,
        LanSession = 8,
        LanCancel = 9
    }

    private sealed record ControlMessage(
        ControlMessageKind Kind,
        SettingsUpdate? SettingsUpdate = null,
        IpClaimInfo? IpClaim = null,
        IpRejectInfo? IpReject = null,
        ChatInfo? Chat = null,
        LobbyStatusInfo? LobbyStatus = null,
        LanProposalInfo? LanProposal = null,
        LanSessionPayloadInfo? LanSession = null,
        LanCancelInfo? LanCancel = null);

    private readonly record struct IpClaimInfo(uint Ip, ushort Salt);
    private readonly record struct IpRejectInfo(uint Ip, string Reason);
    private readonly record struct ChatInfo(string Text);
    private readonly record struct LobbyStatusInfo(LobbyMemberState State, string SessionId, uint Ip, string IpMode);
    private readonly record struct LanProposalInfo(string SessionId, LanMode Mode, PeerId OwnerId, string OwnerName, long CreatedMs);
    private readonly record struct LanSessionPayloadInfo(string SessionId, LanMode Mode, PeerId HostId, string HostName, bool Active, long StartedMs);
    private readonly record struct LanCancelInfo(string SessionId, string Reason);

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
            byte[] reasonBytes = Utf8Limited(reason, 120, "rechazada");
            var b = new byte[1 + 4 + 1 + reasonBytes.Length];
            b[0] = (byte)ControlMessageKind.IpReject;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(1, 4), ip);
            b[5] = (byte)reasonBytes.Length;
            reasonBytes.CopyTo(b.AsSpan(6));
            return b;
        }

        public static byte[] CreateChat(string text)
        {
            byte[] textBytes = Utf8Limited(text, 500, "...");
            var b = new byte[1 + 2 + textBytes.Length];
            b[0] = (byte)ControlMessageKind.Chat;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(1, 2), (ushort)textBytes.Length);
            textBytes.CopyTo(b.AsSpan(3));
            return b;
        }

        public static byte[] CreateLobbyStatus(LobbyMemberState state, string sessionId, uint ip, string ipMode)
        {
            byte[] sessionBytes = Utf8Limited(sessionId, 32, "");
            byte[] modeBytes = Utf8Limited(ipMode, 16, "auto");
            var b = new byte[1 + 1 + 2 + sessionBytes.Length + 4 + 1 + modeBytes.Length];
            b[0] = (byte)ControlMessageKind.LobbyStatus;
            b[1] = (byte)state;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2, 2), (ushort)sessionBytes.Length);
            sessionBytes.CopyTo(b.AsSpan(4));
            int o = 4 + sessionBytes.Length;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o, 4), ip);
            o += 4;
            b[o++] = (byte)modeBytes.Length;
            modeBytes.CopyTo(b.AsSpan(o));
            return b;
        }

        public static byte[] CreateLanProposal(LobbyProposal proposal)
        {
            byte[] sessionBytes = Utf8Limited(proposal.SessionId, 32, "LAN");
            byte[] nameBytes = Utf8Limited(proposal.OwnerName, 80, "host");
            var b = new byte[1 + 1 + 8 + 16 + 2 + sessionBytes.Length + 2 + nameBytes.Length];
            int o = 0;
            b[o++] = (byte)ControlMessageKind.LanProposal;
            b[o++] = (byte)proposal.Mode;
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(o, 8), proposal.CreatedMs); o += 8;
            proposal.OwnerId.WriteTo(b.AsSpan(o, 16)); o += 16;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)sessionBytes.Length); o += 2;
            sessionBytes.CopyTo(b.AsSpan(o)); o += sessionBytes.Length;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)nameBytes.Length); o += 2;
            nameBytes.CopyTo(b.AsSpan(o));
            return b;
        }

        public static byte[] CreateLanSession(LanSessionInfo session, bool active)
        {
            byte[] sessionBytes = Utf8Limited(session.SessionId, 32, "LAN");
            byte[] nameBytes = Utf8Limited(session.HostName, 80, "host");
            var b = new byte[1 + 1 + 1 + 8 + 16 + 2 + sessionBytes.Length + 2 + nameBytes.Length];
            int o = 0;
            b[o++] = (byte)ControlMessageKind.LanSession;
            b[o++] = (byte)session.Mode;
            b[o++] = active ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(o, 8), session.StartedMs); o += 8;
            session.HostId.WriteTo(b.AsSpan(o, 16)); o += 16;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)sessionBytes.Length); o += 2;
            sessionBytes.CopyTo(b.AsSpan(o)); o += sessionBytes.Length;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)nameBytes.Length); o += 2;
            nameBytes.CopyTo(b.AsSpan(o));
            return b;
        }

        public static byte[] CreateLanCancel(string sessionId, string reason)
        {
            byte[] sessionBytes = Utf8Limited(sessionId, 32, "LAN");
            byte[] reasonBytes = Utf8Limited(reason, 120, "cancelada");
            var b = new byte[1 + 2 + sessionBytes.Length + 1 + reasonBytes.Length];
            int o = 0;
            b[o++] = (byte)ControlMessageKind.LanCancel;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o, 2), (ushort)sessionBytes.Length); o += 2;
            sessionBytes.CopyTo(b.AsSpan(o)); o += sessionBytes.Length;
            b[o++] = (byte)reasonBytes.Length;
            reasonBytes.CopyTo(b.AsSpan(o));
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
                        message = new ControlMessage(kind, SettingsUpdate: new SettingsUpdate(settings, new SettingsRevision(ts, origin, seq)));
                        return true;

                    case ControlMessageKind.IpClaim:
                        if (b.Length != 7) return false;
                        message = new ControlMessage(kind, IpClaim: new IpClaimInfo(BinaryPrimitives.ReadUInt32BigEndian(b.Slice(1, 4)), BinaryPrimitives.ReadUInt16BigEndian(b.Slice(5, 2))));
                        return true;

                    case ControlMessageKind.IpReject:
                        if (b.Length < 6) return false;
                        uint rejectedIp = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(1, 4));
                        int len = b[5];
                        if (b.Length != 6 + len) return false;
                        message = new ControlMessage(kind, IpReject: new IpRejectInfo(rejectedIp, Encoding.UTF8.GetString(b.Slice(6, len))));
                        return true;

                    case ControlMessageKind.Chat:
                        if (b.Length < 3) return false;
                        int chatLen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(1, 2));
                        if (b.Length != 3 + chatLen) return false;
                        message = new ControlMessage(kind, Chat: new ChatInfo(Encoding.UTF8.GetString(b.Slice(3, chatLen))));
                        return true;

                    case ControlMessageKind.LobbyStatus:
                    {
                        if (b.Length < 1 + 1 + 2 + 4 + 1) return false;
                        var state = (LobbyMemberState)b[1];
                        int slen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(2, 2));
                        if (b.Length < 4 + slen + 4 + 1) return false;
                        string sid = Encoding.UTF8.GetString(b.Slice(4, slen));
                        int o = 4 + slen;
                        uint ip = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(o, 4)); o += 4;
                        int mlen = b[o++];
                        if (b.Length != o + mlen) return false;
                        string ipMode = Encoding.UTF8.GetString(b.Slice(o, mlen));
                        message = new ControlMessage(kind, LobbyStatus: new LobbyStatusInfo(state, sid, ip, ipMode));
                        return true;
                    }

                    case ControlMessageKind.LanProposal:
                    {
                        if (b.Length < 1 + 1 + 8 + 16 + 2 + 2) return false;
                        int o = 1;
                        var mode = (LanMode)b[o++];
                        long created = BinaryPrimitives.ReadInt64BigEndian(b.Slice(o, 8)); o += 8;
                        var owner = PeerId.FromSpan(b.Slice(o, 16)); o += 16;
                        int slen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o, 2)); o += 2;
                        if (b.Length < o + slen + 2) return false;
                        string sid = Encoding.UTF8.GetString(b.Slice(o, slen)); o += slen;
                        int nlen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o, 2)); o += 2;
                        if (b.Length != o + nlen) return false;
                        string name = Encoding.UTF8.GetString(b.Slice(o, nlen));
                        message = new ControlMessage(kind, LanProposal: new LanProposalInfo(sid, mode, owner, name, created));
                        return true;
                    }

                    case ControlMessageKind.LanSession:
                    {
                        if (b.Length < 1 + 1 + 1 + 8 + 16 + 2 + 2) return false;
                        int o = 1;
                        var mode = (LanMode)b[o++];
                        bool active = b[o++] != 0;
                        long started = BinaryPrimitives.ReadInt64BigEndian(b.Slice(o, 8)); o += 8;
                        var host = PeerId.FromSpan(b.Slice(o, 16)); o += 16;
                        int slen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o, 2)); o += 2;
                        if (b.Length < o + slen + 2) return false;
                        string sid = Encoding.UTF8.GetString(b.Slice(o, slen)); o += slen;
                        int nlen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o, 2)); o += 2;
                        if (b.Length != o + nlen) return false;
                        string name = Encoding.UTF8.GetString(b.Slice(o, nlen));
                        message = new ControlMessage(kind, LanSession: new LanSessionPayloadInfo(sid, mode, host, name, active, started));
                        return true;
                    }

                    case ControlMessageKind.LanCancel:
                    {
                        if (b.Length < 1 + 2 + 1) return false;
                        int o = 1;
                        int slen = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(o, 2)); o += 2;
                        if (b.Length < o + slen + 1) return false;
                        string sid = Encoding.UTF8.GetString(b.Slice(o, slen)); o += slen;
                        int rlen = b[o++];
                        if (b.Length != o + rlen) return false;
                        string reason = Encoding.UTF8.GetString(b.Slice(o, rlen));
                        message = new ControlMessage(kind, LanCancel: new LanCancelInfo(sid, reason));
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        private static byte[] Utf8Limited(string? value, int maxBytes, string fallback)
        {
            string text = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            if (bytes.Length <= maxBytes) return bytes;
            return bytes.AsSpan(0, maxBytes).ToArray();
        }
    }
}
