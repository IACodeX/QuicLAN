using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace QuicLan;

internal static partial class Program
{
    private sealed unsafe class WintunAdapter : IDisposable
    {
        private IntPtr _handle;
        private WintunAdapter(IntPtr handle) => _handle = handle;
        public static WintunAdapter CreateOrOpen(string name)
        {
            IntPtr handle = WintunNative.WintunOpenAdapter(name);
            if (handle == IntPtr.Zero)
            {
                Guid guid = Guid.NewGuid();
                handle = WintunNative.WintunCreateAdapter(name, "QuicLAN", &guid);
            }
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo abrir/crear el adaptador Wintun.");
            return new WintunAdapter(handle);
        }
        public WintunSession StartSession(uint capacity = 0x400000)
        {
            IntPtr session = WintunNative.WintunStartSession(_handle, capacity);
            if (session == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo iniciar sesión Wintun.");
            return new WintunSession(session);
        }
        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                WintunNative.WintunCloseAdapter(_handle);
                _handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
    }

    private sealed unsafe class WintunSession : IDisposable
    {
        private IntPtr _handle;
        private readonly WaitHandle _readWaitEvent;
        public WintunSession(IntPtr handle)
        {
            _handle = handle;
            IntPtr wait = WintunNative.WintunGetReadWaitEvent(handle);
            if (wait == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo obtener el evento de lectura Wintun.");
            _readWaitEvent = new EventWaitHandle(false, EventResetMode.AutoReset)
            {
                SafeWaitHandle = new SafeWaitHandle(wait, ownsHandle: false)
            };
        }
        public IntPtr Handle => _handle;
        public WaitHandle ReadWaitEvent => _readWaitEvent;
        public void SendPacket(byte[] packet)
        {
            if (packet.Length is < 20 or > 65535) return;
            byte* dst = WintunNative.WintunAllocateSendPacket(_handle, (uint)packet.Length);
            if (dst == null) throw new Win32Exception(Marshal.GetLastWin32Error(), "WintunAllocateSendPacket falló.");
            Marshal.Copy(packet, 0, (IntPtr)dst, packet.Length);
            WintunNative.WintunSendPacket(_handle, dst);
        }
        public void Dispose()
        {
            _readWaitEvent.Dispose();
            if (_handle != IntPtr.Zero)
            {
                WintunNative.WintunEndSession(_handle);
                _handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
    }

    private static unsafe class WintunNative
    {
        private const string DllName = "wintun";

        static WintunNative()
        {
            NativeLibrary.SetDllImportResolver(typeof(WintunNative).Assembly, (name, assembly, path) =>
            {
                if (name != DllName) return IntPtr.Zero;
                string localDll = Path.Combine(AppContext.BaseDirectory, "wintun.dll");
                return File.Exists(localDll) ? NativeLibrary.Load(localDll) : IntPtr.Zero;
            });
        }
        [DllImport(DllName, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(string name, string tunnelType, Guid* requestedGuid);
        [DllImport(DllName, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunOpenAdapter(string name);
        [DllImport(DllName, ExactSpelling = true)]
        public static extern void WintunCloseAdapter(IntPtr adapter);
        [DllImport(DllName, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);
        [DllImport(DllName, ExactSpelling = true)]
        public static extern void WintunEndSession(IntPtr session);
        [DllImport(DllName, ExactSpelling = true)]
        public static extern IntPtr WintunGetReadWaitEvent(IntPtr session);
        [DllImport(DllName, ExactSpelling = true, SetLastError = true)]
        public static extern byte* WintunReceivePacket(IntPtr session, out uint packetSize);
        [DllImport(DllName, ExactSpelling = true)]
        public static extern void WintunReleaseReceivePacket(IntPtr session, byte* packet);
        [DllImport(DllName, ExactSpelling = true, SetLastError = true)]
        public static extern byte* WintunAllocateSendPacket(IntPtr session, uint packetSize);
        [DllImport(DllName, ExactSpelling = true)]
        public static extern void WintunSendPacket(IntPtr session, byte* packet);
    }

    private static string AppDataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "QuicLAN");

    private static ECDsa LoadOrCreateIdentityKey(string room)
    {
        string path = Path.Combine(AppDataDir, $"identity-{RoomFileKey(room)}.p8");
        var key = ECDsa.Create();
        if (File.Exists(path))
        {
            try
            {
                key.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _);
                return key;
            }
            catch
            {
                key.Dispose();
                File.Move(path, path + ".bad-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds(), overwrite: true);
            }
        }
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllBytes(path, key.ExportPkcs8PrivateKey());
        return key;
    }

    private static ushort LoadOrCreateIpSalt(string room)
    {
        string path = Path.Combine(AppDataDir, $"ipsalt-{RoomFileKey(room)}.bin");
        if (File.Exists(path))
        {
            var b = File.ReadAllBytes(path);
            if (b.Length == 2) return BinaryPrimitives.ReadUInt16BigEndian(b);
        }
        ushort salt = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        SaveIpSalt(room, salt);
        return salt;
    }

    private static void SaveIpSalt(string room, ushort salt)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(b, salt);
        File.WriteAllBytes(Path.Combine(AppDataDir, $"ipsalt-{RoomFileKey(room)}.bin"), b.ToArray());
    }

    private static byte[] DeriveRoomKey(string room)
    {
        using var kdf = new Rfc2898DeriveBytes(room, Encoding.UTF8.GetBytes("QuicLAN room key v5"), 250_000, HashAlgorithmName.SHA256);
        return kdf.GetBytes(32);
    }

    private static byte[] DeriveSubKey(byte[] roomKey, string label)
    {
        using var h = new HMACSHA256(roomKey);
        return h.ComputeHash(Encoding.UTF8.GetBytes("QuicLAN " + label));
    }

    private static byte[] DeriveTrackerInfoHash(byte[] roomKey) => DeriveSubKey(roomKey, "tracker-infohash-v5")[..20];

    private static uint CalculateVirtualIp(byte[] roomKey, PeerId peerId, ushort salt, uint prefix)
    {
        using var h = new HMACSHA256(roomKey);
        Span<byte> data = stackalloc byte[18];
        peerId.WriteTo(data[..16]);
        BinaryPrimitives.WriteUInt16BigEndian(data.Slice(16, 2), salt);
        byte[] hash = h.ComputeHash(data.ToArray());
        uint host = BinaryPrimitives.ReadUInt16BigEndian(hash.AsSpan(0, 2));
        if (host is 0 or 0xFFFF) host ^= 0x4242;
        if ((host & 0xFF) is 0 or 255) host ^= 0x0042;
        return (prefix & 0xFFFF0000) | host;
    }

    private static uint AllocateVirtualIp(byte[] roomKey, PeerId peerId, ref ushort salt, uint prefix, IEnumerable<uint> occupied)
    {
        var used = new HashSet<uint>(occupied.Where(ip => ip != 0));
        ushort candidateSalt = salt == 0 ? (ushort)1 : salt;
        for (int i = 0; i < ushort.MaxValue; i++)
        {
            uint candidate = CalculateVirtualIp(roomKey, peerId, candidateSalt, prefix);
            if (!used.Contains(candidate) && IsUnicastInPrefix(candidate, prefix, DefaultPrefixBits) && !VirtualIpConflictsWithLocalNetworks(candidate))
            {
                salt = candidateSalt;
                return candidate;
            }
            candidateSalt = candidateSalt == ushort.MaxValue ? (ushort)1 : (ushort)(candidateSalt + 1);
        }
        throw new InvalidOperationException("No se pudo encontrar una IP virtual libre para la sala.");
    }

    private static bool IsUnicastInPrefix(uint ip, uint prefix, int bits)
    {
        uint mask = PrefixMask(bits);
        uint host = ip & ~mask;
        return (ip & mask) == (prefix & mask) && host != 0 && host != ~mask;
    }

    private static uint ParsePrefix16(string text)
    {
        string ipText = text.Trim();
        int slash = ipText.IndexOf('/');
        if (slash >= 0)
        {
            string bitsText = ipText[(slash + 1)..];
            ipText = ipText[..slash];
            if (!int.TryParse(bitsText, out int bits) || bits != DefaultPrefixBits)
                throw new ArgumentException($"--prefix sólo admite redes /{DefaultPrefixBits}.");
        }
        if (!IPAddress.TryParse(ipText, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("--prefix debe ser una IPv4 válida, por ejemplo 10.88.0.0 o 10.88.0.0/16.");
        uint value = Ipv4ToUInt32(ip.GetAddressBytes());
        uint mask = PrefixMask(DefaultPrefixBits);
        uint prefix = value & mask;
        byte first = (byte)(prefix >> 24);
        byte second = (byte)(prefix >> 16);
        bool privateRange = first == 10 || (first == 172 && second is >= 16 and <= 31) || (first == 192 && second == 168);
        if (!privateRange)
            throw new ArgumentException("--prefix debe estar en un rango IPv4 privado RFC1918.");
        return prefix;
    }

    private static bool OverlayPrefixConflictsWithLocalNetworks(uint prefix)
    {
        uint overlayMask = PrefixMask(DefaultPrefixBits);
        uint overlayNetwork = prefix & overlayMask;
        foreach (var net in GetLocalIpv4Networks())
        {
            uint commonMask = net.MaskBits < DefaultPrefixBits ? net.Mask : overlayMask;
            if ((net.Network & commonMask) == (overlayNetwork & commonMask))
                return true;
        }
        return false;
    }

    private static bool VirtualIpConflictsWithLocalNetworks(uint ip)
    {
        foreach (var net in GetLocalIpv4Networks())
        {
            if (net.Address == ip || net.Network == ip || net.Broadcast == ip)
                return true;
        }
        return false;
    }

    private static IEnumerable<LocalIpv4Network> GetLocalIpv4Networks()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            IPInterfaceProperties props;
            try { props = nic.GetIPProperties(); }
            catch { continue; }
            foreach (var uni in props.UnicastAddresses)
            {
                if (uni.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var mask = uni.IPv4Mask;
                if (mask is null) continue;
                uint address = Ipv4ToUInt32(uni.Address.GetAddressBytes());
                uint maskValue = Ipv4ToUInt32(mask.GetAddressBytes());
                if (address == 0 || maskValue == 0) continue;
                uint network = address & maskValue;
                uint broadcast = network | ~maskValue;
                int bits = BitOperations.PopCount(maskValue);
                yield return new LocalIpv4Network(address, network, broadcast, maskValue, bits);
            }
        }
    }

    private static uint Ipv4ToUInt32(byte[] bytes)
    {
        if (bytes.Length != 4) throw new ArgumentException("IPv4 esperada.", nameof(bytes));
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    private readonly record struct LocalIpv4Network(uint Address, uint Network, uint Broadcast, uint Mask, int MaskBits);

    private static byte[] MakeTrackerPeerId(PeerId localId)
    {
        var peerId = new byte[20];
        Encoding.ASCII.GetBytes("-QL0003-").CopyTo(peerId, 0);
        Span<byte> id = stackalloc byte[16];
        localId.WriteTo(id);
        id[..12].CopyTo(peerId.AsSpan(8));
        return peerId;
    }

    private static byte[] BuildPairwiseContext(PeerId local, PeerId remote)
    {
        PeerId first = local.CompareTo(remote) <= 0 ? local : remote;
        PeerId second = local.CompareTo(remote) <= 0 ? remote : local;
        byte[] label = Encoding.ASCII.GetBytes("QuicLAN pairwise data v5\0");
        byte[] context = new byte[label.Length + 32];
        label.CopyTo(context, 0);
        first.WriteTo(context.AsSpan(label.Length, 16));
        second.WriteTo(context.AsSpan(label.Length + 16, 16));
        return context;
    }

    private static bool TryParseIpv4Packet(ReadOnlySpan<byte> packet, out Ipv4Info info)
    {
        info = default;
        if (packet.Length < 20 || (packet[0] >> 4) != 4) return false;
        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > packet.Length) return false;
        int totalLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (totalLen < ihl || totalLen != packet.Length) return false;
        uint src = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
        uint dst = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));
        info = new Ipv4Info(src, dst);
        return true;
    }

    private static uint PrefixMask(int bits) => bits == 0 ? 0 : uint.MaxValue << (32 - bits);

    private static string IpToString(uint ip)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, ip);
        return new IPAddress(b).ToString();
    }

    private static string Fingerprint(byte[] data) => Convert.ToHexString(SHA256.HashData(data).AsSpan(0, 6)).ToLowerInvariant();

    private static string RoomFileKey(string room) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(room)).AsSpan(0, 12)).ToLowerInvariant();

    private static ulong RandomUInt64()
    {
        Span<byte> b = stackalloc byte[8];
        RandomNumberGenerator.Fill(b);
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(b);
        return value == 0 ? 1 : value;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var c = new byte[a.Length + b.Length];
        a.CopyTo(c, 0);
        b.CopyTo(c, a.Length);
        return c;
    }

    private static void ConfigureAdapter(string name, string ip, int mtu)
    {
        ValidateAdapterName(name);
        RunNetsh($"interface ip set address name=\"{name}\" static {ip} 255.255.0.0");
        RunNetsh($"interface ipv4 set subinterface \"{name}\" mtu={mtu} store=persistent");
    }

    private static void ValidateAdapterName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 64 || name.Any(c => char.IsControl(c) || c is '"' or '\r' or '\n'))
            throw new ArgumentException("Nombre de adaptador inválido.", nameof(name));
    }

    private static void RunNetsh(string arguments)
    {
        using var p = Process.Start(new ProcessStartInfo("netsh", arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        }) ?? throw new InvalidOperationException("No se pudo ejecutar netsh.");
        if (!p.WaitForExit(10_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("netsh tardó demasiado en responder.");
        }
        if (p.ExitCode != 0)
        {
            string err = p.StandardError.ReadToEnd();
            string output = p.StandardOutput.ReadToEnd();
            throw new InvalidOperationException($"netsh falló: {err}{output}");
        }
    }
}
