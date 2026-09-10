using System;
using System.Runtime.InteropServices;

namespace RDPForge
{
    static class WinStation
    {
        [DllImport("winsta.dll", SetLastError = true)]
        static extern IntPtr WinStationOpenServerW(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName);

        [DllImport("winsta.dll", SetLastError = true)]
        static extern bool WinStationCloseServer(IntPtr server);

        [DllImport("winsta.dll", SetLastError = true)]
        static extern int WinStationEnumerateW(
            IntPtr server,
            out IntPtr sessions,
            out int count);

        [DllImport("winsta.dll", SetLastError = true)]
        static extern void WinStationFreeMemory(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential)]
        struct SessionInfo1
        {
            public int ExecEnvId;
            public int State;
            public int SessionId;
            public IntPtr pSessionName;
            public IntPtr pHostName;
            public IntPtr pUserName;
            public IntPtr pDomainName;
            public IntPtr pFarmName;
        }

        public static IntPtr OpenServer() => WinStationOpenServerW(null);

        public static void CloseServer(IntPtr server) => WinStationCloseServer(server);

        public static System.Collections.Generic.IEnumerable<string> Enumerate(IntPtr server)
        {
            var names = new System.Collections.Generic.List<string>();
            if (WinStationEnumerateW(server, out var buf, out var count) == 0 || buf == IntPtr.Zero)
                return names;
            try
            {
                int size = Marshal.SizeOf<SessionInfo1>();
                for (int i = 0; i < count; i++)
                {
                    var info = Marshal.PtrToStructure<SessionInfo1>(IntPtr.Add(buf, i * size));
                    names.Add(Marshal.PtrToStringUni(info.pSessionName) ?? string.Empty);
                }
            }
            finally { WinStationFreeMemory(buf); }
            return names;
        }
    }
}
