using System;
using System.Runtime.InteropServices;

namespace RDPForge
{
    static class WinStation
    {
        [DllImport("winsta.dll", SetLastError = true)]
        static extern int WinStationEnumerateW(
            IntPtr server,
            out IntPtr sessions,
            out int count);

        [DllImport("winsta.dll", SetLastError = true)]
        static extern int WinStationFreeMemory(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SessionInfo
        {
            public int SessionId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 34)]
            public string Name;
            public int State;
        }

        public static System.Collections.Generic.IEnumerable<string> Enumerate()
        {
            var names = new System.Collections.Generic.List<string>();
            if (WinStationEnumerateW(IntPtr.Zero, out var buf, out var count) == 0 || buf == IntPtr.Zero)
                return names;
            try
            {
                int size = Marshal.SizeOf<SessionInfo>();
                for (int i = 0; i < count; i++)
                {
                    var info = Marshal.PtrToStructure<SessionInfo>(IntPtr.Add(buf, i * size));
                    names.Add(info.Name ?? string.Empty);
                }
            }
            finally { WinStationFreeMemory(buf); }
            return names;
        }
    }
}
