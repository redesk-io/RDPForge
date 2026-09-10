using Microsoft.Win32;
using System;

namespace RDPForge
{
    public static class TsSettings
    {
        const string TsKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
        const string RdpTcp = TsKey + @"\WinStations\RDP-Tcp";
        const string PolicyTs = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

        static RegistryKey OpenTs(bool writable)
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(TsKey, writable);
        }

        public static bool GetAllowConnections()
        {
            using (var key = OpenTs(false))
                return Convert.ToInt32(key?.GetValue("fDenyTSConnections", 1) ?? 1) == 0;
        }

        public static void SetAllowConnections(bool allow)
        {
            using (var key = OpenTs(true))
                key?.SetValue("fDenyTSConnections", allow ? 0 : 1, RegistryValueKind.DWord);
        }

        public static bool GetSingleSessionPerUser()
        {
            using (var key = OpenTs(false))
                return Convert.ToInt32(key?.GetValue("fSingleSessionPerUser", 1) ?? 1) == 1;
        }

        public static void SetSingleSessionPerUser(bool single)
        {
            using (var key = OpenTs(true))
                key?.SetValue("fSingleSessionPerUser", single ? 1 : 0, RegistryValueKind.DWord);
            using (var pol = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(PolicyTs, true))
                pol?.SetValue("fSingleSessionPerUser", single ? 1 : 0, RegistryValueKind.DWord);
        }

        public static int GetPort()
        {
            using (var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(RdpTcp, false))
                return Convert.ToInt32(key?.GetValue("PortNumber", 3389) ?? 3389);
        }

        public static void SetPort(int port)
        {
            using (var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(RdpTcp, true))
                key?.SetValue("PortNumber", port, RegistryValueKind.DWord);
        }
    }
}
