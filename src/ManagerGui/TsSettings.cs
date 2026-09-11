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

        static RegistryKey OpenRdpTcp(bool writable)
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(RdpTcp, writable);
        }

        static RegistryKey CreatePolicyTs()
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .CreateSubKey(PolicyTs);
        }

        static RegistryKey CreatePolicyClient()
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .CreateSubKey(PolicyTs + @"\Client");
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
            using (var pol = CreatePolicyTs())
                pol?.SetValue("fSingleSessionPerUser", single ? 1 : 0, RegistryValueKind.DWord);
        }

        public static int GetPort()
        {
            using (var key = OpenRdpTcp(false))
                return Convert.ToInt32(key?.GetValue("PortNumber", 3389) ?? 3389);
        }

        public static void SetPort(int port)
        {
            using (var key = OpenRdpTcp(true))
                key?.SetValue("PortNumber", port, RegistryValueKind.DWord);
        }

        public enum NlaMode { GuiOnly, Default, Nla }

        public static NlaMode GetNla()
        {
            using (var key = OpenRdpTcp(false))
            {
                int layer = Convert.ToInt32(key?.GetValue("SecurityLayer", 1) ?? 1);
                int auth = Convert.ToInt32(key?.GetValue("UserAuthentication", 0) ?? 0);
                if (layer == 2 && auth == 1) return NlaMode.Nla;
                if (layer == 0 && auth == 0) return NlaMode.GuiOnly;
                return NlaMode.Default;
            }
        }

        public static void SetNla(NlaMode mode)
        {
            int layer = 1, auth = 0;
            if (mode == NlaMode.Nla) { layer = 2; auth = 1; }
            if (mode == NlaMode.GuiOnly) { layer = 0; auth = 0; }
            using (var key = OpenRdpTcp(true))
            {
                key?.SetValue("SecurityLayer", layer, RegistryValueKind.DWord);
                key?.SetValue("UserAuthentication", auth, RegistryValueKind.DWord);
            }
        }

        public static int GetShadow()
        {
            using (var key = OpenRdpTcp(false))
                return Convert.ToInt32(key?.GetValue("Shadow", 1) ?? 1);
        }

        public static void SetShadow(int value)
        {
            using (var key = OpenRdpTcp(true))
                key?.SetValue("Shadow", value, RegistryValueKind.DWord);
            using (var pol = CreatePolicyTs())
                pol?.SetValue("Shadow", value, RegistryValueKind.DWord);
        }

        public static bool GetHonorLegacy()
        {
            using (var key = OpenTs(false))
                return Convert.ToInt32(key?.GetValue("HonorLegacySettings", 0) ?? 0) == 1;
        }

        public static void SetHonorLegacy(bool honor)
        {
            using (var key = OpenTs(true))
                key?.SetValue("HonorLegacySettings", honor ? 1 : 0, RegistryValueKind.DWord);
        }

        public static bool GetCameraAllowed()
        {
            using (var pol = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(PolicyTs, false))
                return Convert.ToInt32(pol?.GetValue("fDisableCam", 0) ?? 0) == 0;
        }

        public static void SetCameraAllowed(bool allow)
        {
            using (var pol = CreatePolicyTs())
                pol?.SetValue("fDisableCam", allow ? 0 : 1, RegistryValueKind.DWord);
        }

        public static bool GetUsbForUsers()
        {
            using (var pol = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(PolicyTs + @"\Client", false))
            {
                var v = pol?.GetValue("fUsbRedirectionEnableMode");
                return v != null && Convert.ToInt32(v) == 2;
            }
        }

        public static void SetUsbForUsers(bool users)
        {
            using (var pol = CreatePolicyClient())
            {
                if (pol == null) return;
                if (users) pol.SetValue("fUsbRedirectionEnableMode", 2, RegistryValueKind.DWord);
                else pol.DeleteValue("fUsbRedirectionEnableMode", false);
            }
        }
    }
}
