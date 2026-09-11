using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace RDPForge
{
    public enum WrapperState { NotInstalled, RDPForge, ThirdParty, Unknown }

    public static class SystemState
    {
        const string TermServiceParams =
            @"SYSTEM\CurrentControlSet\Services\TermService\Parameters";

        public static WrapperState GetWrapperState()
        {
            try
            {
                using (var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                    RegistryView.Registry64).OpenSubKey(TermServiceParams, false))
                {
                    var dll = (key?.GetValue("ServiceDll") as string) ?? string.Empty;
                    var name = Path.GetFileName(dll).ToLowerInvariant();
                    if (name == "termsrv.dll") return WrapperState.NotInstalled;
                    if (name == "forgehook.dll") return WrapperState.RDPForge;
                    if (name.Length == 0) return WrapperState.Unknown;
                    return WrapperState.ThirdParty;
                }
            }
            catch { return WrapperState.Unknown; }
        }

        public static string GetServiceState()
        {
            try
            {
                using (var sc = new ServiceController("TermService"))
                    return sc.Status.ToString();
            }
            catch (Exception ex) { return "Error: " + ex.Message; }
        }

        public static string GetTermsrvVersion()
        {
            try
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var info = FileVersionInfo.GetVersionInfo(Path.Combine(sys, "termsrv.dll"));
                return info.FileVersion ?? "unknown";
            }
            catch { return "unknown"; }
        }

        public static bool IsListenerActive()
        {
            foreach (var session in SystemSessions())
                if (session.Equals("RDP-Tcp", StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        static string[] SystemSessions()
        {
            try
            {
                var names = new System.Collections.Generic.List<string>();
                IntPtr server = WinStation.OpenServer();
                if (server == IntPtr.Zero) return names.ToArray();
                try
                {
                    foreach (var name in WinStation.Enumerate(server))
                        names.Add(name);
                }
                finally { WinStation.CloseServer(server); }
                return names.ToArray();
            }
            catch { return new string[0]; }
        }
    }
}
