using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace RDPForge
{
    public sealed class CliResult
    {
        public int ExitCode { get; set; }
        public string Output { get; set; } = string.Empty;
    }

    public static class InstallerRunner
    {
        public static string ExePath()
        {
            var dir = Path.GetDirectoryName(
                System.Reflection.Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            return Path.Combine(dir, "InstallerCli.exe");
        }

        public static bool Available() => File.Exists(ExePath());

        public static CliResult Run(string args)
        {
            var result = new CliResult();
            try
            {
                var psi = new ProcessStartInfo(ExePath(), args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                var sb = new StringBuilder();
                using (var p = Process.Start(psi))
                {
                    if (p == null)
                    {
                        result.ExitCode = 1;
                        result.Output = "error: could not start InstallerCli.exe";
                        return result;
                    }
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    p.WaitForExit();
                    result.ExitCode = p.ExitCode;
                }
                result.Output = sb.ToString().Trim();
            }
            catch (Exception ex)
            {
                result.ExitCode = 1;
                result.Output = "error: " + ex.Message;
            }
            return result;
        }

        public static bool IsThirdPartyRefusal(CliResult r) =>
            r.ExitCode != 0 &&
            r.Output.IndexOf("third-party", StringComparison.OrdinalIgnoreCase) >= 0;
    }
}
