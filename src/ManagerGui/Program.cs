using System;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;

namespace RDPForge
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                Environment.Exit(RunInstallerPassthrough(args));
                return;
            }
            bool created;
            using (var mutex = new Mutex(true, "RDPForge.ManagerGui", out created))
            {
                if (!created) return;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
        }

        static int RunInstallerPassthrough(string[] args)
        {
            string mapped = null;
            switch (args[0].ToLowerInvariant())
            {
                case "-install": mapped = "-i"; break;
                case "-uninstall": mapped = "-u"; break;
                case "-restart": mapped = "-r"; break;
                case "-check": mapped = "-l"; break;
            }
            if (mapped == null)
            {
                Console.WriteLine("usage: ManagerGui [-install [-o]| -uninstall [-k] | -restart | -check]");
                return 2;
            }
            var rest = args.Length > 1 ? " " + string.Join(" ", args, 1, args.Length - 1) : string.Empty;
            try
            {
                var psi = new ProcessStartInfo(InstallerRunner.ExePath(), mapped + rest)
                {
                    UseShellExecute = false,
                };
                using (var p = Process.Start(psi))
                {
                    p?.WaitForExit();
                    return p?.ExitCode ?? 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("error: " + ex.Message);
                return 1;
            }
        }
    }
}
