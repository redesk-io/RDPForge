using System;
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
                Console.WriteLine("ManagerGui: CLI passthrough not yet implemented: " +
                    string.Join(" ", args));
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
    }
}
