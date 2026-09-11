using System;
using System.Collections.Generic;
using System.IO;

namespace RDPForge
{
    public sealed class PatchSummary
    {
        public string Text { get; set; } = "Unknown (no log — reboot to observe)";
        public bool IsGood { get; set; }
        public bool IsBad { get; set; }
    }

    public static class PatchState
    {
        static readonly string[] Sites = { "def_policy", "single_user", "local_only" };

        public static string LogPath() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "RDPForge", "forge.log");

        public static string ReadTail()
        {
            try
            {
                var log = LogPath();
                if (!File.Exists(log)) return string.Empty;
                using (var fs = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs))
                {
                    var text = sr.ReadToEnd();
                    if (text.Length > 8000) text = text.Substring(text.Length - 8000);
                    return text;
                }
            }
            catch { return string.Empty; }
        }

        public static PatchSummary Summarize(string log)
        {
            var summary = new PatchSummary();
            if (string.IsNullOrEmpty(log)) return summary;
            int boot = log.LastIndexOf("event=HOOK_INIT", StringComparison.Ordinal);
            if (boot < 0) return summary;
            var tail = log.Substring(boot);
            var found = new HashSet<string>(StringComparer.Ordinal);
            foreach (var site in Sites)
                if (tail.Contains("event=SITE_FOUND site=" + site))
                    found.Add(site);
            var missing = new List<string>();
            foreach (var site in Sites)
                if (!found.Contains(site)) missing.Add(site);
            if (tail.Contains("event=BOOT result=patched") && missing.Count == 0)
            {
                summary.Text = "Fully patched (3/3)";
                summary.IsGood = true;
            }
            else if (tail.Contains("event=BOOT result=failed"))
            {
                summary.Text = "Boot failed — see log";
                summary.IsBad = true;
            }
            else if (missing.Count == 0)
            {
                summary.Text = "Fully patched (3/3)";
                summary.IsGood = true;
            }
            else
            {
                summary.Text = "Partially patched, missing: " + string.Join(", ", missing);
                summary.IsBad = true;
            }
            return summary;
        }
    }
}
