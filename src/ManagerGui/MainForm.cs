using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.ServiceProcess;
using System.Windows.Forms;

namespace RDPForge
{
    public class MainForm : Form
    {
        readonly Label lblWrapper = new Label { Left = 12, Top = 12, Width = 460 };
        readonly Label lblService = new Label { Left = 12, Top = 34, Width = 460 };
        readonly Label lblListener = new Label { Left = 12, Top = 56, Width = 460 };
        readonly Label lblVersion = new Label { Left = 12, Top = 78, Width = 460 };
        readonly CheckBox chkConnections = new CheckBox { Left = 12, Top = 106, Width = 260, Text = "Allow RDP connections" };
        readonly CheckBox chkSingleSession = new CheckBox { Left = 280, Top = 106, Width = 200, Text = "Single session per user" };
        readonly ComboBox cmbNla = new ComboBox { Left = 12, Top = 132, Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
        readonly ComboBox cmbShadow = new ComboBox { Left = 220, Top = 132, Width = 240, DropDownStyle = ComboBoxStyle.DropDownList };
        readonly NumericUpDown numPort = new NumericUpDown { Left = 12, Top = 160, Width = 100, Minimum = 1, Maximum = 65535 };
        readonly Button btnApply = new Button { Left = 120, Top = 158, Width = 100, Text = "Apply" };
        readonly Button btnTest = new Button { Left = 228, Top = 158, Width = 110, Text = "Test 127.0.0.2" };
        readonly Button btnRestart = new Button { Left = 346, Top = 158, Width = 120, Text = "Restart service" };
        readonly Button btnUsers = new Button { Left = 12, Top = 188, Width = 120, Text = "Users..." };
        readonly TextBox txtLog = new TextBox { Left = 12, Top = 218, Width = 454, Height = 150, Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true, Font = new Font(FontFamily.GenericMonospace, 8) };
        readonly Timer timer = new Timer { Interval = 1000 };

        public MainForm()
        {
            Text = "RDPForge Manager";
            Width = 494;
            Height = 440;
            cmbNla.Items.AddRange(new object[] { "GUI-only", "Default", "NLA" });
            cmbShadow.Items.AddRange(new object[] {
                "0 - Disable", "1 - Full control with permission",
                "2 - Full control", "3 - View with permission", "4 - View" });
            Controls.AddRange(new Control[] {
                lblWrapper, lblService, lblListener, lblVersion,
                chkConnections, chkSingleSession, cmbNla, cmbShadow,
                numPort, btnApply, btnTest, btnRestart, btnUsers, txtLog });
            btnApply.Click += (s, e) => ApplySettings();
            btnTest.Click += (s, e) => LoopbackTest();
            btnRestart.Click += (s, e) => RestartService();
            btnUsers.Click += (s, e) => ManageUsers();
            timer.Tick += (s, e) => { RefreshDiagnostics(); TailLog(); };
            timer.Start();
            RefreshDiagnostics();
            LoadSettings();
            TailLog();
        }

        void RefreshDiagnostics()
        {
            var wrapper = SystemState.GetWrapperState();
            lblWrapper.Text = "Wrapper: " + wrapper;
            lblService.Text = "TermService: " + SystemState.GetServiceState();
            lblListener.Text = "RDP-Tcp listener: " +
                (SystemState.IsListenerActive() ? "active" : "absent");
            lblVersion.Text = "termsrv.dll: " + SystemState.GetTermsrvVersion();
            lblWrapper.ForeColor = wrapper == WrapperState.RDPForge
                ? System.Drawing.Color.DarkGreen : System.Drawing.Color.DarkRed;
        }

        void LoadSettings()
        {
            try
            {
                chkConnections.Checked = TsSettings.GetAllowConnections();
                chkSingleSession.Checked = TsSettings.GetSingleSessionPerUser();
                cmbNla.SelectedIndex = (int)TsSettings.GetNla();
                cmbShadow.SelectedIndex = TsSettings.GetShadow();
                numPort.Value = TsSettings.GetPort();
            }
            catch (Exception ex) { Warn(ex.Message); }
        }

        void ApplySettings()
        {
            try
            {
                TsSettings.SetAllowConnections(chkConnections.Checked);
                TsSettings.SetSingleSessionPerUser(chkSingleSession.Checked);
                if (cmbNla.SelectedIndex >= 0)
                    TsSettings.SetNla((TsSettings.NlaMode)cmbNla.SelectedIndex);
                if (cmbShadow.SelectedIndex >= 0)
                    TsSettings.SetShadow(cmbShadow.SelectedIndex);
                TsSettings.SetPort((int)numPort.Value);
            }
            catch (Exception ex) { Error(ex.Message); }
        }

        void LoopbackTest()
        {
            try { Process.Start("mstsc.exe", "/v:127.0.0.2:" + TsSettings.GetPort()); }
            catch (Exception ex) { Error(ex.Message); }
        }

        void RestartService()
        {
            try
            {
                using (var sc = new ServiceController("TermService"))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    }
                    sc.Start();
                }
            }
            catch (Exception ex) { Error(ex.Message); }
        }

        void ManageUsers()
        {
            try { Process.Start("lusrmgr.msc"); }
            catch (Exception ex) { Error(ex.Message); }
        }

        void TailLog()
        {
            try
            {
                var log = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "RDPForge", "forge.log");
                if (!File.Exists(log)) return;
                using (var fs = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs))
                {
                    var text = sr.ReadToEnd();
                    if (text.Length > 8000) text = text.Substring(text.Length - 8000);
                    if (txtLog.Text != text) { txtLog.Text = text; txtLog.SelectionStart = txtLog.Text.Length; txtLog.ScrollToCaret(); }
                }
            }
            catch { }
        }

        static void Warn(string m) =>
            MessageBox.Show(m, "RDPForge", MessageBoxButtons.OK, MessageBoxIcon.Warning);

        static void Error(string m) =>
            MessageBox.Show(m, "RDPForge", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
