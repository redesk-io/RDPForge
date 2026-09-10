using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace RDPForge
{
    public class MainForm : Form
    {
        readonly Label lblWrapper = new Label { Left = 12, Top = 12, Width = 460 };
        readonly Label lblService = new Label { Left = 12, Top = 36, Width = 460 };
        readonly Label lblListener = new Label { Left = 12, Top = 60, Width = 460 };
        readonly Label lblVersion = new Label { Left = 12, Top = 84, Width = 460 };
        readonly CheckBox chkConnections = new CheckBox { Left = 12, Top = 120, Width = 300, Text = "Allow RDP connections" };
        readonly CheckBox chkSingleSession = new CheckBox { Left = 12, Top = 146, Width = 300, Text = "Single session per user" };
        readonly Button btnApply = new Button { Left = 12, Top = 176, Width = 120, Text = "Apply" };
        readonly Button btnTest = new Button { Left = 140, Top = 176, Width = 160, Text = "Test 127.0.0.2" };
        readonly Timer timer = new Timer { Interval = 1000 };

        public MainForm()
        {
            Text = "RDPForge Manager";
            Width = 500;
            Height = 260;
            Controls.AddRange(new Control[] {
                lblWrapper, lblService, lblListener, lblVersion,
                chkConnections, chkSingleSession, btnApply, btnTest });
            btnApply.Click += (s, e) => ApplySettings();
            btnTest.Click += (s, e) => LoopbackTest();
            timer.Tick += (s, e) => RefreshDiagnostics();
            timer.Start();
            RefreshDiagnostics();
            LoadSettings();
        }

        void RefreshDiagnostics()
        {
            lblWrapper.Text = "Wrapper: " + SystemState.GetWrapperState();
            lblService.Text = "TermService: " + SystemState.GetServiceState();
            lblListener.Text = "RDP-Tcp listener: " +
                (SystemState.IsListenerActive() ? "active" : "absent");
            lblVersion.Text = "termsrv.dll: " + SystemState.GetTermsrvVersion();
        }

        void LoadSettings()
        {
            try
            {
                chkConnections.Checked = TsSettings.GetAllowConnections();
                chkSingleSession.Checked = TsSettings.GetSingleSessionPerUser();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "RDPForge", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        void ApplySettings()
        {
            try
            {
                TsSettings.SetAllowConnections(chkConnections.Checked);
                TsSettings.SetSingleSessionPerUser(chkSingleSession.Checked);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "RDPForge", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void LoopbackTest()
        {
            try
            {
                Process.Start("mstsc.exe", "/v:127.0.0.2:" + TsSettings.GetPort());
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "RDPForge", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
