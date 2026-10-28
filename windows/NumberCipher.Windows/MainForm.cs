using System.Diagnostics;
using System.Reflection;
using NumberCipher.Core;

namespace NumberCipher.Windows;

/// <summary>Main window — mirrors the Mac app: Encrypt/Decrypt, passphrase + confirm, strength meter,
/// a progress bar during the ~10 s key strengthening, and a clipboard copy that stays out of
/// Windows clipboard history and clears itself after 60 seconds.</summary>
internal sealed class MainForm : Form
{
    private static readonly Font Mono = new("Consolas", 11f);
    private static readonly Color ErrorColor = Color.FromArgb(196, 43, 28);
    private static readonly Color GoodColor = Color.FromArgb(16, 124, 16);
    private static readonly Color FairColor = Color.FromArgb(202, 80, 16);

    private readonly RadioButton encryptMode = new() { Text = "Encrypt", Checked = true, AutoSize = true };
    private readonly RadioButton decryptMode = new() { Text = "Decrypt", AutoSize = true };
    private readonly Label inputLabel = Heading("Numbers to encrypt");
    private readonly TextBox input = new()
    {
        Multiline = true, AcceptsReturn = true, ScrollBars = ScrollBars.Vertical,
        Font = Mono, Dock = DockStyle.Fill, MinimumSize = new Size(0, 90),
    };
    private readonly TextBox passphrase = new() { UseSystemPasswordChar = true, PlaceholderText = "Passphrase", Dock = DockStyle.Fill };
    private readonly TextBox confirm = new() { UseSystemPasswordChar = true, PlaceholderText = "Confirm passphrase", Dock = DockStyle.Fill };
    private readonly ProgressBar strengthBar = new() { Maximum = 100, Width = 140, Height = 12, Margin = new Padding(0, 4, 8, 0) };
    private readonly Label strengthLabel = new() { AutoSize = true, Text = "Passphrase strength", ForeColor = SystemColors.GrayText };
    private readonly Label mismatchLabel = new() { AutoSize = true, Text = "Passphrases don't match", ForeColor = ErrorColor, Visible = false, Margin = new Padding(16, 0, 0, 0) };
    private readonly FlowLayoutPanel strengthRow = new() { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };

    private readonly Button runButton = new() { Text = "Encrypt", AutoSize = true, MinimumSize = new Size(110, 32) };
    private readonly Button clearButton = new() { Text = "Clear All", AutoSize = true, MinimumSize = new Size(90, 32) };

    private readonly ProgressBar workBar = new() { Maximum = 1000, Dock = DockStyle.Fill, Height = 14 };
    private readonly Label workLabel = new() { AutoSize = true, ForeColor = SystemColors.GrayText };
    private readonly TableLayoutPanel workPanel = new() { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 1, Visible = false };

    private readonly Label errorLabel = new() { AutoSize = true, ForeColor = ErrorColor, Visible = false, MaximumSize = new Size(560, 0) };

    private readonly Label outputLabel = Heading("Letter code");
    private readonly Button copyButton = new() { Text = "Copy", AutoSize = true, MinimumSize = new Size(90, 30), Anchor = AnchorStyles.Right };
    private readonly TextBox output = new()
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        Font = Mono, Dock = DockStyle.Fill, MinimumSize = new Size(0, 80), BackColor = SystemColors.Window,
    };
    private readonly TableLayoutPanel outputPanel = new() { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Visible = false };

    private readonly System.Windows.Forms.Timer progressTimer = new() { Interval = 200 };
    private readonly System.Windows.Forms.Timer clipboardTimer = new() { Interval = 60_000 };

    private bool busy;
    private Stopwatch? workClock;
    private double estimate;
    private string? copiedText;

    public MainForm()
    {
        string version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "";
        Text = $"Number Cipher {version}".Trim();
        Font = SystemFonts.MessageBoxFont ?? Font;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(600, 660);
        MinimumSize = new Size(520, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = SystemColors.Control;

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(18), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var modeRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, 0, 0, 8) };
        modeRow.Controls.AddRange([encryptMode, decryptMode]);

        strengthRow.Controls.AddRange([strengthBar, strengthLabel, mismatchLabel]);

        var buttonRow = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 2, Margin = new Padding(0, 8, 0, 8) };
        buttonRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        buttonRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        clearButton.Anchor = AnchorStyles.Right;
        buttonRow.Controls.Add(runButton, 0, 0);
        buttonRow.Controls.Add(clearButton, 1, 0);

        workPanel.Controls.Add(workBar);
        workPanel.Controls.Add(workLabel);

        outputPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        outputPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        outputPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        outputPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outputPanel.Controls.Add(outputLabel, 0, 0);
        outputPanel.Controls.Add(copyButton, 1, 0);
        outputPanel.Controls.Add(output, 0, 1);
        outputPanel.SetColumnSpan(output, 2);

        var footer = new Label
        {
            AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 10, 0, 0),
            Text = "AES-256-GCM · PBKDF2-SHA256 tuned to ~10 s on this PC · every encryption is unique",
        };

        // Rows: mode, label, input(%), pass, confirm, strength, buttons, work, error, output(%), footer
        Control[] rows = [modeRow, inputLabel, input, passphrase, confirm, strengthRow, buttonRow, workPanel, errorLabel, outputPanel, footer];
        foreach (Control row in rows)
        {
            bool grows = row == input || row == outputPanel;
            layout.RowStyles.Add(grows ? new RowStyle(SizeType.Percent, 50) : new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(row);
        }
        passphrase.Margin = confirm.Margin = new Padding(0, 6, 0, 0);
        Controls.Add(layout);

        encryptMode.CheckedChanged += (_, _) => { if (encryptMode.Checked) ModeChanged(); };
        decryptMode.CheckedChanged += (_, _) => { if (decryptMode.Checked) ModeChanged(); };
        input.TextChanged += (_, _) => UpdateState();
        passphrase.TextChanged += (_, _) => UpdateState();
        confirm.TextChanged += (_, _) => UpdateState();
        runButton.Click += (_, _) => Run();
        clearButton.Click += (_, _) => ClearAll();
        copyButton.Click += (_, _) => CopyOutput();
        progressTimer.Tick += (_, _) => UpdateProgress();
        clipboardTimer.Tick += (_, _) => ClearClipboardIfUnchanged();

        AcceptButton = null; // Enter makes new lines in the numbers box; Ctrl+Enter runs.
        UpdateState();
    }

    private static Label Heading(string text) => new()
    {
        Text = text, AutoSize = true, Margin = new Padding(0, 4, 0, 4),
        Font = new Font(SystemFonts.MessageBoxFont ?? SystemFonts.DefaultFont, FontStyle.Bold),
    };

    private bool IsEncrypt => encryptMode.Checked;

    private bool CanRun =>
        !busy
        && input.Text.Trim().Length > 0
        && passphrase.Text.Length > 0
        && (!IsEncrypt || passphrase.Text == confirm.Text);

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.Enter))
        {
            if (CanRun) Run();
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    private void ModeChanged()
    {
        ClearAll();
        inputLabel.Text = IsEncrypt ? "Numbers to encrypt" : "Letter code to decrypt";
        outputLabel.Text = IsEncrypt ? "Letter code" : "Numbers";
        runButton.Text = IsEncrypt ? "Encrypt" : "Decrypt";
        confirm.Visible = strengthRow.Visible = IsEncrypt;
        UpdateState();
    }

    private void UpdateState()
    {
        runButton.Enabled = CanRun;
        bool mismatch = IsEncrypt && confirm.Text.Length > 0 && confirm.Text != passphrase.Text;
        mismatchLabel.Visible = mismatch;

        double bits = CipherEngine.StrengthBits(passphrase.Text);
        strengthBar.Value = (int)Math.Min(bits, 100);
        if (passphrase.Text.Length == 0)
        {
            strengthLabel.Text = "Passphrase strength";
            strengthLabel.ForeColor = SystemColors.GrayText;
        }
        else
        {
            (strengthLabel.Text, strengthLabel.ForeColor) = bits switch
            {
                < 40 => ("Weak — use a longer passphrase", ErrorColor),
                < 60 => ("Fair", FairColor),
                < 80 => ("Strong", GoodColor),
                _ => ("Very strong", GoodColor),
            };
        }
    }

    private async void Run()
    {
        if (!CanRun) return;
        bool encrypt = IsEncrypt;
        string text = input.Text;
        string pw = passphrase.Text;

        busy = true;
        SetInputsEnabled(false);
        errorLabel.Visible = false;
        outputPanel.Visible = false;
        output.Text = "";
        ResetCopyButton();
        workBar.Value = 0;
        workLabel.Text = "Measuring this PC's speed…";
        workPanel.Visible = true;

        try
        {
            estimate = await Task.Run(() => encrypt ? CipherEngine.TargetSeconds : CipherEngine.EstimatedSeconds(text) ?? 0);
            workClock = Stopwatch.StartNew();
            UpdateProgress();
            progressTimer.Start();

            string result = await Task.Run(() => encrypt ? CipherEngine.Encrypt(text, pw) : CipherEngine.Decrypt(text, pw));
            output.Text = encrypt ? result : result.Replace("\n", "\r\n");
            outputPanel.Visible = true;
        }
        catch (CipherException e)
        {
            ShowError(e.Message);
        }
        catch (Exception)
        {
            ShowError("Something went wrong inside the encryption engine.");
        }
        finally
        {
            progressTimer.Stop();
            workPanel.Visible = false;
            busy = false;
            SetInputsEnabled(true);
            UpdateState();
        }
    }

    private void UpdateProgress()
    {
        if (workClock is null || estimate <= 0) return;
        double elapsed = workClock.Elapsed.TotalSeconds;
        workBar.Value = (int)(Math.Min(elapsed / estimate, 1) * workBar.Maximum);
        int remaining = (int)Math.Ceiling(estimate - elapsed);
        workLabel.Text = remaining > 0 ? $"Strengthening key — about {remaining} s left" : "Finishing…";
    }

    private void SetInputsEnabled(bool enabled)
    {
        encryptMode.Enabled = decryptMode.Enabled = enabled;
        input.ReadOnly = !enabled;
        passphrase.Enabled = confirm.Enabled = clearButton.Enabled = enabled;
    }

    private void ShowError(string message)
    {
        errorLabel.Text = "⚠ " + message;
        errorLabel.Visible = true;
    }

    private void CopyOutput()
    {
        try
        {
            var data = new DataObject();
            data.SetText(output.Text);
            // Keep the code out of Windows clipboard history, cloud clipboard sync and clipboard monitors.
            data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[4]));
            data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
            Clipboard.SetDataObject(data, copy: true, retryTimes: 5, retryDelay: 100);
            copiedText = output.Text;
            copyButton.Text = "Copied — clears in 60s";
            clipboardTimer.Stop();
            clipboardTimer.Start();
        }
        catch (Exception)
        {
            ShowError("Couldn't access the clipboard. Select the text and press Ctrl+C instead.");
        }
    }

    private void ClearClipboardIfUnchanged()
    {
        clipboardTimer.Stop();
        try
        {
            if (copiedText is not null && Clipboard.ContainsText() && Clipboard.GetText() == copiedText)
                Clipboard.Clear();
        }
        catch (Exception) { /* clipboard busy; nothing else to do */ }
        copiedText = null;
        ResetCopyButton();
    }

    private void ResetCopyButton() => copyButton.Text = "Copy";

    private void ClearAll()
    {
        input.Text = passphrase.Text = confirm.Text = output.Text = "";
        errorLabel.Visible = false;
        outputPanel.Visible = false;
        ResetCopyButton();
        UpdateState();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        // Don't leave a copied code on the clipboard after the app closes.
        if (copiedText is not null) ClearClipboardIfUnchanged();
        base.OnFormClosed(e);
    }
}
