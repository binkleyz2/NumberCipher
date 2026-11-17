using System.Diagnostics;
using System.Text;
using NumberCipher.Core;

namespace NumberCipher.Windows;

/// <summary>Compact dialog launched from the File Explorer context menu via --encrypt / --decrypt args.</summary>
internal sealed class FileOperationForm : Form
{
    private static readonly Color ErrorColor = Color.FromArgb(196, 43, 28);
    private static readonly Color GoodColor = Color.FromArgb(16, 124, 16);

    private readonly string filePath;
    private readonly bool isDecrypt;

    private readonly Label fileLabel = new() { AutoSize = true, Margin = new Padding(0, 0, 0, 6), MaximumSize = new Size(500, 0) };
    private readonly TextBox passphrase = new() { UseSystemPasswordChar = true, PlaceholderText = "Passphrase", Dock = DockStyle.Fill };
    private readonly TextBox confirm = new() { UseSystemPasswordChar = true, PlaceholderText = "Confirm passphrase", Dock = DockStyle.Fill };
    private readonly ProgressBar strengthBar = new() { Maximum = 100, Width = 140, Height = 12, Margin = new Padding(0, 4, 8, 0) };
    private readonly Label strengthLabel = new() { AutoSize = true, Text = "Passphrase strength", ForeColor = SystemColors.GrayText };
    private readonly Button runButton = new() { AutoSize = true, MinimumSize = new Size(100, 32), FlatStyle = FlatStyle.System };
    private readonly Button cancelButton = new() { Text = "Cancel", AutoSize = true, MinimumSize = new Size(90, 32), FlatStyle = FlatStyle.System };
    private readonly ProgressBar workBar = new() { Maximum = 1000, Dock = DockStyle.Fill, Height = 14 };
    private readonly Label workLabel = new() { AutoSize = true, ForeColor = SystemColors.GrayText };
    private readonly TableLayoutPanel workPanel = new() { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 1, Visible = false };
    private readonly Label resultLabel = new() { AutoSize = true, Visible = false, MaximumSize = new Size(500, 0) };
    private readonly Button deleteButton = new()
    {
        Text = "Securely delete original…", AutoSize = true, MinimumSize = new Size(190, 28),
        FlatStyle = FlatStyle.System, Visible = false, Margin = new Padding(0, 4, 0, 0),
    };

    private bool busy;
    private Stopwatch? workClock;
    private double estimate;
    private readonly System.Windows.Forms.Timer progressTimer = new() { Interval = 200 };

    public FileOperationForm(string filePath, bool decrypt)
    {
        this.filePath = filePath;
        this.isDecrypt = decrypt;

        Text = decrypt ? "Decrypt File — Cipherwords" : "Encrypt File — Cipherwords";
        Font = SystemFonts.MessageBoxFont ?? Font;
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = SystemColors.Control;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;

        fileLabel.Text = $"{(decrypt ? "Decrypt" : "Encrypt")}: {Path.GetFileName(filePath)}";
        runButton.Text = decrypt ? "Decrypt" : "Encrypt";

        var layout = new TableLayoutPanel
        {
            ColumnCount = 1,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(16),
            MinimumSize = new Size(420, 0),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var strengthRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Visible = !decrypt };
        strengthRow.Controls.AddRange([strengthBar, strengthLabel]);

        var buttonRow = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 8, 0, 0),
        };
        buttonRow.Controls.Add(cancelButton);
        buttonRow.Controls.Add(runButton);

        workPanel.Controls.Add(workBar);
        workPanel.Controls.Add(workLabel);

        Control[] rows = isDecrypt
            ? [fileLabel, passphrase, workPanel, resultLabel, buttonRow]
            : [fileLabel, passphrase, confirm, strengthRow, workPanel, resultLabel, deleteButton, buttonRow];

        foreach (Control row in rows)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(row);
        }
        passphrase.Margin = new Padding(0, 8, 0, 0);
        Controls.Add(layout);

        passphrase.TextChanged += (_, _) => UpdateState();
        confirm.TextChanged += (_, _) => UpdateState();
        runButton.Click += (_, _) => Run();
        cancelButton.Click += (_, _) => { if (!busy) Close(); };
        progressTimer.Tick += (_, _) => UpdateProgress();
        deleteButton.Click += (_, _) => SecureDelete();

        AcceptButton = runButton;
        UpdateState();
    }

    private bool CanRun =>
        !busy && passphrase.Text.Length > 0
        && (isDecrypt || passphrase.Text == confirm.Text);

    private void UpdateState()
    {
        runButton.Enabled = CanRun;
        if (!isDecrypt)
        {
            double bits = CipherEngine.StrengthBits(passphrase.Text);
            strengthBar.Value = (int)Math.Min(bits, 100);
            (strengthLabel.Text, strengthLabel.ForeColor) = passphrase.Text.Length == 0
                ? ("Passphrase strength", SystemColors.GrayText)
                : bits < 40  ? ("Weak — use a longer passphrase", Color.FromArgb(196, 43, 28))
                : bits < 60  ? ("Fair", Color.FromArgb(202, 80, 16))
                : bits < 80  ? ("Strong", Color.FromArgb(16, 124, 16))
                             : ("Very strong", Color.FromArgb(16, 124, 16));
        }
    }

    private async void Run()
    {
        if (!CanRun) return;
        string pw = passphrase.Text;

        busy = true;
        runButton.Enabled = false;
        cancelButton.Enabled = false;
        passphrase.ReadOnly = confirm.ReadOnly = true;
        resultLabel.Visible = false;
        workLabel.Text = isDecrypt ? "Measuring this PC's speed…" : "Encrypting…";
        workPanel.Visible = true;

        try
        {
            byte[] fileBytes = await Task.Run(() => File.ReadAllBytes(filePath));
            if (isDecrypt)
            {
                string code = new UTF8Encoding(false).GetString(fileBytes);
                estimate = await Task.Run(() => CipherEngine.EstimatedSeconds(code) ?? 0);
                workClock = Stopwatch.StartNew();
                UpdateProgress();
                progressTimer.Start();
                byte[] result = await Task.Run(() => CipherEngine.DecryptFile(code, pw));
                string outPath = GetDecryptOutputPath(filePath);
                await Task.Run(() => File.WriteAllBytes(outPath, result));
                ShowResult($"Saved: {Path.GetFileName(outPath)}", error: false);
            }
            else
            {
                estimate = CipherEngine.TargetSeconds;
                workClock = Stopwatch.StartNew();
                UpdateProgress();
                progressTimer.Start();
                string code = await Task.Run(() => CipherEngine.EncryptFile(fileBytes, pw));
                string outPath = GetEncryptOutputPath(filePath);
                await Task.Run(() => File.WriteAllText(outPath, code, new UTF8Encoding(false)));
                ShowResult($"Saved: {Path.GetFileName(outPath)}", error: false);
                deleteButton.Visible = true;
            }
        }
        catch (CipherException ex) { ShowResult(ex.Message, error: true); }
        catch (IOException ex) { ShowResult($"File error: {ex.Message}", error: true); }
        catch { ShowResult("Something went wrong.", error: true); }
        finally
        {
            progressTimer.Stop();
            workPanel.Visible = false;
            busy = false;
            cancelButton.Text = "Close";
            cancelButton.Enabled = true;
        }
    }

    private void ShowResult(string message, bool error)
    {
        resultLabel.Text = error ? "⚠ " + message : "✓ " + message;
        resultLabel.ForeColor = error ? Color.FromArgb(196, 43, 28) : Color.FromArgb(16, 124, 16);
        resultLabel.Visible = true;
    }

    private void UpdateProgress()
    {
        if (workClock is null || estimate <= 0) return;
        double elapsed = workClock.Elapsed.TotalSeconds;
        workBar.Value = (int)(Math.Min(elapsed / estimate, 1) * workBar.Maximum);
        int remaining = (int)Math.Ceiling(estimate - elapsed);
        workLabel.Text = remaining > 1 ? $"Strengthening key — about {remaining} s left" : "Finishing…";
    }

    private async void SecureDelete()
    {
        string name = Path.GetFileName(filePath);
        var confirm = MessageBox.Show(
            $"Overwrite \"{name}\" with random data, then delete it?\n\n" +
            "Note: on SSDs or cloud-synced folders the original data may still be recoverable " +
            "even after overwriting.",
            "Securely delete original",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        deleteButton.Enabled = false;
        try
        {
            await Task.Run(() =>
            {
                long size = new FileInfo(filePath).Length;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    byte[] buf = new byte[Math.Min(65536, (int)Math.Max(size, 1))];
                    long remaining = size;
                    while (remaining > 0)
                    {
                        int chunk = (int)Math.Min(buf.Length, remaining);
                        System.Security.Cryptography.RandomNumberGenerator.Fill(buf.AsSpan(0, chunk));
                        fs.Write(buf, 0, chunk);
                        remaining -= chunk;
                    }
                    fs.Flush();
                }
                File.Delete(filePath);
            });
            deleteButton.Text = "✓ Deleted";
        }
        catch (Exception ex)
        {
            deleteButton.Enabled = true;
            ShowResult($"Could not delete: {ex.Message}", error: true);
        }
    }

    private static string GetEncryptOutputPath(string sourcePath)
    {
        string candidate = sourcePath + ".cipherwords";
        if (!File.Exists(candidate)) return candidate;
        for (int i = 2; ; i++)
        {
            candidate = $"{sourcePath} ({i}).cipherwords";
            if (!File.Exists(candidate)) return candidate;
        }
    }

    private static string GetDecryptOutputPath(string sourcePath)
    {
        string basePath = sourcePath.EndsWith(".cipherwords", StringComparison.OrdinalIgnoreCase)
            ? sourcePath[..^".cipherwords".Length]
            : sourcePath + ".decrypted";
        if (!File.Exists(basePath)) return basePath;
        string dir = Path.GetDirectoryName(basePath) ?? "";
        string nameNoExt = Path.GetFileNameWithoutExtension(basePath);
        string ext = Path.GetExtension(basePath);
        for (int i = 2; ; i++)
        {
            string candidate = Path.Combine(dir, $"{nameNoExt} ({i}){ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        progressTimer.Dispose();
        base.OnFormClosed(e);
    }
}
