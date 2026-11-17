using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace NumberCipher.Windows;

/// <summary>Registers and unregisters the "Encrypt with Cipherwords" context-menu verb and
/// the .cipherwords file-type association, all under HKCU (no admin rights needed).</summary>
internal static class ShellRegistration
{
    private static readonly string[] Extensions =
    [
        // Plain text / markup
        ".txt", ".md", ".log", ".eml",
        // Rich documents
        ".rtf", ".doc", ".docx", ".odt",
        // PDF
        ".pdf",
        // Spreadsheets (Excel + Google Sheets exports)
        ".xls", ".xlsx", ".xlsm", ".ods", ".csv", ".tsv",
        // Presentations
        ".ppt", ".pptx", ".odp",
        // Data / web
        ".json", ".xml", ".yaml", ".yml", ".html", ".htm",
    ];

    private const string ProgId = "Cipherwords.EncryptedFile";
    private const string VerbName = "Encrypt with Cipherwords";
    private const string VerbKey = @"shell\Encrypt with Cipherwords\command";

    public static bool IsRegistered()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Classes\.cipherwords");
        return key != null;
    }

    public static void Register()
    {
        string exe = Environment.ProcessPath
            ?? System.Reflection.Assembly.GetExecutingAssembly().Location;

        // .cipherwords association → open with app to decrypt
        using (var cwKey = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.cipherwords"))
        {
            cwKey.SetValue("", ProgId);
            cwKey.SetValue("Content Type", "application/octet-stream");
        }
        using (var prog = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}"))
        {
            prog.SetValue("", "Cipherwords Encrypted File");
            using var open = prog.CreateSubKey(@"shell\open\command");
            open.SetValue("", $"\"{exe}\" --decrypt \"%1\"");
        }
        using (var icon = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}\DefaultIcon"))
        {
            icon.SetValue("", $"\"{exe}\",0");
        }

        // "Encrypt with Cipherwords" verb on each supported extension
        foreach (string ext in Extensions)
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ext}\{VerbKey}");
            key.SetValue("", $"\"{exe}\" --encrypt \"%1\"");
        }

        NotifyShell();
    }

    public static void Unregister()
    {
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\.cipherwords", throwOnMissingSubKey: false);
        Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{ProgId}", throwOnMissingSubKey: false);
        foreach (string ext in Extensions)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(
                    $@"Software\Classes\{ext}\shell\{VerbName}",
                    throwOnMissingSubKey: false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        NotifyShell();
    }

    [DllImport("shell32.dll", SetLastError = false)]
    private static extern void SHChangeNotify(uint wEventId, uint uFlags, nint dwItem1, nint dwItem2);

    private static void NotifyShell() => SHChangeNotify(0x08000000, 0, nint.Zero, nint.Zero);
}
