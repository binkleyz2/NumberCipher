namespace NumberCipher.Windows;
internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length == 2 && args[0] is "--encrypt" or "--decrypt" && File.Exists(args[1]))
        {
            Application.Run(new FileOperationForm(args[1], decrypt: args[0] == "--decrypt"));
            return;
        }
        Application.Run(new MainForm());
    }
}
