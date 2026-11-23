using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("VaultKeep")]
[assembly: System.Reflection.AssemblyProduct("VaultKeep")]
[assembly: System.Reflection.AssemblyVersion("0.1.0.0")]

namespace VaultKeep
{
    internal static class Program
    {
        private const string AppName = "VaultKeep";

        /// <summary>
        /// Usage:
        ///   VaultKeep.exe                       -> install / uninstall the right-click menu
        ///   VaultKeep.exe install | uninstall
        ///   VaultKeep.exe lock   "path"         -> prompt for password, lock file/folder
        ///   VaultKeep.exe open   "path.vkl"     -> prompt for password, open it, re-lock when it's closed
        ///   VaultKeep.exe unlock "path.vkl"     -> prompt for password, unlock permanently
        ///   VaultKeep.exe recover               -> offer to re-lock items left unlocked by a crash
        ///   add --password-stdin to lock/open/unlock to read the password from stdin (no dialogs; for scripts/tests)
        ///   add --no-launch to open to skip launching the item, --guard-seconds N to shorten the late-save watch (tests)
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            bool stdinMode = Array.IndexOf(args, "--password-stdin") >= 0;
            if (!stdinMode)
            {
                try { SetProcessDPIAware(); } catch { }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }

            string command = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            string path = args.Length > 1 ? args[1] : null;

            try
            {
                if (!stdinMode && command != "uninstall")
                    Recovery.PromptForOrphans();

                switch (command)
                {
                    case "open":
                        if (!RequirePath(path)) return 1;
                        return stdinMode ? OpenQuiet(path, Array.IndexOf(args, "--no-launch") < 0, GuardSeconds(args)) : OpenInteractive(path);
                    case "recover":
                        return 0; // orphan check above is all this does (runs at sign-in)
                    case "lock":
                        return RequirePath(path) ? (stdinMode ? LockQuiet(path) : LockInteractive(path)) : 1;
                    case "unlock":
                        return RequirePath(path) ? (stdinMode ? UnlockQuiet(path) : UnlockInteractive(path)) : 1;
                    case "install":
                        Shell.Install();
                        Info("The \"Lock with VaultKeep\" option was added to the right-click menu for files and folders.");
                        return 0;
                    case "uninstall":
                        Shell.Uninstall();
                        Info("VaultKeep was removed from the right-click menu. Your locked .vkl files are not affected.");
                        return 0;
                    case "":
                        return SetupPrompt();
                    default:
                        Error("Unknown command: " + args[0]);
                        return 1;
                }
            }
            catch (Exception ex)
            {
                if (stdinMode) Console.Error.WriteLine(ex.Message);
                else Error(ex.Message);
                return 1;
            }
        }

        // ------------------------------------------------------------ Interactive

        private static int LockInteractive(string path)
        {
            string name = Path.GetFileName(Path.GetFullPath(path).TrimEnd('\\'));
            if (VaultCrypto.IsVaultFile(path))
            {
                Info("\"" + name + "\" is already locked.");
                return 0;
            }
            return LockWithPrompt(path, false) ? 0 : 2;
        }

        /// <summary>Asks for a new password and locks the item. Returns false if the user cancelled.</summary>
        internal static bool LockWithPrompt(string path, bool replaceStale)
        {
            string name = Path.GetFileName(Path.GetFullPath(path).TrimEnd('\\'));
            string password;
            using (var f = new PasswordForm(true, name, null))
            {
                if (f.ShowDialog() != DialogResult.OK) return false;
                password = f.Password;
            }

            LockResult result = null;
            ProgressForm.Run("Locking " + name + "...", delegate { result = VaultCrypto.Lock(path, password, replaceStale); });

            if (result.UndeletedItems.Count > 0)
            {
                Warn("\"" + name + "\" was locked into \"" + Path.GetFileName(result.OutputPath) + "\", but some originals " +
                     "could not be removed (they may be open in another program):\n\n" +
                     string.Join("\n", result.UndeletedItems.ToArray(), 0, Math.Min(10, result.UndeletedItems.Count)) +
                     "\n\nClose them and delete them manually.");
            }
            return true;
        }

        /// <summary>Default double-click action: unlock for use, open it, re-lock when it's closed.</summary>
        private static int OpenInteractive(string path)
        {
            string password;
            string restored = PromptAndUnlock(path, "Opening", out password);
            if (restored == null) return 2;
            Application.Run(new OpenSession(restored, password, true, OpenSession.DefaultGuardSeconds));
            return 0;
        }

        /// <summary>"Unlock permanently": restore the original and stop protecting it.</summary>
        private static int UnlockInteractive(string path)
        {
            string password;
            return PromptAndUnlock(path, "Unlocking", out password) != null ? 0 : 2;
        }

        /// <summary>Asks for the password (retrying on a wrong one) and restores the item in place.</summary>
        /// <returns>Path of the restored item, or null if the user cancelled.</returns>
        private static string PromptAndUnlock(string path, string verb, out string password)
        {
            password = null;
            string name = Path.GetFileName(path);
            if (!VaultCrypto.IsVaultFile(path))
            {
                Error("\"" + name + "\" is not a VaultKeep locked file.");
                return null;
            }

            string error = null;
            while (true)
            {
                string pwd;
                using (var f = new PasswordForm(false, name, error))
                {
                    if (f.ShowDialog() != DialogResult.OK) return null;
                    pwd = f.Password;
                }
                try
                {
                    string restored = null;
                    ProgressForm.Run(verb + " " + name + "...", delegate { restored = VaultCrypto.Unlock(path, pwd); });
                    password = pwd;
                    return restored;
                }
                catch (WrongPasswordException)
                {
                    error = "Wrong password. Try again.";
                }
            }
        }

        private static int SetupPrompt()
        {
            if (Shell.IsInstalled())
            {
                var r = MessageBox.Show(
                    "VaultKeep is in your right-click menu.\n\nDo you want to remove it?\n" +
                    "(Your locked .vkl files stay locked and can be unlocked after reinstalling.)",
                    AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r == DialogResult.Yes) { Shell.Uninstall(); Info("VaultKeep was removed from the right-click menu."); }
            }
            else
            {
                var r = MessageBox.Show(
                    "Add \"Lock with VaultKeep\" to the right-click menu for files and folders?",
                    AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r == DialogResult.Yes)
                {
                    Shell.Install();
                    Info("Done! Right-click any file or folder and choose \"Lock with VaultKeep\".\n\n" +
                         "To use a locked item, double-click its .vkl file and enter the password. It opens normally " +
                         "and locks again automatically when you close it.\n" +
                         "To remove the lock for good, right-click the .vkl file and choose \"Unlock permanently\".\n\n" +
                         "Keep VaultKeep.exe in this folder; if you move it, run it again to update the menu.");
                }
            }
            return 0;
        }

        // ---------------------------------------------------------- Script mode

        private static int LockQuiet(string path)
        {
            string password = Console.In.ReadLine() ?? "";
            if (password.Length < PasswordForm.MinPasswordLength)
            {
                Console.Error.WriteLine("Password must be at least " + PasswordForm.MinPasswordLength + " characters.");
                return 1;
            }
            var result = VaultCrypto.Lock(path, password);
            Console.WriteLine(result.OutputPath);
            foreach (string s in result.UndeletedItems) Console.Error.WriteLine("Could not delete: " + s);
            return result.UndeletedItems.Count == 0 ? 0 : 3;
        }

        private static int OpenQuiet(string path, bool launch, int guardSeconds)
        {
            string password = Console.In.ReadLine() ?? "";
            string restored;
            try { restored = VaultCrypto.Unlock(path, password); }
            catch (WrongPasswordException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 4;
            }
            Console.WriteLine(restored);
            Console.Out.Flush();
            Application.Run(new OpenSession(restored, password, launch, guardSeconds));
            return 0;
        }

        private static int UnlockQuiet(string path)
        {
            string password = Console.In.ReadLine() ?? "";
            try
            {
                Console.WriteLine(VaultCrypto.Unlock(path, password));
                return 0;
            }
            catch (WrongPasswordException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 4;
            }
        }

        // ---------------------------------------------------------------- Misc

        /// <summary>Test option "--guard-seconds N": how long to watch for late saves after re-locking.</summary>
        private static int GuardSeconds(string[] args)
        {
            int i = Array.IndexOf(args, "--guard-seconds");
            int value;
            if (i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out value) && value >= 0) return value;
            return OpenSession.DefaultGuardSeconds;
        }

        private static bool RequirePath(string path)
        {
            if (!string.IsNullOrEmpty(path)) return true;
            Error("No file or folder was given.");
            return false;
        }

        private static void Info(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        private static void Warn(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        private static void Error(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error); }

        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();
    }
}
