using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("VaultKeep")]
[assembly: System.Reflection.AssemblyProduct("VaultKeep")]
[assembly: System.Reflection.AssemblyVersion("0.2.0.0")]

namespace VaultKeep
{
    internal static class Program
    {
        private const string AppName = "VaultKeep";
        private static string[] _args = new string[0];

        /// <summary>
        /// Usage:
        ///   VaultKeep.exe                       -> VaultKeep window: right-click menu + security keys
        ///   VaultKeep.exe install | uninstall
        ///   VaultKeep.exe lock   "path"         -> prompt for password, lock file/folder
        ///   VaultKeep.exe open   "path.vkl"     -> security key or password, open it, re-lock when it's closed
        ///   VaultKeep.exe unlock "path.vkl"     -> security key or password, unlock permanently
        ///   VaultKeep.exe key-create "E:\"      -> make a USB drive a security key (asks first)
        ///   VaultKeep.exe recover               -> offer to re-lock items left unlocked by a crash
        /// Script mode (no dialogs; for scripts/tests):
        ///   --password-stdin    lock/open/unlock read the password from stdin (open/unlock try keys first)
        ///   --quiet             key-create "dir" [--label L] | key-remove ID | key-list
        ///   --key-dir DIR       also look for a key in DIR (repeatable); --no-drive-scan skips real drives
        ///   --no-launch, --guard-seconds N   (open) skip launching the item / shorten the late-save watch
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            _args = args;
            bool quiet = HasFlag("--password-stdin") || HasFlag("--quiet");
            if (!quiet)
            {
                try { SetProcessDPIAware(); } catch { }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }

            string command = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            string path = PathArgument();

            try
            {
                if (!quiet && command != "uninstall")
                    Recovery.PromptForOrphans();

                switch (command)
                {
                    case "open":
                        if (!RequirePath(path)) return 1;
                        return quiet ? OpenQuiet(path, !HasFlag("--no-launch"), GuardSeconds()) : OpenInteractive(path);
                    case "unlock":
                        if (!RequirePath(path)) return 1;
                        return quiet ? UnlockQuiet(path) : UnlockInteractive(path);
                    case "lock":
                        if (!RequirePath(path)) return 1;
                        return quiet ? LockQuiet(path) : LockInteractive(path);
                    case "recover":
                        return 0; // orphan check above is all this does (runs at sign-in)
                    case "key-create":
                        if (!RequirePath(path)) return 1;
                        return quiet ? KeyCreateQuiet(path) : (MainForm.CreateKeyOnDrive(null, path) ? 0 : 2);
                    case "key-remove":
                        if (!RequirePath(path)) return 1;
                        return KeyStore.Unregister(KeyStore.FromHex(path)) ? 0 : 1;
                    case "key-list":
                        foreach (RegisteredKey k in KeyStore.LoadRegistered()) Console.WriteLine(k.IdHex + "\t" + k.Label);
                        return 0;
                    case "install":
                        Shell.Install();
                        Info("The \"Lock with VaultKeep\" option was added to the right-click menu for files and folders.");
                        return 0;
                    case "uninstall":
                        Shell.Uninstall();
                        Info("VaultKeep was removed from the right-click menu. Your locked .vkl files are not affected.");
                        return 0;
                    case "":
                    case "keys":
                        Application.Run(new MainForm());
                        return 0;
                    default:
                        Error("Unknown command: " + args[0]);
                        return 1;
                }
            }
            catch (Exception ex)
            {
                if (quiet) Console.Error.WriteLine(ex.Message);
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
            List<RegisteredKey> registered = RegisteredKeysOrEmpty();
            string note = registered.Count == 0 ? null
                : registered.Count == 1 ? "Your security key \"" + registered[0].Label + "\" will also open it."
                : "Your " + registered.Count + " security keys will also open it.";

            string password;
            using (var f = new PasswordForm(true, name, null, note, null))
            {
                if (f.ShowDialog() != DialogResult.OK) return false;
                password = f.Password;
            }

            LockResult result = null;
            ProgressForm.Run("Locking " + name + "...", delegate
            {
                VaultKeys keys = VaultKeys.CreateNew(password, registered);
                try { result = VaultCrypto.Lock(path, keys, replaceStale); }
                finally { keys.Clear(); }
            });

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
            VaultKeys keys;
            string restored = PromptAndUnlock(path, "Opening", out keys);
            if (restored == null) return 2;
            Application.Run(new OpenSession(restored, keys, true, OpenSession.DefaultGuardSeconds));
            return 0;
        }

        /// <summary>"Unlock permanently": restore the original and stop protecting it.</summary>
        private static int UnlockInteractive(string path)
        {
            VaultKeys keys;
            string restored = PromptAndUnlock(path, "Unlocking", out keys);
            if (keys != null) keys.Clear();
            return restored != null ? 0 : 2;
        }

        /// <summary>
        /// Opens the item with a plugged-in security key if one fits; otherwise asks for the password
        /// (the dialog also notices a key being plugged in while it's open). Restores the item in place.
        /// </summary>
        /// <returns>Path of the restored item, or null if the user cancelled.</returns>
        private static string PromptAndUnlock(string path, string verb, out VaultKeys keys)
        {
            keys = null;
            string name = Path.GetFileName(path);
            if (!VaultCrypto.IsVaultFile(path))
            {
                Error("\"" + name + "\" is not a VaultKeep locked file.");
                return null;
            }

            string error = null;
            bool showKeyHint = RegisteredKeysOrEmpty().Count > 0;
            while (true)
            {
                KeyFile key = VaultCrypto.FindKeyFor(path, FindKeys());
                if (key != null)
                {
                    try
                    {
                        UnlockResult r = null;
                        ProgressForm.Run(verb + " " + name + " with security key \"" + key.Label + "\"...",
                            delegate { r = VaultCrypto.Unlock(path, null, new[] { key }); });
                        keys = r.Keys;
                        return r.Restored;
                    }
                    catch (WrongPasswordException)
                    {
                        error = "The security key didn't open it (the file may be damaged). Try the password.";
                    }
                }

                string pwd;
                using (var f = new PasswordForm(false, name, error,
                    showKeyHint ? "Or plug in your VaultKeep security key." : null,
                    () => VaultCrypto.FindKeyFor(path, FindKeys()) != null))
                {
                    DialogResult answer = f.ShowDialog();
                    if (answer == DialogResult.Yes) { error = null; continue; } // a key was plugged in
                    if (answer != DialogResult.OK) return null;
                    pwd = f.Password;
                }
                try
                {
                    UnlockResult r = null;
                    ProgressForm.Run(verb + " " + name + "...", delegate { r = VaultCrypto.Unlock(path, pwd, null); });
                    // Items from VaultKeep 0.1 have no key slots yet: give them new keys so re-locking upgrades them.
                    keys = r.Keys ?? VaultKeys.CreateNew(pwd, RegisteredKeysOrEmpty());
                    return r.Restored;
                }
                catch (WrongPasswordException)
                {
                    error = "Wrong password. Try again.";
                }
            }
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
            VaultKeys keys = VaultKeys.CreateNew(password, KeyStore.LoadRegistered());
            LockResult result;
            try { result = VaultCrypto.Lock(path, keys, false); }
            finally { keys.Clear(); }
            Console.WriteLine(result.OutputPath);
            foreach (string s in result.UndeletedItems) Console.Error.WriteLine("Could not delete: " + s);
            return result.UndeletedItems.Count == 0 ? 0 : 3;
        }

        /// <summary>Unlocks with a fitting key if one is found, else with the password from stdin.</summary>
        private static UnlockResult UnlockQuietCore(string path, out int exitCode)
        {
            exitCode = 0;
            KeyFile key = VaultCrypto.FindKeyFor(path, FindKeys());
            try
            {
                if (key != null)
                    return VaultCrypto.Unlock(path, null, new[] { key });
                string password = Console.In.ReadLine() ?? "";
                UnlockResult r = VaultCrypto.Unlock(path, password, null);
                if (r.Keys == null) r.Keys = VaultKeys.CreateNew(password, KeyStore.LoadRegistered());
                return r;
            }
            catch (WrongPasswordException ex)
            {
                Console.Error.WriteLine(ex.Message);
                exitCode = 4;
                return null;
            }
        }

        private static int OpenQuiet(string path, bool launch, int guardSeconds)
        {
            int code;
            UnlockResult r = UnlockQuietCore(path, out code);
            if (r == null) return code;
            Console.WriteLine(r.Restored + (r.UsedKey != null ? "\tkey" : "\tpassword"));
            Console.Out.Flush();
            Application.Run(new OpenSession(r.Restored, r.Keys, launch, guardSeconds));
            return 0;
        }

        private static int UnlockQuiet(string path)
        {
            int code;
            UnlockResult r = UnlockQuietCore(path, out code);
            if (r == null) return code;
            Console.WriteLine(r.Restored + (r.UsedKey != null ? "\tkey" : "\tpassword"));
            if (r.Keys != null) r.Keys.Clear();
            return 0;
        }

        private static int KeyCreateQuiet(string root)
        {
            string label = OptionValue("--label") ?? "Test key";
            KeyFile key = KeyStore.CreateKey(root, label);
            Console.WriteLine(key.IdHex);
            return 0;
        }

        // ---------------------------------------------------------------- Misc

        /// <summary>Keys on plugged-in drives, plus --key-dir folders (tests).</summary>
        internal static List<KeyFile> FindKeys()
        {
            var extra = new List<string>();
            for (int i = 0; i < _args.Length - 1; i++)
                if (_args[i] == "--key-dir") extra.Add(_args[i + 1]);
            return KeyStore.FindKeyFiles(extra, !HasFlag("--no-drive-scan"));
        }

        internal static List<RegisteredKey> RegisteredKeysOrEmpty()
        {
            try { return KeyStore.LoadRegistered(); }
            catch { return new List<RegisteredKey>(); }
        }

        private static readonly string[] OptionsWithValue = { "--label", "--key-dir", "--guard-seconds" };

        /// <summary>
        /// The first argument after the command that isn't an option, cleaned up. Explorer passes a drive as
        /// "E:\" and Windows reads the closing \" as an escaped quote, so the program receives E:" (and would
        /// swallow any following arguments into it). Stray quotes are removed and a bare "E:" becomes "E:\".
        /// </summary>
        private static string PathArgument()
        {
            for (int i = 1; i < _args.Length; i++)
            {
                if (Array.IndexOf(OptionsWithValue, _args[i]) >= 0) { i++; continue; }
                if (_args[i].StartsWith("--")) continue;
                return NormalizePath(_args[i]);
            }
            return null;
        }

        internal static string NormalizePath(string raw)
        {
            if (raw == null) return null;
            string p = raw.Replace("\"", "").Trim();
            if (p.Length == 2 && p[1] == ':') p += "\\";
            return p.Length == 0 ? null : p;
        }

        private static bool HasFlag(string flag)
        {
            return Array.IndexOf(_args, flag) >= 0;
        }

        private static string OptionValue(string name)
        {
            int i = Array.IndexOf(_args, name);
            return i >= 0 && i + 1 < _args.Length ? _args[i + 1] : null;
        }

        /// <summary>Test option "--guard-seconds N": how long to watch for late saves after re-locking.</summary>
        private static int GuardSeconds()
        {
            int value;
            if (int.TryParse(OptionValue("--guard-seconds"), out value) && value >= 0) return value;
            return OpenSession.DefaultGuardSeconds;
        }

        private static bool RequirePath(string path)
        {
            if (!string.IsNullOrEmpty(path)) return true;
            Error("No file or folder was given.");
            return false;
        }

        internal static void Info(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        internal static void Warn(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        internal static void Error(string msg) { MessageBox.Show(msg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error); }

        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();
    }
}
