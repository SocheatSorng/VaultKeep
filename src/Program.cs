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
                    case "key-pin":
                        // Script mode: set/change the PIN of the key on drive/folder <path>. stdin: current PIN
                        // (ignored if the key has none), new PIN. Needs the current PIN, so no sign-in is required.
                        if (!RequirePath(path)) return 1;
                        if (!quiet) { Application.Run(new MainForm()); return 0; }
                        {
                            string current = Console.In.ReadLine();
                            string next = Console.In.ReadLine();
                            if (KeyStore.ChangePin(KeyStore.KeyFilePath(path), current, next)) return 0;
                            Console.Error.WriteLine("The current PIN is wrong.");
                            return 4;
                        }
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
            return LockWithPrompt(path, false, null) ? 0 : 2;
        }

        /// <summary>Asks for a new password and locks the item. Returns false if the user cancelled.</summary>
        /// <param name="outputPath">The .vkl to write (null: next to the item).</param>
        internal static bool LockWithPrompt(string path, bool replaceStale, string outputPath)
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
                try { result = VaultCrypto.Lock(path, keys, replaceStale, outputPath); }
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

        /// <summary>
        /// Default double-click action: decrypt into VaultKeep's private workspace (the .vkl stays where it is,
        /// so sync apps never see an unlocked copy), open it, and write it back into the .vkl once it's closed.
        /// </summary>
        private static int OpenInteractive(string path)
        {
            string openCopy = Recovery.FindOpenCopy(path);
            if (openCopy != null)
            {
                // Already open: show the same copy again rather than making a second one whose
                // re-lock could overwrite the first one's edits.
                if (!Directory.Exists(openCopy) || !ExplorerWindows.NavigateFrom(Path.GetDirectoryName(Path.GetFullPath(path)), openCopy))
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(openCopy) { UseShellExecute = true });
                return 0;
            }

            string sessionDir = Workspace.CreateSessionDir();
            VaultKeys keys;
            string restored;
            try { restored = PromptAndUnlock(path, "Opening", out keys, sessionDir, false); }
            catch { Workspace.DeleteSessionDir(sessionDir); throw; }
            if (restored == null) { Workspace.DeleteSessionDir(sessionDir); return 2; }
            Application.Run(new OpenSession(restored, path, keys, true, OpenSession.DefaultGuardSeconds));
            return 0;
        }

        /// <summary>"Unlock permanently": restore the original next to the .vkl and stop protecting it.</summary>
        private static int UnlockInteractive(string path)
        {
            if (Recovery.FindOpenCopy(path) != null)
            {
                Info("\"" + Path.GetFileName(path) + "\" is open right now. Close it first; once it has locked again, " +
                     "you can unlock it permanently.");
                return 2;
            }
            VaultKeys keys;
            string restored = PromptAndUnlock(path, "Unlocking", out keys, null, true);
            if (keys != null) keys.Clear();
            return restored != null ? 0 : 2;
        }

        /// <summary>
        /// Opens the item with a plugged-in security key if one fits; otherwise asks for the password
        /// (the dialog also notices a key being plugged in while it's open).
        /// </summary>
        /// <param name="restoreDir">Where to restore (null: next to the .vkl).</param>
        /// <param name="deleteVkl">Delete the .vkl afterwards (permanent unlock only).</param>
        /// <returns>Path of the restored item, or null if the user cancelled.</returns>
        private static string PromptAndUnlock(string path, string verb, out VaultKeys keys, string restoreDir, bool deleteVkl)
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
            var failedKeys = new List<string>();
            Func<List<KeyFile>> usableKeys = () => FindKeys().FindAll(k => !failedKeys.Contains(k.IdHex + "|" + k.Path));
            while (true)
            {
                KeyFile key = VaultCrypto.FindKeyFor(path, usableKeys());
                if (key != null && !UnlockKeyWithPin(key))
                {
                    // PIN cancelled: don't ask again for this key; use the item password instead.
                    failedKeys.Add(key.IdHex + "|" + key.Path);
                    showKeyHint = false;
                    key = null;
                }
                if (key != null)
                {
                    try
                    {
                        UnlockResult r = null;
                        ProgressForm.Run(verb + " " + name + " with security key \"" + key.Label + "\"...",
                            delegate { r = VaultCrypto.Unlock(path, null, new[] { key }, restoreDir, deleteVkl); });
                        keys = r.Keys;
                        return r.Restored;
                    }
                    catch (Exception ex)
                    {
                        // A key with a matching ID that doesn't work (damaged, or a fake copying the ID) must
                        // never stop the owner from using the password.
                        if (!(ex is WrongPasswordException) && !(ex is NeedPasswordException)) throw;
                        error = "The security key \"" + key.Label + "\" didn't open it. Use the password.";
                        showKeyHint = false;
                        failedKeys.Add(key.IdHex + "|" + key.Path);
                    }
                }

                string pwd;
                // Watch for a (not yet tried) key being plugged in while the dialog is open.
                using (var f = new PasswordForm(false, name, error,
                    showKeyHint ? "Or plug in your VaultKeep security key." : null,
                    () => VaultCrypto.FindKeyFor(path, usableKeys()) != null))
                {
                    DialogResult answer = f.ShowDialog();
                    if (answer == DialogResult.Yes) { error = null; continue; } // a key was plugged in
                    if (answer != DialogResult.OK) return null;
                    pwd = f.Password;
                }
                try
                {
                    UnlockResult r = null;
                    ProgressForm.Run(verb + " " + name + "...", delegate { r = VaultCrypto.Unlock(path, pwd, null, restoreDir, deleteVkl); });
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

        /// <summary>Asks for the key's PIN until it's right. False if the user chose to use the password instead.</summary>
        private static bool UnlockKeyWithPin(KeyFile key)
        {
            if (!key.NeedsPin || key.IsUnlocked) return true;
            string error = null;
            while (true)
            {
                string pin;
                using (var f = new PinForm(key.Label, false, false, error))
                {
                    if (f.ShowDialog() != DialogResult.OK) return false;
                    pin = f.Pin;
                }
                bool ok = false;
                ProgressForm.Run("Checking the PIN...", delegate { ok = key.TryUnlock(pin); });
                if (ok) return true;
                error = "Wrong PIN. Try again.";
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

        /// <summary>
        /// Unlocks with a fitting key if one is found (stdin line 2 is its PIN, if it has one), else with the
        /// password (stdin line 1).
        /// </summary>
        private static UnlockResult UnlockQuietCore(string path, string restoreDir, bool deleteVkl, out int exitCode)
        {
            exitCode = 0;
            string password = Console.In.ReadLine() ?? "";
            string pin = Console.In.ReadLine();
            KeyFile key = VaultCrypto.FindKeyFor(path, FindKeys());
            if (key != null && !key.TryUnlock(pin) && key.NeedsPin) key = null; // wrong or no PIN: use the password
            try
            {
                if (key != null)
                {
                    try { return VaultCrypto.Unlock(path, null, new[] { key }, restoreDir, deleteVkl); }
                    catch (NeedPasswordException) { } // key has the right ID but doesn't fit: use the password
                    catch (WrongPasswordException) { }
                }
                UnlockResult r = VaultCrypto.Unlock(path, password, null, restoreDir, deleteVkl);
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
            string openCopy = Recovery.FindOpenCopy(path);
            if (openCopy != null)
            {
                Console.WriteLine(openCopy + "\talready-open");
                return 0;
            }
            string sessionDir = Workspace.CreateSessionDir();
            int code;
            UnlockResult r;
            try { r = UnlockQuietCore(path, sessionDir, false, out code); }
            catch { Workspace.DeleteSessionDir(sessionDir); throw; }
            if (r == null) { Workspace.DeleteSessionDir(sessionDir); return code; }
            Console.WriteLine(r.Restored + (r.UsedKey != null ? "\tkey" : "\tpassword"));
            Console.Out.Flush();
            Application.Run(new OpenSession(r.Restored, path, r.Keys, launch, guardSeconds));
            return 0;
        }

        private static int UnlockQuiet(string path)
        {
            if (Recovery.FindOpenCopy(path) != null)
            {
                Console.Error.WriteLine("This item is open right now. Close it first.");
                return 1;
            }
            int code;
            UnlockResult r = UnlockQuietCore(path, null, true, out code);
            if (r == null) return code;
            Console.WriteLine(r.Restored + (r.UsedKey != null ? "\tkey" : "\tpassword"));
            if (r.Keys != null) r.Keys.Clear();
            return 0;
        }

        private static int KeyCreateQuiet(string root)
        {
#if TESTHOOKS
            string label = OptionValue("--label") ?? "Test key";
            // --with-pin: PIN from stdin line 1. Without it the test key has no PIN (like VaultKeep 0.2 keys).
            string pin = HasFlag("--with-pin") ? Console.In.ReadLine() : null;
            KeyFile key = KeyStore.CreateKey(root, label, pin);
            Console.WriteLine(key.IdHex);
            return 0;
#else
            // Adding a key needs Windows sign-in, so there is no silent way to do it in the real app.
            Console.Error.WriteLine("Adding a security key needs your Windows password: use the VaultKeep window " +
                                    "or right-click the drive and choose \"Make VaultKeep security key\".");
            return 1;
#endif
        }

        // ---------------------------------------------------------------- Misc

        /// <summary>Keys on plugged-in drives (test build: plus --key-dir folders, and --no-drive-scan).</summary>
        internal static List<KeyFile> FindKeys()
        {
            var extra = new List<string>();
            bool scanDrives = true;
#if TESTHOOKS
            for (int i = 0; i < _args.Length - 1; i++)
                if (_args[i] == "--key-dir") extra.Add(_args[i + 1]);
            scanDrives = !HasFlag("--no-drive-scan");
#endif
            return KeyStore.FindKeyFiles(extra, scanDrives);
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
