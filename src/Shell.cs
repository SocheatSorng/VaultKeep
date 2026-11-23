using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace VaultKeep
{
    /// <summary>
    /// Registers the Explorer right-click entries for the current user only (HKCU, no admin needed):
    ///   files   -> "Lock with VaultKeep"
    ///   folders -> "Lock with VaultKeep"
    ///   .vkl    -> "Unlock with VaultKeep" (also the double-click action)
    /// </summary>
    internal static class Shell
    {
        private const string Classes = @"Software\Classes\";
        private const string ProgId = "VaultKeep.Locked";
        private const string LockVerb = "VaultKeep.Lock";
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string LockIcon = @"%SystemRoot%\System32\shell32.dll,47"; // padlock

        private static Icon _appIcon;

        public static Icon AppIcon
        {
            get
            {
                if (_appIcon == null)
                {
                    IntPtr large = IntPtr.Zero, small = IntPtr.Zero;
                    try
                    {
                        string shell32 = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\shell32.dll");
                        if (ExtractIconEx(shell32, 47, out large, out small, 1) > 0 && large != IntPtr.Zero)
                            _appIcon = (Icon)Icon.FromHandle(large).Clone();
                    }
                    catch { }
                    finally
                    {
                        if (large != IntPtr.Zero) DestroyIcon(large);
                        if (small != IntPtr.Zero) DestroyIcon(small);
                    }
                    if (_appIcon == null) _appIcon = SystemIcons.Shield;
                }
                return _appIcon;
            }
        }

        public static bool IsInstalled()
        {
            using (var k = Registry.CurrentUser.OpenSubKey(Classes + @"Directory\shell\" + LockVerb))
                return k != null;
        }

        public static void Install()
        {
            string exe = Application.ExecutablePath;
            string lockCmd = "\"" + exe + "\" lock \"%1\"";
            string openCmd = "\"" + exe + "\" open \"%1\"";
            string unlockCmd = "\"" + exe + "\" unlock \"%1\"";

            // Files (hidden on files that are already locked).
            using (var k = Registry.CurrentUser.CreateSubKey(Classes + @"*\shell\" + LockVerb))
            {
                k.SetValue("", "Lock with VaultKeep");
                k.SetValue("Icon", LockIcon, RegistryValueKind.ExpandString);
                k.SetValue("AppliesTo", "NOT System.FileExtension:=" + VaultCrypto.Extension);
                using (var c = k.CreateSubKey("command")) c.SetValue("", lockCmd);
            }

            // Folders.
            using (var k = Registry.CurrentUser.CreateSubKey(Classes + @"Directory\shell\" + LockVerb))
            {
                k.SetValue("", "Lock with VaultKeep");
                k.SetValue("Icon", LockIcon, RegistryValueKind.ExpandString);
                using (var c = k.CreateSubKey("command")) c.SetValue("", lockCmd);
            }

            // Locked items (.vkl).
            using (var k = Registry.CurrentUser.CreateSubKey(Classes + VaultCrypto.Extension))
                k.SetValue("", ProgId);
            using (var k = Registry.CurrentUser.CreateSubKey(Classes + ProgId))
            {
                k.SetValue("", "VaultKeep Locked Item");
                using (var i = k.CreateSubKey("DefaultIcon")) i.SetValue("", LockIcon, RegistryValueKind.ExpandString);
                using (var s = k.CreateSubKey("shell"))
                {
                    s.SetValue("", "open");
                    using (var o = s.CreateSubKey("open"))
                    {
                        o.SetValue("", "Open with VaultKeep (password)");
                        o.SetValue("Icon", LockIcon, RegistryValueKind.ExpandString);
                        using (var c = o.CreateSubKey("command")) c.SetValue("", openCmd);
                    }
                    using (var u = s.CreateSubKey("VaultKeep.Unlock"))
                    {
                        u.SetValue("", "Unlock permanently");
                        using (var c = u.CreateSubKey("command")) c.SetValue("", unlockCmd);
                    }
                }
            }

            // At sign-in, offer to re-lock anything left unlocked by a crash or power cut.
            using (var run = Registry.CurrentUser.CreateSubKey(RunKey))
                run.SetValue("VaultKeep", "\"" + exe + "\" recover");

            NotifyShell();
        }

        public static void Uninstall()
        {
            using (var run = Registry.CurrentUser.OpenSubKey(RunKey, true))
                if (run != null) run.DeleteValue("VaultKeep", false);
            Registry.CurrentUser.DeleteSubKeyTree(Classes + @"*\shell\" + LockVerb, false);
            Registry.CurrentUser.DeleteSubKeyTree(Classes + @"Directory\shell\" + LockVerb, false);
            Registry.CurrentUser.DeleteSubKeyTree(Classes + ProgId, false);
            using (var k = Registry.CurrentUser.OpenSubKey(Classes + VaultCrypto.Extension))
            {
                bool ours = k != null && ProgId.Equals(k.GetValue("") as string);
                if (ours) Registry.CurrentUser.DeleteSubKeyTree(Classes + VaultCrypto.Extension, false);
            }
            NotifyShell();
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int ExtractIconEx(string file, int index, out IntPtr large, out IntPtr small, int count);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);

        [DllImport("shell32.dll")]
        private static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);

        private static void NotifyShell()
        {
            const int SHCNE_ASSOCCHANGED = 0x08000000;
            SHChangeNotify(SHCNE_ASSOCCHANGED, 0, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
