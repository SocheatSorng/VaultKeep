using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace VaultKeep
{
    /// <summary>
    /// Confirms the person at the keyboard is the signed-in Windows user, using Windows' own credential
    /// prompt. The password is checked with Windows (LogonUser) and wiped from memory; it is never stored.
    /// Used before adding a USB security key, so someone using an unlocked PC can't register their own drive.
    /// </summary>
    internal static class WindowsAuth
    {
        private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200;
        private const int CRED_PACK_PROTECTED_CREDENTIALS = 0x1;
        private const int ERROR_CANCELLED = 1223;
        private const int ERROR_LOGON_FAILURE = 1326;
        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_LOGON_NETWORK = 3;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        /// <summary>Shows the Windows sign-in prompt until the right password is entered or the user cancels.</summary>
        /// <returns>True if the current Windows user's password was verified.</returns>
        public static bool Verify(IWin32Window owner, string message)
        {
            int lastError = 0;
            while (true)
            {
                var info = new CREDUI_INFO
                {
                    cbSize = Marshal.SizeOf(typeof(CREDUI_INFO)),
                    hwndParent = owner != null ? owner.Handle : IntPtr.Zero,
                    pszCaptionText = "VaultKeep",
                    pszMessageText = message
                };
                uint authPackage = 0;
                IntPtr outBuf;
                uint outSize;
                bool save = false;
                int rc = CredUIPromptForWindowsCredentials(ref info, lastError, ref authPackage, IntPtr.Zero, 0,
                    out outBuf, out outSize, ref save, CREDUIWIN_ENUMERATE_CURRENT_USER);
                if (rc == ERROR_CANCELLED) return false;
                if (rc != 0) throw new InvalidOperationException("Windows sign-in prompt failed (error " + rc + ").");

                Result result;
                try { result = CheckCredentials(outBuf, outSize); }
                finally
                {
                    ZeroMemory(outBuf, (UIntPtr)outSize);
                    CoTaskMemFree(outBuf);
                }

                if (result == Result.Ok) return true;
                if (result == Result.NotPassword)
                {
                    MessageBox.Show(owner,
                        "Please sign in with your Windows password. A PIN, fingerprint or face can't be checked here.\n\n" +
                        "In the next window, click \"More choices\" and choose your password.",
                        "VaultKeep", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    lastError = 0;
                }
                else
                {
                    lastError = ERROR_LOGON_FAILURE; // the prompt shows "The user name or password is incorrect"
                }
            }
        }

        private enum Result { Ok, WrongPassword, NotPassword }

        private static Result CheckCredentials(IntPtr buffer, uint size)
        {
            var user = new StringBuilder(513);
            var domain = new StringBuilder(338);
            var password = new StringBuilder(513);
            int userLen = user.Capacity, domainLen = domain.Capacity, pwdLen = password.Capacity;
            try
            {
                if (!CredUnPackAuthenticationBuffer(CRED_PACK_PROTECTED_CREDENTIALS, buffer, size,
                        user, ref userLen, domain, ref domainLen, password, ref pwdLen))
                    return Result.NotPassword;
                if (password.Length == 0) return Result.NotPassword;

                string u = user.ToString(), d = domain.ToString();
                if (d.Length == 0 && u.Contains("\\"))
                {
                    int i = u.IndexOf('\\');
                    d = u.Substring(0, i);
                    u = u.Substring(i + 1);
                }

                IntPtr token;
                bool ok = LogonUser(u, d.Length > 0 ? d : null, password.ToString(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out token) ||
                          LogonUser(u, d.Length > 0 ? d : null, password.ToString(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out token);
                if (!ok) return Result.WrongPassword;
                try
                {
                    // Must be the account that is signed in, not some other account on this PC.
                    using (var signedIn = new WindowsIdentity(token))
                    using (var current = WindowsIdentity.GetCurrent())
                        return signedIn.User != null && signedIn.User.Equals(current.User) ? Result.Ok : Result.WrongPassword;
                }
                finally
                {
                    CloseHandle(token);
                }
            }
            finally
            {
                password.Clear();
                password.Append('\0', password.Capacity);
                password.Clear();
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO info, int authError, ref uint authPackage,
            IntPtr inAuthBuffer, uint inAuthBufferSize, out IntPtr outAuthBuffer, out uint outAuthBufferSize, ref bool save, int flags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredUnPackAuthenticationBuffer(int flags, IntPtr authBuffer, uint authBufferSize,
            StringBuilder userName, ref int maxUserName, StringBuilder domainName, ref int maxDomainName,
            StringBuilder password, ref int maxPassword);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("ole32.dll")]
        private static extern void CoTaskMemFree(IntPtr ptr);

        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory")]
        private static extern void ZeroMemory(IntPtr dest, UIntPtr size);
    }
}
