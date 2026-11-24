using System;
using System.IO;
using System.Text.RegularExpressions;

namespace VaultKeep
{
    /// <summary>
    /// Private folder where opened items live while in use: %LOCALAPPDATA%\VaultKeep\workspace\&lt;session&gt;\&lt;item&gt;.
    /// Keeping the unlocked copy here (instead of next to the .vkl) means sync apps (Google Drive, OneDrive,
    /// Dropbox), network shares and USB drives only ever see the encrypted .vkl. %LOCALAPPDATA% is per-user
    /// and is not synced or roamed by Windows.
    /// </summary>
    internal static class Workspace
    {
        private static readonly Regex SessionName = new Regex("^[0-9a-f]{12}$");

        public static string Root
        {
            get { return Path.Combine(AppPaths.DataDir, "workspace"); }
        }

        /// <summary>Creates a new, empty session folder and returns its path.</summary>
        public static string CreateSessionDir()
        {
            string dir = Path.Combine(Root, Guid.NewGuid().ToString("N").Substring(0, 12));
            Directory.CreateDirectory(dir);
            return dir;
        }

        /// <summary>The session folder an item path lives in, or null if it isn't inside the workspace.</summary>
        public static string SessionDirOf(string itemPath)
        {
            string parent = Path.GetDirectoryName(Path.GetFullPath(itemPath).TrimEnd('\\'));
            return IsSessionDir(parent) ? parent : null;
        }

        /// <summary>
        /// True only for a VaultKeep session folder: directly inside the workspace root (exactly one level
        /// below it), named like the ones <see cref="CreateSessionDir"/> makes, and not a link/junction.
        /// Every delete in the workspace goes through this check, so a bad path can never delete anything else.
        /// </summary>
        public static bool IsSessionDir(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            string full = Path.GetFullPath(dir).TrimEnd('\\');
            string root = Path.GetFullPath(Root).TrimEnd('\\');
            if (!string.Equals(Path.GetDirectoryName(full), root, StringComparison.OrdinalIgnoreCase)) return false;
            if (!SessionName.IsMatch(Path.GetFileName(full))) return false;
            if (!Directory.Exists(full)) return false;
            return (File.GetAttributes(full) & FileAttributes.ReparsePoint) == 0;
        }

        /// <summary>Deletes a session folder and everything in it (links inside are removed, never followed).</summary>
        public static void DeleteSessionDir(string dir)
        {
            if (!IsSessionDir(dir))
                throw new InvalidOperationException("Refusing to delete a folder outside VaultKeep's workspace: " + dir);
            DeleteTree(Path.GetFullPath(dir));
        }

        /// <summary>Removes a session folder if it is empty (after its item was re-locked). Never throws.</summary>
        public static void RemoveIfEmpty(string dir)
        {
            try
            {
                if (IsSessionDir(dir) && Directory.GetFileSystemEntries(dir).Length == 0)
                    Directory.Delete(dir, false);
            }
            catch { }
        }

        private static void DeleteTree(string dir)
        {
            foreach (string entry in Directory.GetFileSystemEntries(dir))
            {
                FileAttributes attr = File.GetAttributes(entry);
                if ((attr & FileAttributes.Directory) != 0)
                {
                    if ((attr & FileAttributes.ReparsePoint) != 0)
                        Directory.Delete(entry, false); // removes the link itself, not its target
                    else
                        DeleteTree(entry);
                }
                else
                {
                    File.SetAttributes(entry, FileAttributes.Normal);
                    File.Delete(entry);
                }
            }
            new DirectoryInfo(dir).Attributes = FileAttributes.Directory;
            Directory.Delete(dir, false);
        }
    }
}
