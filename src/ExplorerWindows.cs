using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace VaultKeep
{
    /// <summary>
    /// Works with open File Explorer windows (Shell.Application), so an opened folder feels like it is still
    /// in its original place even though the unlocked copy lives in VaultKeep's private workspace:
    ///   - it opens inside the Explorer window the .vkl was double-clicked in, so Back returns there;
    ///   - a window that goes Up (or otherwise) into VaultKeep's private folders is sent back to the original folder.
    /// </summary>
    internal static class ExplorerWindows
    {
        /// <summary>
        /// Shows <paramref name="folder"/> in an Explorer window that is currently showing
        /// <paramref name="fromFolder"/> (so its Back button leads there). Returns false if no such window is open.
        /// </summary>
        public static bool NavigateFrom(string fromFolder, string folder)
        {
            bool done = false;
            ForEachWindow((w, location) =>
            {
                if (done || !SamePath(location, fromFolder)) return;
                w.Navigate2(folder);
                done = true;
            });
            return done;
        }

        /// <summary>
        /// Sends every Explorer window that shows one of <paramref name="privateFolders"/> exactly (not their
        /// contents) to <paramref name="target"/>. Returns how many windows were moved.
        /// </summary>
        public static int Redirect(IEnumerable<string> privateFolders, string target)
        {
            var list = new List<string>(privateFolders);
            int moved = 0;
            ForEachWindow((w, location) =>
            {
                foreach (string p in list)
                {
                    if (!SamePath(location, p)) continue;
                    w.Navigate2(target);
                    moved++;
                    return;
                }
            });
            return moved;
        }

        private static void ForEachWindow(Action<dynamic, string> action)
        {
            object shell = null;
            try
            {
                Type t = Type.GetTypeFromProgID("Shell.Application");
                if (t == null) return;
                shell = Activator.CreateInstance(t);
                dynamic windows = ((dynamic)shell).Windows();
                int count = windows.Count;
                for (int i = 0; i < count; i++)
                {
                    try
                    {
                        dynamic w = windows.Item(i);
                        if (w == null) continue;
                        string url = w.LocationURL;
                        if (string.IsNullOrEmpty(url) || !url.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) continue;
                        action(w, new Uri(url).LocalPath);
                    }
                    catch { }
                }
            }
            catch { }
            finally
            {
                if (shell != null) Marshal.FinalReleaseComObject(shell);
            }
        }

        private static bool SamePath(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            try
            {
                return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }
}
