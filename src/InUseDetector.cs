using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace VaultKeep
{
    /// <summary>
    /// Decides whether an unlocked file/folder is still being used. Windows has no single "is this open?"
    /// API, so three signals are combined:
    ///   1. a program holds the file open (an exclusive open fails), e.g. Word, Excel, VLC
    ///   2. a visible window's title shows the file name, e.g. Notepad, Photos, Paint, which read the file and close it
    ///   3. (folders) an Explorer window is showing the folder or one of its subfolders
    /// </summary>
    internal sealed class InUseDetector
    {
        private const int MaxFilesToCheck = 2000;

        private readonly string _path;
        private readonly bool _isFolder;

        public InUseDetector(string path, bool isFolder)
        {
            _path = Path.GetFullPath(path).TrimEnd('\\');
            _isFolder = isFolder;
        }

        /// <summary>Returns a short reason when in use (for the tray tooltip), or null when free.</summary>
        public string GetUseReason()
        {
            if (!_isFolder)
            {
                if (!File.Exists(_path)) return null;
                if (IsFileHeldOpen(_path)) return "open in a program";
                if (AnyWindowShows(new[] { _path })) return "open in a window";
                return null;
            }

            if (!Directory.Exists(_path)) return null;
            if (ExplorerShowsFolder(_path)) return "open in File Explorer";

            List<string> files = ListFiles(_path, MaxFilesToCheck);
            foreach (string f in files)
                if (IsFileHeldOpen(f)) return Path.GetFileName(f) + " is open";
            if (AnyWindowShows(files)) return "a file inside is open";
            return null;
        }

        // ------------------------------------------------------------ Signal 1

        public static bool IsFileHeldOpen(string file)
        {
            try
            {
                using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None)) { }
                return false;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (IOException) { return true; } // sharing violation
        }

        // ------------------------------------------------------------ Signal 2

        private static bool AnyWindowShows(IEnumerable<string> files)
        {
            var names = new List<string[]>();
            foreach (string f in files)
            {
                string full = Path.GetFileName(f);
                string bare = Path.GetFileNameWithoutExtension(f);
                names.Add(new[] { full.ToLowerInvariant(), bare.ToLowerInvariant() });
            }
            if (names.Count == 0) return false;

            foreach (string title in VisibleWindowTitles())
            {
                string t = title.ToLowerInvariant();
                foreach (string[] n in names)
                {
                    // "report.txt - Notepad", "Photos - pic.jpg", "*report.txt - Notepad"
                    if (n[0].Length > 0 && t.Contains(n[0])) return true;
                    // "report - Word", "budget - Excel" (when extensions are hidden)
                    if (n[1].Length >= 2 && (t.StartsWith(n[1] + " - ") || t.StartsWith(n[1] + " – ") ||
                                             t.StartsWith("*" + n[1] + " - ")))
                        return true;
                }
            }
            return false;
        }

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc proc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int max);

        [DllImport("user32.dll")]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

        private static List<string> VisibleWindowTitles()
        {
            var titles = new List<string>();
            uint self = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
            EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                if (!IsWindowVisible(h)) return true;
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                if (pid == self) return true; // ignore our own windows
                int len = GetWindowTextLength(h);
                if (len <= 0) return true;
                var sb = new StringBuilder(len + 1);
                GetWindowText(h, sb, sb.Capacity);
                titles.Add(sb.ToString());
                return true;
            }, IntPtr.Zero);
            return titles;
        }

        // ------------------------------------------------------------ Signal 3

        private static bool ExplorerShowsFolder(string folder)
        {
            string prefix = folder + "\\";
            object shell = null;
            try
            {
                Type t = Type.GetTypeFromProgID("Shell.Application");
                if (t == null) return false;
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
                        string local = new Uri(url).LocalPath.TrimEnd('\\');
                        if (local.Equals(folder, StringComparison.OrdinalIgnoreCase) ||
                            local.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                    catch { }
                }
            }
            catch { }
            finally
            {
                if (shell != null) Marshal.FinalReleaseComObject(shell);
            }
            return false;
        }

        // ---------------------------------------------------------------- Misc

        private static List<string> ListFiles(string root, int max)
        {
            var result = new List<string>();
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0 && result.Count < max)
            {
                string dir = stack.Pop();
                try
                {
                    foreach (string f in Directory.GetFiles(dir))
                    {
                        result.Add(f);
                        if (result.Count >= max) break;
                    }
                    foreach (string d in Directory.GetDirectories(dir)) stack.Push(d);
                }
                catch { }
            }
            return result;
        }
    }
}
