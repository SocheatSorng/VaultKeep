using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace VaultKeep
{
    /// <summary>
    /// Runs while a locked item is temporarily open. The unlocked copy lives in VaultKeep's private workspace
    /// (never next to the .vkl, so sync apps and shared folders never see it); the .vkl stays where it is.
    /// Shows a tray icon, watches the copy, and once nothing uses it any more writes it (edits included)
    /// back into the original .vkl with the same keys, then removes the copy.
    ///
    /// After re-locking it keeps watching quietly for a while ("guard"): some programs keep the content in
    /// memory without holding the file, and a later Save would recreate the copy. A file that reappears is
    /// locked into the .vkl again; a folder that reappears is reported (merging it could lose files).
    /// </summary>
    internal sealed class OpenSession : ApplicationContext
    {
        public const int DefaultGuardSeconds = 15 * 60;

        private const int CheckIntervalMs = 2000;
        private const int StartupGraceSeconds = 10;  // give the program time to open the file
        private const int FreeChecksNeeded = 3;      // must be unused for ~6 s in a row before re-locking

        private readonly string _path;      // the open copy, in the workspace
        private readonly string _vklPath;   // the original locked file it came from
        private readonly string _sessionDir;
        private readonly string _name;
        private readonly VaultKeys _keys;
        private readonly bool _isFolder;
        private readonly int _guardSeconds;
        private readonly InUseDetector _detector;
        private readonly NotifyIcon _tray;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly System.Windows.Forms.Timer _navTimer; // folders only
        private readonly DateTime _started = DateTime.UtcNow;
        private readonly Control _ui = new Control(); // marshals background results back to the UI thread
        private string _record;
        private int _freeChecks;
        private bool _locking;
        private bool _guarding;
        private DateTime _guardUntil;
        private bool _finished;

        public OpenSession(string path, string vklPath, VaultKeys keys, bool launch, int guardSeconds)
        {
            _path = Path.GetFullPath(path).TrimEnd('\\');
            _vklPath = Path.GetFullPath(vklPath);
            _sessionDir = Workspace.SessionDirOf(_path);
            _name = Path.GetFileName(_path);
            _keys = keys;
            _isFolder = Directory.Exists(_path);
            _guardSeconds = guardSeconds;
            _detector = new InUseDetector(_path, _isFolder);
            _record = Recovery.Add(_path, _vklPath);
            _ui.CreateControl();
            IntPtr forceHandle = _ui.Handle;

            var menu = new ContextMenuStrip();
            var header = new ToolStripMenuItem(_name + " is unlocked") { Enabled = false };
            menu.Items.Add(header);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open", null, delegate { Launch(); });
            menu.Items.Add("Lock now", null, delegate { LockNow(); });

            _tray = new NotifyIcon
            {
                Icon = Shell.AppIcon,
                Text = Trim("VaultKeep: " + _name + " is unlocked"),
                ContextMenuStrip = menu,
                Visible = true
            };
            _tray.DoubleClick += delegate { Launch(); };
            _tray.ShowBalloonTip(4000, "VaultKeep",
                "\"" + _name + "\" is open. It locks again automatically when you close it.", ToolTipIcon.Info);

            _timer = new System.Windows.Forms.Timer { Interval = CheckIntervalMs };
            _timer.Tick += OnTick;
            _timer.Start();

            if (_isFolder)
            {
                _navTimer = new System.Windows.Forms.Timer { Interval = 400 };
                _navTimer.Tick += OnNavigationTick;
                _navTimer.Start();
            }

            SystemEvents.SessionEnding += OnSessionEnding;

            if (launch) Launch();
        }

        private void Launch()
        {
            if (_guarding) return;
            try
            {
                // A folder opens inside the Explorer window the .vkl was double-clicked in, so Back returns there.
                if (_isFolder && ExplorerWindows.NavigateFrom(Path.GetDirectoryName(_vklPath), _path)) return;
                Process.Start(new ProcessStartInfo(_path) { UseShellExecute = true });
            }
            catch (Exception ex) { _tray.ShowBalloonTip(4000, "VaultKeep", "Couldn't open: " + ex.Message, ToolTipIcon.Warning); }
        }

        /// <summary>
        /// Keeps Explorer windows out of VaultKeep's private folders: going Up from the open folder would land in
        /// the session folder, the workspace or %LOCALAPPDATA%\VaultKeep. Send such windows to the folder the
        /// .vkl is in instead, which is where the user expects "up" to lead.
        /// </summary>
        private void OnNavigationTick(object sender, EventArgs e)
        {
            if (_finished) { _navTimer.Stop(); return; }
            ExplorerWindows.Redirect(new[] { _sessionDir, Workspace.Root, AppPaths.DataDir }, Path.GetDirectoryName(_vklPath));
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (_locking || _finished) return;
            if (_guarding) { GuardTick(); return; }

            if (!File.Exists(_path) && !Directory.Exists(_path))
            {
                // The open copy was moved or deleted. The .vkl was never touched, so nothing is lost.
                Notify("The open copy of \"" + _name + "\" was moved or deleted. \"" + Path.GetFileName(_vklPath) +
                       "\" still has the version from before you opened it.", ToolTipIcon.Warning);
                ExitSoon();
                return;
            }

            string reason = _detector.GetUseReason();
            if (reason != null)
            {
                _freeChecks = 0;
                _tray.Text = Trim("VaultKeep: " + _name + " is unlocked (" + reason + ")");
                return;
            }

            if ((DateTime.UtcNow - _started).TotalSeconds < StartupGraceSeconds) return;
            _tray.Text = Trim("VaultKeep: " + _name + " will lock shortly");
            if (++_freeChecks >= FreeChecksNeeded) Relock();
        }

        /// <summary>After re-locking: watch for a late Save recreating the copy.</summary>
        private void GuardTick()
        {
            if (DateTime.UtcNow > _guardUntil) { Exit(); return; }

            bool fileBack = File.Exists(_path);
            bool folderBack = Directory.Exists(_path);
            if (!fileBack && !folderBack) { _freeChecks = 0; return; }

            if (_isFolder || folderBack)
            {
                // Never merge into a locked folder automatically: a partial folder could replace the full one.
                _timer.Stop();
                _tray.Visible = true;
                MessageBox.Show(
                    "A program saved into \"" + _name + "\" again after VaultKeep had locked it.\n\n" +
                    "That copy is in VaultKeep's private folder and is NOT inside \"" + Path.GetFileName(_vklPath) + "\":\n" +
                    _path + "\n\nCheck what it contains, then lock it yourself or delete it.",
                    "VaultKeep", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Exit();
                return;
            }

            if (_detector.GetUseReason() != null) { _freeChecks = 0; return; }
            if (++_freeChecks >= FreeChecksNeeded) Relock();
        }

        private void LockNow()
        {
            if (_locking || _finished || _guarding) return;
            string reason = _detector.GetUseReason();
            if (reason != null)
            {
                MessageBox.Show("\"" + _name + "\" is still in use (" + reason + ").\n\nSave and close it first; VaultKeep will then lock it automatically.",
                    "VaultKeep", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Relock();
        }

        private void Relock()
        {
            _locking = true;
            _timer.Stop();
            bool lateSave = _guarding;
            if (!lateSave) _tray.Text = Trim("VaultKeep: locking " + _name + "...");

            var t = new Thread(() =>
            {
                LockResult result = null;
                Exception error = null;
                // Written to a temp file and swapped in, so the .vkl is replaced only by a complete new version.
                try { result = VaultCrypto.Lock(_path, CurrentKeys(), true, _vklPath); }
                catch (Exception ex) { error = ex; }
                if (_finished) return;
                _ui.BeginInvoke(new Action(() => OnRelocked(result, error, lateSave)));
            });
            t.IsBackground = false; // never abandon a half-finished lock
            t.Start();
        }

        private void OnRelocked(LockResult result, Exception error, bool lateSave)
        {
            _locking = false;
            _freeChecks = 0;
            if (error != null)
            {
                // Most likely a program grabbed the file again. Keep watching and retry.
                _tray.Visible = true;
                _tray.ShowBalloonTip(4000, "VaultKeep", "Couldn't lock \"" + _name + "\" yet: " + error.Message + "\nWill retry.", ToolTipIcon.Warning);
                _timer.Start();
                return;
            }

            Workspace.RemoveIfEmpty(_sessionDir);
            string message;
            ToolTipIcon icon = ToolTipIcon.Info;
            if (result.UndeletedItems.Count > 0)
            {
                message = "\"" + _name + "\" was locked, but some open files are still in use and could not be removed.";
                icon = ToolTipIcon.Warning;
            }
            else if (lateSave)
                message = "A program saved \"" + _name + "\" again after it was locked. The new version is locked too.";
            else
                message = "\"" + _name + "\" is locked again.";
            EnterGuard(message, icon);
        }

        private void EnterGuard(string message, ToolTipIcon icon)
        {
            Recovery.Remove(_record);
            _record = null;
            Notify(message, icon);
            if (_guardSeconds <= 0) { ExitSoon(); return; }

            _guarding = true;
            _guardUntil = DateTime.UtcNow.AddSeconds(_guardSeconds);
            _tray.Text = Trim("VaultKeep: " + _name + " is locked");
            _tray.ContextMenuStrip.Items[0].Text = _name + " is locked";

            // Hide the icon once the notification has been seen; keep guarding in the background.
            var hide = new System.Windows.Forms.Timer { Interval = 4000 };
            hide.Tick += delegate { hide.Stop(); hide.Dispose(); if (_guarding && !_locking) _tray.Visible = false; };
            hide.Start();
            _timer.Start();
        }

        private void OnSessionEnding(object sender, SessionEndingEventArgs e)
        {
            // Sign-out / shutdown: lock right now if possible, so no open copy is left behind.
            if (_locking || _finished) return;
            try
            {
                bool present = _isFolder ? Directory.Exists(_path) && !_guarding : File.Exists(_path);
                if (present && _detector.GetUseReason() == null)
                {
                    VaultCrypto.Lock(_path, CurrentKeys(), true, _vklPath);
                    Workspace.RemoveIfEmpty(_sessionDir);
                    Recovery.Remove(_record);
                    _finished = true;
                }
            }
            catch { }
        }

        /// <summary>The item's keys, with USB-key slots updated to the keys registered on this PC right now.</summary>
        private VaultKeys CurrentKeys()
        {
            try { _keys.SyncKeySlots(KeyStore.LoadRegistered()); }
            catch { } // key list unreadable: keep the slots the item already had
            return _keys;
        }

        private void Notify(string message, ToolTipIcon icon)
        {
            _tray.Visible = true;
            _tray.ShowBalloonTip(3000, "VaultKeep", message, icon);
        }

        /// <summary>Exit after a few seconds so the last notification can be seen.</summary>
        private void ExitSoon()
        {
            _finished = true;
            _timer.Stop();
            var exitTimer = new System.Windows.Forms.Timer { Interval = 4000 };
            exitTimer.Tick += delegate { exitTimer.Stop(); Exit(); };
            exitTimer.Start();
        }

        private void Exit()
        {
            _finished = true;
            _timer.Stop();
            if (_navTimer != null) _navTimer.Stop();
            Recovery.Remove(_record);
            Workspace.RemoveIfEmpty(_sessionDir);
            SystemEvents.SessionEnding -= OnSessionEnding;
            _tray.Visible = false;
            _tray.Dispose();
            ExitThread();
        }

        private static string Trim(string s)
        {
            return s.Length <= 63 ? s : s.Substring(0, 60) + "...";
        }
    }

    /// <summary>
    /// Remembers which items are currently open, so that if VaultKeep is killed or the PC crashes while
    /// something is open, the user is offered to lock it again next time, and so a second double-click on
    /// the same .vkl reuses the open copy instead of making another one.
    /// Records are encrypted with Windows DPAPI (current user), so they don't reveal item names.
    /// Record: pid \n open-copy path \n .vkl path   (VaultKeep 0.2 records have no .vkl line: opened in place.)
    /// </summary>
    internal static class Recovery
    {
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("VaultKeep recovery v1");

        private static string Dir
        {
            get { return Path.Combine(AppPaths.DataDir, "open"); }
        }

        public static string Add(string path, string vklPath)
        {
            Directory.CreateDirectory(Dir);
            string file = Path.Combine(Dir, Guid.NewGuid().ToString("N") + ".rec");
            byte[] plain = Encoding.UTF8.GetBytes(Process.GetCurrentProcess().Id + "\n" + path + "\n" + vklPath);
            File.WriteAllBytes(file, ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser));
            return file;
        }

        public static void Remove(string record)
        {
            try { if (record != null) File.Delete(record); } catch { }
        }

        /// <summary>If <paramref name="vklPath"/> is open right now in a running session, the open copy's path.</summary>
        public static string FindOpenCopy(string vklPath)
        {
            if (!Directory.Exists(Dir)) return null;
            string want = Path.GetFullPath(vklPath);
            foreach (string record in Directory.GetFiles(Dir, "*.rec"))
            {
                string[] lines = ReadRecord(record);
                if (lines == null || lines.Length < 3) continue;
                int pid;
                if (!int.TryParse(lines[0], out pid) || !IsVaultKeepRunning(pid)) continue;
                if (!string.Equals(lines[2], want, StringComparison.OrdinalIgnoreCase)) continue;
                if (File.Exists(lines[1]) || Directory.Exists(lines[1])) return lines[1];
            }
            return null;
        }

        /// <summary>Offers to lock any item that was left open by a VaultKeep that is no longer running.</summary>
        public static void PromptForOrphans()
        {
            if (!Directory.Exists(Dir)) return;
            foreach (string record in Directory.GetFiles(Dir))
            {
                string[] lines = ReadRecord(record);
                if (lines == null || lines.Length < 2) { Remove(record); continue; }

                int pid;
                if (int.TryParse(lines[0], out pid) && IsVaultKeepRunning(pid)) continue;

                string path = lines[1];
                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    Workspace.RemoveIfEmpty(Workspace.SessionDirOf(path));
                    Remove(record);
                    continue;
                }

                if (lines.Length < 3)
                {
                    // VaultKeep 0.2: the item was opened in place.
                    var old = MessageBox.Show(
                        "\"" + path + "\" was left unlocked because VaultKeep closed unexpectedly.\n\nLock it now?",
                        "VaultKeep", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                    if (old == DialogResult.Yes && !Program.LockWithPrompt(path, true, null)) continue;
                    Remove(record);
                    continue;
                }

                string vklPath = lines[2];
                string sessionDir = Workspace.SessionDirOf(path);
                var answer = MessageBox.Show(
                    "\"" + Path.GetFileName(path) + "\" was still open when VaultKeep closed unexpectedly. " +
                    "The open copy is in VaultKeep's private folder.\n\n" +
                    "Yes: lock it into \"" + vklPath + "\", keeping any changes you made.\n" +
                    "No: throw the open copy away. The locked file keeps the version from before you opened it.\n" +
                    "Cancel: ask me later.",
                    "VaultKeep", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);
                if (answer == DialogResult.Cancel) continue;
                if (answer == DialogResult.Yes)
                {
                    if (!Program.LockWithPrompt(path, true, vklPath)) continue; // cancelled: ask again next time
                    Workspace.RemoveIfEmpty(sessionDir);
                }
                else
                {
                    if (sessionDir != null) Workspace.DeleteSessionDir(sessionDir);
                }
                Remove(record);
            }
        }

        private static string[] ReadRecord(string record)
        {
            try
            {
                if (record.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                    return File.ReadAllLines(record); // written by VaultKeep 0.1 (unencrypted)
                byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(record), Entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plain).Split('\n');
            }
            catch
            {
                return null;
            }
        }

        private static bool IsVaultKeepRunning(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                return p.ProcessName.Equals("VaultKeep", StringComparison.OrdinalIgnoreCase) && !p.HasExited;
            }
            catch { return false; }
        }
    }
}
