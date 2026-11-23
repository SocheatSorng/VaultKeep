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
    /// Runs while a locked item is temporarily unlocked for use. Shows a tray icon, watches the item,
    /// and re-encrypts it (with the same password, edits included) once nothing is using it any more.
    ///
    /// After re-locking it keeps watching quietly for a while ("guard"): some programs keep the content in
    /// memory without holding the file, and a later Save would recreate an unprotected copy. A file that
    /// reappears is locked again into the .vkl; a folder that reappears is reported (merging it could lose files).
    /// </summary>
    internal sealed class OpenSession : ApplicationContext
    {
        public const int DefaultGuardSeconds = 15 * 60;

        private const int CheckIntervalMs = 2000;
        private const int StartupGraceSeconds = 10;  // give the program time to open the file
        private const int FreeChecksNeeded = 3;      // must be unused for ~6 s in a row before re-locking

        private readonly string _path;
        private readonly string _name;
        private readonly VaultKeys _keys;
        private readonly bool _isFolder;
        private readonly int _guardSeconds;
        private readonly InUseDetector _detector;
        private readonly NotifyIcon _tray;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly DateTime _started = DateTime.UtcNow;
        private readonly Control _ui = new Control(); // marshals background results back to the UI thread
        private string _record;
        private int _freeChecks;
        private bool _locking;
        private bool _guarding;
        private DateTime _guardUntil;
        private bool _finished;

        public OpenSession(string path, VaultKeys keys, bool launch, int guardSeconds)
        {
            _path = Path.GetFullPath(path).TrimEnd('\\');
            _name = Path.GetFileName(_path);
            _keys = keys;
            _isFolder = Directory.Exists(_path);
            _guardSeconds = guardSeconds;
            _detector = new InUseDetector(_path, _isFolder);
            _record = Recovery.Add(_path);
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
                "\"" + _name + "\" is unlocked. It locks again automatically when you close it.", ToolTipIcon.Info);

            _timer = new System.Windows.Forms.Timer { Interval = CheckIntervalMs };
            _timer.Tick += OnTick;
            _timer.Start();

            SystemEvents.SessionEnding += OnSessionEnding;

            if (launch) Launch();
        }

        private void Launch()
        {
            if (_guarding) return;
            try { Process.Start(new ProcessStartInfo(_path) { UseShellExecute = true }); }
            catch (Exception ex) { _tray.ShowBalloonTip(4000, "VaultKeep", "Couldn't open: " + ex.Message, ToolTipIcon.Warning); }
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (_locking || _finished) return;
            if (_guarding) { GuardTick(); return; }

            if (!File.Exists(_path) && !Directory.Exists(_path))
            {
                // Moved, renamed or deleted by the user: nothing left to lock here.
                Notify("\"" + _name + "\" was moved or deleted, so VaultKeep stopped watching it.", ToolTipIcon.Warning);
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

        /// <summary>After re-locking: watch for a late Save recreating the item unprotected.</summary>
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
                    "A program saved \"" + _name + "\" again after VaultKeep had locked it.\n\n" +
                    "The new copy next to \"" + _name + VaultCrypto.Extension + "\" is NOT protected. " +
                    "Check what it contains, then lock it yourself or delete it.",
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
                // replaceStale: an older .vkl of this same item may still be there (e.g. a late save, or the
                // .vkl could not be deleted when it was opened). The new copy has the latest content.
                try { result = VaultCrypto.Lock(_path, CurrentKeys(), true); }
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

            string message;
            ToolTipIcon icon = ToolTipIcon.Info;
            if (result.UndeletedItems.Count > 0)
            {
                message = "\"" + _name + "\" was locked, but some original files are still in use and could not be removed.";
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
            // Sign-out / shutdown: lock right now if possible, so nothing stays unlocked on disk.
            if (_locking || _finished) return;
            try
            {
                bool present = _isFolder ? Directory.Exists(_path) && !_guarding : File.Exists(_path);
                if (present && _detector.GetUseReason() == null)
                {
                    VaultCrypto.Lock(_path, CurrentKeys(), true);
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
            Recovery.Remove(_record);
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
    /// Remembers which items are currently unlocked, so that if VaultKeep is killed or the PC crashes
    /// while something is open, the user is offered to lock it again next time.
    /// Records are encrypted with Windows DPAPI (current user), so they don't reveal item names.
    /// </summary>
    internal static class Recovery
    {
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("VaultKeep recovery v1");

        private static string Dir
        {
            get { return Path.Combine(AppPaths.DataDir, "open"); }
        }

        public static string Add(string path)
        {
            Directory.CreateDirectory(Dir);
            string file = Path.Combine(Dir, Guid.NewGuid().ToString("N") + ".rec");
            byte[] plain = Encoding.UTF8.GetBytes(Process.GetCurrentProcess().Id + "\n" + path);
            File.WriteAllBytes(file, ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser));
            return file;
        }

        public static void Remove(string record)
        {
            try { if (record != null) File.Delete(record); } catch { }
        }

        /// <summary>Offers to lock any item that was left unlocked by a VaultKeep that is no longer running.</summary>
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
                if (!File.Exists(path) && !Directory.Exists(path)) { Remove(record); continue; }

                var answer = MessageBox.Show(
                    "\"" + path + "\" was left unlocked because VaultKeep closed unexpectedly.\n\nLock it now?",
                    "VaultKeep", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                // replaceStale: the .vkl next to it (if any) is the older copy from before it was opened.
                if (answer == DialogResult.Yes && !Program.LockWithPrompt(path, true)) continue; // cancelled: ask again next time
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
