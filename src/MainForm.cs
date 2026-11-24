using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace VaultKeep
{
    /// <summary>Window shown when VaultKeep.exe is run directly: right-click menu and USB security keys.</summary>
    internal sealed class MainForm : Form
    {
        private readonly Label _menuStatus;
        private readonly Button _menuButton;
        private readonly ListView _keys;
        private readonly Button _removeKey;

        public MainForm()
        {
            Text = "VaultKeep";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(480, 400);
            Icon = Shell.AppIcon;

            var bold = new Font("Segoe UI", 10F, FontStyle.Bold);
            Controls.Add(new Label { Text = "Right-click menu", Font = bold, Location = new Point(16, 16), Size = new Size(300, 22) });
            _menuStatus = new Label { Location = new Point(16, 44), Size = new Size(330, 20) };
            _menuButton = new Button { Location = new Point(368, 39), Size = new Size(96, 28) };
            _menuButton.Click += delegate { ToggleMenu(); };
            Controls.Add(_menuStatus);
            Controls.Add(_menuButton);

            Controls.Add(new Label { Text = "Security keys (USB flash drives)", Font = bold, Location = new Point(16, 88), Size = new Size(440, 22) });
            Controls.Add(new Label
            {
                Text = "With a key drive plugged in, double-clicking a locked item opens it without typing the " +
                       "password. The password always works too. Anyone holding the drive can open your items, " +
                       "so keep it safe like a house key.",
                ForeColor = SystemColors.GrayText,
                Location = new Point(16, 114),
                Size = new Size(448, 50)
            });

            _keys = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                HideSelection = false,
                HeaderStyle = ColumnHeaderStyle.Nonclickable,
                Location = new Point(16, 170),
                Size = new Size(448, 150)
            };
            _keys.Columns.Add("Name", 190);
            _keys.Columns.Add("Status", 150);
            _keys.Columns.Add("Added", 100);
            _keys.SelectedIndexChanged += delegate { _removeKey.Enabled = _keys.SelectedItems.Count > 0; };
            Controls.Add(_keys);

            var addKey = new Button { Text = "Add USB key...", Location = new Point(16, 330), Size = new Size(120, 28) };
            addKey.Click += delegate { if (CreateKeyOnDrive(this, null)) RefreshAll(); };
            _removeKey = new Button { Text = "Remove key", Location = new Point(144, 330), Size = new Size(100, 28), Enabled = false };
            _removeKey.Click += delegate { RemoveSelectedKey(); };
            var close = new Button { Text = "Close", Location = new Point(384, 362), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };
            close.Click += delegate { Close(); };
            Controls.Add(addKey);
            Controls.Add(_removeKey);
            Controls.Add(close);
            CancelButton = close;

            var refresh = new System.Windows.Forms.Timer { Interval = 3000 };
            refresh.Tick += delegate { RefreshKeyStatus(); };
            Shown += delegate { RefreshAll(); refresh.Start(); };
            FormClosed += delegate { refresh.Dispose(); };
        }

        private void RefreshAll()
        {
            bool installed = Shell.IsInstalled();
            _menuStatus.Text = installed ? "\"Lock with VaultKeep\" is in your right-click menu." : "Not in your right-click menu.";
            _menuButton.Text = installed ? "Remove" : "Add";

            _keys.Items.Clear();
            foreach (RegisteredKey k in Program.RegisteredKeysOrEmpty())
            {
                var item = new ListViewItem(new[] { k.Label, "", k.CreatedUtc.ToLocalTime().ToShortDateString() }) { Tag = k };
                _keys.Items.Add(item);
            }
            if (_keys.Items.Count == 0)
                _keys.Items.Add(new ListViewItem(new[] { "No keys yet: click \"Add USB key...\"", "", "" }) { ForeColor = SystemColors.GrayText });
            _removeKey.Enabled = false;
            RefreshKeyStatus();
        }

        private void RefreshKeyStatus()
        {
            List<KeyFile> present = KeyStore.FindKeyFiles(null, true);
            foreach (ListViewItem item in _keys.Items)
            {
                var k = item.Tag as RegisteredKey;
                if (k == null) continue;
                KeyFile found = present.Find(p => KeyStore.BytesEqual(p.Id, k.Id));
                item.SubItems[1].Text = found != null
                    ? "Plugged in (" + Path.GetPathRoot(found.Path).TrimEnd('\\') + ")"
                    : "Not plugged in";
            }
        }

        private void ToggleMenu()
        {
            if (Shell.IsInstalled())
            {
                if (MessageBox.Show(this, "Remove VaultKeep from the right-click menu?\n\nYour locked .vkl files stay locked.",
                        "VaultKeep", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                Shell.Uninstall();
            }
            else
            {
                Shell.Install();
            }
            RefreshAll();
        }

        private void RemoveSelectedKey()
        {
            if (_keys.SelectedItems.Count == 0) return;
            var k = _keys.SelectedItems[0].Tag as RegisteredKey;
            if (k == null) return;
            var answer = MessageBox.Show(this,
                "Remove the security key \"" + k.Label + "\" from this PC?\n\n" +
                "Items you lock from now on won't include it, and items lose it the next time you open them.\n\n" +
                "Items you haven't opened since can still be opened with this key. If the drive was lost, " +
                "open your important items once so they're re-locked without it.\n\n" +
                "The key file on the drive itself is not deleted.",
                "VaultKeep", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
            KeyStore.Unregister(k.Id);
            RefreshAll();
        }

        // ------------------------------------------------------------ Add key

        /// <summary>
        /// A registered key opens everything locked afterwards, so only the signed-in Windows user may add one:
        /// someone using an unlocked PC must not be able to slip in their own USB drive.
        /// </summary>
        private static bool ConfirmItsYou(IWin32Window owner)
        {
            return WindowsAuth.Verify(owner,
                "Confirm it's you: enter your Windows password to add a VaultKeep security key. " +
                "A key opens every item you lock from now on.");
        }

        /// <summary>
        /// Makes a drive a security key (or registers the key it already holds). <paramref name="root"/> null
        /// lets the user pick a drive. Returns true if a key was added.
        /// </summary>
        public static bool CreateKeyOnDrive(IWin32Window owner, string root)
        {
            string label;
            using (var pick = new AddKeyForm(root))
            {
                if (pick.ShowDialog(owner) != DialogResult.OK) return false;
                root = pick.Root;
                label = pick.KeyName;
            }

            string keyPath = KeyStore.KeyFilePath(root);
            if (File.Exists(keyPath))
            {
                KeyFile existing = KeyStore.ReadKeyFile(keyPath);
                if (existing == null)
                {
                    Program.Error("This drive has a damaged VaultKeep key file:\n" + keyPath);
                    return false;
                }
                var use = MessageBox.Show(owner,
                    "This drive already holds the VaultKeep key \"" + existing.Label + "\".\n\nUse it on this PC too?",
                    "VaultKeep", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (use != DialogResult.Yes) return false;
                if (!ConfirmItsYou(owner)) return false;
                if (!KeyStore.Register(existing)) Program.Info("This key is already set up on this PC.");
                return true;
            }

            bool removable = false;
            try { removable = new DriveInfo(root).DriveType == DriveType.Removable; } catch { }
            var confirm = MessageBox.Show(owner,
                "VaultKeep will save a key on " + root + " (in a hidden \".vaultkeep\" folder; your files on the " +
                "drive are not touched).\n\n" +
                (removable ? "" : "Note: Windows doesn't report this drive as removable. That's normal for USB hard disks.\n\n") +
                "Anyone holding this drive can open your locked items, so keep it safe. " +
                "Tip: set up a second drive as a backup key.",
                "VaultKeep", MessageBoxButtons.OKCancel, MessageBoxIcon.Information);
            if (confirm != DialogResult.OK) return false;
            if (!ConfirmItsYou(owner)) return false;

            ProgressForm.Run("Creating the key on " + root + "...", delegate { KeyStore.CreateKey(root, label); });
            Program.Info("\"" + label + "\" is ready.\n\n" +
                         "Items you lock from now on open with it. Items locked earlier get it the next time you open " +
                         "them with the password.");
            return true;
        }
    }

    /// <summary>Pick a drive and a name for a new security key.</summary>
    internal sealed class AddKeyForm : Form
    {
        private readonly ComboBox _drives;
        private readonly TextBox _label;

        public string Root { get { return ((DriveChoice)_drives.SelectedItem).Root; } }
        public string KeyName { get { return _label.Text.Trim(); } }

        private sealed class DriveChoice
        {
            public string Root;
            public string Text;
            public override string ToString() { return Text; }
        }

        public AddKeyForm(string preselectRoot)
        {
            Text = "VaultKeep - Add USB key";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(400, 170);
            Icon = Shell.AppIcon;

            Controls.Add(new System.Windows.Forms.Label { Text = "Drive:", Location = new Point(16, 23), Size = new Size(80, 20) });
            _drives = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(100, 20), Size = new Size(284, 23) };
            Controls.Add(_drives);
            Controls.Add(new System.Windows.Forms.Label { Text = "Key name:", Location = new Point(16, 59), Size = new Size(80, 20) });
            _label = new TextBox { Location = new Point(100, 56), Size = new Size(284, 23) };
            Controls.Add(_label);
            var hint = new System.Windows.Forms.Label
            {
                Text = "Plug in the USB drive first. Drives that aren't listed: unplug and plug in again, then reopen this window.",
                ForeColor = SystemColors.GrayText,
                Location = new Point(16, 88),
                Size = new Size(368, 34)
            };
            Controls.Add(hint);

            var ok = new Button { Text = "Next", Location = new Point(208, 128), Size = new Size(88, 28) };
            var cancel = new Button { Text = "Cancel", Location = new Point(304, 128), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };
            ok.Click += delegate
            {
                if (_drives.SelectedItem == null) { System.Media.SystemSounds.Beep.Play(); return; }
                if (KeyName.Length == 0) _label.Text = "USB key " + Root.TrimEnd('\\');
                DialogResult = DialogResult.OK;
                Close();
            };
            Controls.Add(ok);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;

            foreach (DriveInfo d in KeyStore.CandidateDrives())
            {
                string name = "";
                try { name = d.VolumeLabel; } catch { }
                string size = "";
                try { size = (d.TotalSize / 1e9).ToString("0.#") + " GB"; } catch { }
                var choice = new DriveChoice
                {
                    Root = d.RootDirectory.FullName,
                    Text = d.Name.TrimEnd('\\') + "  " + (name.Length > 0 ? name : "USB drive") + "  (" + size +
                           (d.DriveType == DriveType.Removable ? ", removable)" : ")")
                };
                _drives.Items.Add(choice);
                if (preselectRoot != null && string.Equals(choice.Root, Path.GetPathRoot(preselectRoot), StringComparison.OrdinalIgnoreCase))
                    _drives.SelectedItem = choice;
            }
            if (_drives.SelectedItem == null && _drives.Items.Count > 0) _drives.SelectedIndex = 0;
            if (_drives.Items.Count == 0)
            {
                hint.Text = "No USB drive found. Plug one in, then reopen this window.";
                hint.ForeColor = Color.Firebrick;
                ok.Enabled = false;
            }
            _label.Text = _drives.SelectedItem != null ? "USB key " + Root.TrimEnd('\\') : "";
        }
    }
}
