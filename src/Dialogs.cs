using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;

namespace VaultKeep
{
    /// <summary>Password prompt for locking (password + confirm) or unlocking (single password).</summary>
    internal sealed class PasswordForm : Form
    {
        public const int MinPasswordLength = 8;

        private readonly bool _isLock;
        private readonly TextBox _password;
        private readonly TextBox _confirm;
        private readonly Label _error;

        public string Password { get { return _password.Text; } }

        /// <param name="note">Optional hint under the title (e.g. about security keys).</param>
        /// <param name="keyProbe">
        /// Optional check, run every 1.5 s, that returns true once a security key that fits is plugged in.
        /// The dialog then closes with <see cref="DialogResult.Yes"/>.
        /// </param>
        public PasswordForm(bool isLock, string itemName, string errorText, string note, Func<bool> keyProbe)
        {
            _isLock = isLock;

            Text = isLock ? "VaultKeep - Lock" : "VaultKeep - Unlock";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = true;
            TopMost = true;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(380, (isLock ? 250 : 190) + (note != null ? 24 : 0));
            Icon = Shell.AppIcon;

            int y = 14;
            var title = new Label
            {
                Text = (isLock ? "Lock: " : "Unlock: ") + itemName,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                AutoEllipsis = true,
                Location = new Point(14, y),
                Size = new Size(352, 22)
            };
            Controls.Add(title);
            y += 30;

            if (note != null)
            {
                Controls.Add(new Label
                {
                    Text = note,
                    ForeColor = SystemColors.GrayText,
                    AutoEllipsis = true,
                    Location = new Point(14, y - 4),
                    Size = new Size(352, 20)
                });
                y += 24;
            }

            if (keyProbe != null)
            {
                var probe = new System.Windows.Forms.Timer { Interval = 1500 };
                probe.Tick += delegate
                {
                    probe.Stop();
                    bool found = false;
                    try { found = keyProbe(); } catch { }
                    if (found) { DialogResult = DialogResult.Yes; Close(); }
                    else probe.Start();
                };
                Shown += delegate { probe.Start(); };
                FormClosed += delegate { probe.Stop(); probe.Dispose(); };
            }

            Controls.Add(new Label { Text = "Password:", Location = new Point(14, y + 3), Size = new Size(110, 20) });
            _password = new TextBox { UseSystemPasswordChar = true, Location = new Point(128, y), Size = new Size(238, 23) };
            Controls.Add(_password);
            y += 32;

            if (isLock)
            {
                Controls.Add(new Label { Text = "Confirm:", Location = new Point(14, y + 3), Size = new Size(110, 20) });
                _confirm = new TextBox { UseSystemPasswordChar = true, Location = new Point(128, y), Size = new Size(238, 23) };
                Controls.Add(_confirm);
                y += 32;
            }

            var show = new CheckBox { Text = "Show password", Location = new Point(128, y), Size = new Size(200, 22) };
            show.CheckedChanged += delegate
            {
                _password.UseSystemPasswordChar = !show.Checked;
                if (_confirm != null) _confirm.UseSystemPasswordChar = !show.Checked;
            };
            Controls.Add(show);
            y += 28;

            if (isLock)
            {
                Controls.Add(new Label
                {
                    Text = "Remember this password. If you forget it, the locked item cannot be recovered.",
                    ForeColor = Color.FromArgb(160, 90, 0),
                    Location = new Point(14, y),
                    Size = new Size(352, 34)
                });
                y += 36;
            }

            _error = new Label
            {
                Text = errorText ?? "",
                ForeColor = Color.Firebrick,
                Location = new Point(14, y),
                Size = new Size(352, 20)
            };
            Controls.Add(_error);

            var ok = new Button { Text = isLock ? "Lock" : "Unlock", Size = new Size(88, 28) };
            var cancel = new Button { Text = "Cancel", Size = new Size(88, 28), DialogResult = DialogResult.Cancel };
            ok.Location = new Point(ClientSize.Width - 14 - 88 - 8 - 88, ClientSize.Height - 14 - 28);
            cancel.Location = new Point(ClientSize.Width - 14 - 88, ClientSize.Height - 14 - 28);
            ok.Click += OnOk;
            Controls.Add(ok);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;

            Shown += delegate { Activate(); _password.Focus(); };
        }

        private void OnOk(object sender, EventArgs e)
        {
            string pwd = _password.Text;
            if (pwd.Length == 0)
            {
                ShowError("Please enter a password.");
                return;
            }
            if (_isLock)
            {
                if (pwd.Length < MinPasswordLength)
                {
                    ShowError("Use at least " + MinPasswordLength + " characters.");
                    return;
                }
                if (pwd != _confirm.Text)
                {
                    ShowError("The passwords don't match.");
                    _confirm.SelectAll();
                    _confirm.Focus();
                    return;
                }
            }
            DialogResult = DialogResult.OK;
            Close();
        }

        private void ShowError(string message)
        {
            _error.Text = message;
            System.Media.SystemSounds.Beep.Play();
        }
    }

    /// <summary>
    /// PIN for a USB security key: enter it (one field), or set/change it (current PIN if any, new PIN, confirm).
    /// </summary>
    internal sealed class PinForm : Form
    {
        private readonly TextBox _current;
        private readonly TextBox _pin;
        private readonly TextBox _confirm;
        private readonly Label _error;

        public string CurrentPin { get { return _current != null ? _current.Text : null; } }
        public string Pin { get { return _pin.Text; } }

        /// <param name="setNew">True: choose a new PIN (with confirm). False: enter the existing PIN.</param>
        /// <param name="askCurrent">With setNew: also ask for the current PIN (changing an existing one).</param>
        public PinForm(string keyLabel, bool setNew, bool askCurrent, string errorText)
        {
            Text = setNew ? "VaultKeep - Security key PIN" : "VaultKeep - Enter PIN";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            TopMost = true;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = new Font("Segoe UI", 9F);
            Icon = Shell.AppIcon;

            int y = 14;
            Controls.Add(new Label
            {
                Text = (setNew ? "PIN for security key: " : "Security key: ") + keyLabel,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                AutoEllipsis = true,
                Location = new Point(14, y),
                Size = new Size(352, 22)
            });
            y += 28;
            Controls.Add(new Label
            {
                Text = setNew
                    ? "A copy of the key file is useless without this PIN. Use at least " + PinBox.MinPinLength +
                      " characters; letters and numbers mixed are much harder to guess than digits only."
                    : "Enter the PIN of your security key to open this item.",
                ForeColor = SystemColors.GrayText,
                Location = new Point(14, y),
                Size = new Size(352, setNew ? 48 : 20)
            });
            y += setNew ? 54 : 28;

            if (setNew && askCurrent)
            {
                Controls.Add(new Label { Text = "Current PIN:", Location = new Point(14, y + 3), Size = new Size(110, 20) });
                _current = new TextBox { UseSystemPasswordChar = true, Location = new Point(128, y), Size = new Size(238, 23) };
                Controls.Add(_current);
                y += 32;
            }
            Controls.Add(new Label { Text = setNew ? "New PIN:" : "PIN:", Location = new Point(14, y + 3), Size = new Size(110, 20) });
            _pin = new TextBox { UseSystemPasswordChar = true, Location = new Point(128, y), Size = new Size(238, 23) };
            Controls.Add(_pin);
            y += 32;
            if (setNew)
            {
                Controls.Add(new Label { Text = "Confirm PIN:", Location = new Point(14, y + 3), Size = new Size(110, 20) });
                _confirm = new TextBox { UseSystemPasswordChar = true, Location = new Point(128, y), Size = new Size(238, 23) };
                Controls.Add(_confirm);
                y += 32;
            }

            _error = new Label { Text = errorText ?? "", ForeColor = Color.Firebrick, Location = new Point(14, y), Size = new Size(352, 20) };
            Controls.Add(_error);
            y += 28;

            ClientSize = new Size(380, y + 42);
            var ok = new Button { Text = "OK", Size = new Size(88, 28), Location = new Point(380 - 14 - 88 - 8 - 88, y) };
            var cancel = new Button
            {
                Text = setNew ? "Cancel" : "Use password",
                Size = new Size(setNew ? 88 : 100, 28),
                DialogResult = DialogResult.Cancel
            };
            cancel.Location = new Point(380 - 14 - cancel.Width, y);
            ok.Location = new Point(cancel.Left - 8 - 88, y);
            ok.Click += delegate
            {
                if (_pin.Text.Length == 0) { ShowError("Please enter the PIN."); return; }
                if (setNew)
                {
                    if (_pin.Text.Length < PinBox.MinPinLength) { ShowError("Use at least " + PinBox.MinPinLength + " characters."); return; }
                    if (_pin.Text != _confirm.Text) { ShowError("The PINs don't match."); _confirm.SelectAll(); _confirm.Focus(); return; }
                }
                DialogResult = DialogResult.OK;
                Close();
            };
            Controls.Add(ok);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;
            Shown += delegate { Activate(); if (_current != null) _current.Focus(); else _pin.Focus(); };
        }

        private void ShowError(string message)
        {
            _error.Text = message;
            System.Media.SystemSounds.Beep.Play();
        }
    }

    /// <summary>Small "please wait" window that runs work on a background thread.</summary>
    internal sealed class ProgressForm : Form
    {
        private readonly Action _work;
        private Exception _error;

        private ProgressForm(string message, Action work)
        {
            _work = work;
            Text = "VaultKeep";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            ControlBox = false;
            TopMost = true;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = new Font("Segoe UI", 9F);
            ClientSize = new Size(340, 90);
            Icon = Shell.AppIcon;

            var label = new Label { Text = message, AutoEllipsis = true, Location = new Point(14, 14), Size = new Size(312, 22) };
            var bar = new ProgressBar { Style = ProgressBarStyle.Marquee, Location = new Point(14, 46), Size = new Size(312, 20) };
            Controls.Add(label);
            Controls.Add(bar);

            // Large items report how far along they are: switch from the spinner to a real percentage.
            Action<int> showPercent = percent =>
            {
                if (bar.Style != ProgressBarStyle.Continuous) bar.Style = ProgressBarStyle.Continuous;
                bar.Value = Math.Max(0, Math.Min(100, percent));
                label.Text = message + "  " + percent + "%";
            };

            Shown += delegate
            {
                var t = new Thread(() =>
                {
                    Progress.Hook = percent =>
                    {
                        if (percent > 0 && IsHandleCreated) BeginInvoke(showPercent, percent);
                    };
                    try { _work(); }
                    catch (Exception ex) { _error = ex; }
                    finally { Progress.Hook = null; }
                    BeginInvoke(new Action(Close));
                });
                t.IsBackground = true;
                t.Start();
            };
        }

        /// <summary>Runs <paramref name="work"/> while showing a progress window; rethrows any error.</summary>
        public static void Run(string message, Action work)
        {
            using (var f = new ProgressForm(message, work))
            {
                f.ShowDialog();
                if (f._error != null)
                    throw f._error;
            }
        }
    }
}
