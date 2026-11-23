# VaultKeep

Password-protect any file or folder from the Windows Explorer right-click menu.

- **Right-click a file or folder → Lock with VaultKeep** → choose a password.
  The item is encrypted into a single `<name>.vkl` file and the original is removed.
- **Double-click a `.vkl` file** → enter the password → it opens normally (in its app, or in Explorer for a folder).
  A VaultKeep padlock appears in the system tray while it's unlocked. **Once you close it, VaultKeep
  locks it again automatically**, edits included. So the password is needed every time.
- **Right-click a `.vkl` file → Unlock permanently** removes the protection for good.

### Security key (USB flash drive)

A USB flash drive can be a key: **with it plugged in, double-clicking a `.vkl` opens it without typing
the password.** Without the drive, the password still works, so losing the drive never locks you out.

- **Set up:** right-click the USB drive in File Explorer → **Make VaultKeep security key**, or run
  `VaultKeep.exe` → **Add USB key...**. The key is saved in a hidden `.vaultkeep` folder on the drive;
  your other files there are not touched. Set up a second drive as a backup if you like.
- Everything you lock afterwards opens with the key. Items locked earlier get the key the next time you
  open them with the password (they're re-locked with it).
- The password prompt notices when you plug in the key while it's open.
- **Lost the drive?** Run `VaultKeep.exe`, select the key and click **Remove key**. New items won't include it,
  and each item drops it the next time you open it. Open your important items once so the lost key stops working on them.
- Using the same drive on another PC: on that PC, choose **Add USB key...** with the drive plugged in. VaultKeep
  sees the existing key and offers to use it there too.
- Anyone holding the drive can open your locked items, so keep it safe like a house key.

How it works: the drive holds the private half of an RSA-3072 key pair. The PC keeps only the public half
(in `%LOCALAPPDATA%\VaultKeep\keys.dat`, DPAPI-encrypted), so items can be locked for the key while the
drive is unplugged, but only the drive can open them.

### How "closed" is detected

VaultKeep checks every 2 seconds, and treats the item as in use if any of these is true:

1. a program has the file open (Word, Excel, media players, ...)
2. a window title shows the file's name (Notepad, Photos, Paint, ... which read the file and let go)
3. for folders: a File Explorer window shows the folder or one of its subfolders

When none of these has been true for about 6 seconds (and at least 10 seconds after opening), it locks again.
Tray icon → **Lock now** locks immediately once the item is closed.
On sign-out or shutdown, it locks right away if the item isn't in use.
If VaultKeep is killed or the PC crashes while an item is open, you'll be asked to lock it again at your next sign-in.

After re-locking, VaultKeep keeps watching quietly for 15 minutes. If a program saves the file again
(some keep it in memory without showing its name), the new version is locked into the `.vkl` too.
If a *folder* reappears, VaultKeep warns you instead of merging it, so no files can be lost.

## Build, lint and test

```powershell
.\build.ps1            # -> bin\VaultKeep.exe
.\lint.ps1             # warnings as errors + formatting checks
.\test.ps1 -Headless   # lock/unlock round trips, wrong password, tampering, safety checks
.\test.ps1             # also the open/auto-relock tests (briefly opens Notepad and File Explorer)
```

Uses the C# compiler that ships with Windows (.NET Framework 4.8), so no SDK is required.

### Development setup (optional)

```powershell
pip install pre-commit   # or: uv tool install pre-commit
pre-commit install       # gitleaks, private-key check, lint, zizmor on every commit
```

GitHub Actions (`.github/workflows`) run lint + build + tests, a secret scan, a workflow audit
and CodeQL on every push. Dependabot keeps the pinned actions up to date.

## Install the right-click menu

Run `bin\VaultKeep.exe` (no arguments) and click **Yes**. Run it again to remove the menu.
It registers for the current user only (`HKCU\Software\Classes`, plus a sign-in entry under
`HKCU\...\CurrentVersion\Run` for crash recovery), so no admin rights are needed.
If you move `VaultKeep.exe`, run it again to update the menu path.

Run `VaultKeep.exe` with no arguments for the VaultKeep window (right-click menu and security keys).

Command line: `VaultKeep.exe install | uninstall | lock <path> | open <path.vkl> | unlock <path.vkl> | key-create <drive> | recover`

## Security

- AES-256-CBC encryption with a random data key per item. The data key is stored wrapped once by the
  password and once per security key ("slots"). Password: PBKDF2-HMAC-SHA256 with 600,000 iterations and
  a random 16-byte salt (Windows CNG, about 1 second); passwords need at least 8 characters.
  Security key: RSA-3072 OAEP-SHA256.
- Every item always keeps a password slot, so the password always works.
- Files from older VaultKeep versions (formats v1/v2) still open with the password.
  They're saved in the new format (v3) the next time they're locked.
- An HMAC-SHA256 tag (encrypt-then-MAC) is checked before anything is written, so a wrong password or a modified file is rejected cleanly.
- The `.vkl` is written to a hidden temp file and renamed into place only when complete.
  The original is deleted only after that. Unlocking restores to a temporary name first, then renames it.
- Crash-recovery notes (`%LOCALAPPDATA%\VaultKeep\open`) are encrypted with Windows DPAPI, so they don't reveal item names.
- **There is no password recovery.** If you forget the password, the data is gone.
- Originals are deleted normally, not securely wiped. On SSDs, recovery tools can sometimes still find deleted data.

## Current limitations

- While an item is open, its contents are on disk unencrypted, so other programs and users can read them.
- Programs that load a file and don't show its name in the title bar (some browsers and PDF viewers)
  may let it re-lock while it's still on screen. A save within 15 minutes gets locked too; after that it would
  create an unprotected copy, so double-click the `.vkl` again if you're still working on it.
- Selecting several items asks for a password once per item.
- Folders that contain symbolic links or junctions are refused.
- A whole folder is processed as one stream, so very large folders take a while. A progress window is shown.
