# VaultKeep

Password-protect any file or folder from the Windows Explorer right-click menu.

- **Right-click a file or folder → Lock with VaultKeep** → choose a password.
  The item is encrypted into a single `<name>.vkl` file and the original is removed.
- **Double-click a `.vkl` file** → enter the password → it opens normally (in its app, or in Explorer for a folder).
  A VaultKeep padlock appears in the system tray while it's unlocked. **Once you close it, VaultKeep
  locks it again automatically**, edits included. So the password is needed every time.
- **Right-click a `.vkl` file → Unlock permanently** removes the protection for good.

### Safe with Google Drive, OneDrive, Dropbox and shared folders

When you open a locked item, the unlocked copy is **not** put next to the `.vkl`. It is opened from
VaultKeep's private folder on this PC (`%LOCALAPPDATA%\VaultKeep\workspace`), which is never synced.
The `.vkl` stays where it is the whole time. When you close the item, your edits are written back into
the `.vkl` and the private copy is removed. So a sync app only ever uploads the encrypted `.vkl`.
(Only **Unlock permanently** puts the item back next to the `.vkl`, because that's what it's for.)

- Double-clicking a `.vkl` that is already open shows the open copy again instead of making a second one.
- If you only looked at an item and didn't change it, closing it is instant: the private copy is removed
  and the `.vkl` isn't rewritten (so a sync app has nothing to upload either).

### Large files

Locking, unlocking and opening read and write the whole item once, with a progress percentage shown.
For multi-GB items the speed is set mostly by how fast your drive can write (budget SSDs slow down a
lot on long writes; a 3 GB file takes about 40-50 s to lock on such a drive). Closing an unchanged item
doesn't rewrite anything.
- **Save As** and recent-file lists show the private folder's path while the item is open. That's expected.
- If you locked something *after* your sync app had already uploaded it, the cloud still has the old,
  unlocked copy in its trash or version history. Delete it there (e.g. Google Drive → Trash).

### Security key (USB flash drive)

A USB flash drive can be a key: **with it plugged in, double-clicking a `.vkl` opens it without typing
the password.** Without the drive, the password still works, so losing the drive never locks you out.

- **Set up:** right-click the USB drive in File Explorer → **Make VaultKeep security key**, or run
  `VaultKeep.exe` → **Add USB key...**. The key is saved in a hidden `.vaultkeep` folder on the drive;
  your other files there are not touched. Set up a second drive as a backup if you like.
  **Adding a key asks for your Windows password** (Windows' own sign-in prompt; a PIN or fingerprint
  can't be checked here), so someone using your PC while you're away can't add their own drive.
- Everything you lock afterwards opens with the key. Items locked earlier get the key the next time you
  open them with the password (they're re-locked with it).
- The password prompt notices when you plug in the key while it's open.
- **Lost the drive?** Run `VaultKeep.exe`, select the key and click **Remove key**. New items won't include it,
  and each item drops it the next time you open it. Open your important items once so the lost key stops working on them.
- Using the same drive on another PC: on that PC, choose **Add USB key...** with the drive plugged in. VaultKeep
  sees the existing key and offers to use it there too.
- **PIN:** new keys get a PIN (at least 6 characters). With the key plugged in, VaultKeep asks for the
  PIN instead of the item password; choose **Use password** if you'd rather type the password.
  The PIN encrypts the key on the drive, so a copy of the key file is useless without it.
  Keys made before PINs existed keep working without one. Add or change a PIN with
  `VaultKeep.exe` → select the key → **Change PIN...** (the drive must be plugged in).
- A PIN only slows down someone who copied the key file: they can try PINs on their own computer as
  fast as their hardware allows. A 6-digit PIN can be guessed this way; letters and numbers mixed,
  8+ characters, are far stronger. Keep the drive safe like a house key either way.

**Can someone else's USB drive open my items?** No:

- A key made on another PC (or another Windows account) has no slot in your items, so it opens nothing.
- Copying your key's ID into a fake key doesn't help. Opening needs your drive's private key, and the
  password still works even with a fake key plugged in.
- Adding a key slot to a `.vkl` by editing it is detected (the whole file is authenticated).
- Registering a new key on your PC needs your Windows password, and the real app has no silent way to do it.
- What VaultKeep can't stop: someone with *your drive* (keep it safe), or someone who can run their own
  programs while signed in as you (lock your PC with Win+L when you step away).

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
.\build.ps1            # -> bin\VaultKeep.exe (the app) + bin\test\VaultKeep.exe (test build, never install it)
.\build.ps1 -Installer # also dist\VaultKeep-Setup-X.Y.Z.exe + SHA256SUMS.txt (needs Inno Setup 6)
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

## Install

Download **VaultKeep-Setup-X.Y.Z.exe** from the
[latest release](https://github.com/SocheatSorng/VaultKeep/releases/latest) and run it. It installs for
your Windows account only (`%LOCALAPPDATA%\Programs\VaultKeep`, no admin rights) and adds the right-click
menu. The installer isn't code-signed, so SmartScreen may warn: compare the download with the release's
`SHA256SUMS.txt` (`Get-FileHash`), then **More info** → **Run anyway**.

- **Update:** run the newer installer. Items that are open keep working (the running copy is moved aside).
- **Uninstall:** Settings → Apps → VaultKeep. It removes the right-click menu. Your `.vkl` files, USB keys
  and `%LOCALAPPDATA%\VaultKeep` (registered keys, crash-recovery notes) are kept, so reinstalling
  picks up where you left off. Close opened items first: the uninstaller refuses while VaultKeep is running.

### Releasing (maintainers)

1. Set the version in `src/Program.cs` (`AssemblyVersion`, `AssemblyFileVersion`, `AssemblyInformationalVersion`).
2. `.\build.ps1 -Installer` builds `dist\VaultKeep-Setup-X.Y.Z.exe` locally (needs
   [Inno Setup 6](https://jrsoftware.org/isinfo.php): `winget install JRSoftware.InnoSetup`). Try it.
3. Push a tag `vX.Y.Z` on `main`. `.github/workflows/release.yml` checks the tag matches the version, lints,
   builds, tests and publishes the installer and `SHA256SUMS.txt` to a GitHub Release.

## Install the right-click menu without the installer

Run `bin\VaultKeep.exe` (no arguments) and click **Yes**. Run it again to remove the menu.
It registers for the current user only (`HKCU\Software\Classes`, plus a sign-in entry under
`HKCU\...\CurrentVersion\Run` for crash recovery), so no admin rights are needed.
If you move `VaultKeep.exe`, run it again to update the menu path.

Run `VaultKeep.exe` with no arguments for the VaultKeep window (right-click menu and security keys).

Command line: `VaultKeep.exe install | uninstall [--quiet] | lock <path> | open <path.vkl> | unlock <path.vkl> | key-create <drive> | recover`

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

## License

MIT, see [LICENSE](LICENSE).
