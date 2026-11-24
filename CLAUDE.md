# VaultKeep

Windows Explorer add-on that password-protects files and folders. Right-click → "Lock with VaultKeep"
encrypts an item into `<name>.vkl`; double-clicking the `.vkl` asks for the password, decrypts the item into a
private local workspace, opens it, and writes it back into the .vkl once it's closed. See README.md for user-facing behaviour.

## Commands

```powershell
.\build.ps1            # build bin\VaultKeep.exe (csc.exe from .NET Framework 4.8, no SDK needed)
.\lint.ps1             # compiler warnings as errors (/warn:4) + formatting checks
.\test.ps1 -Headless   # crypto + security-key tests (~2 min, what CI runs)
.\test.ps1             # + session tests: open Notepad/Explorer briefly, need a desktop (~3 min)
```

After every code change: run lint, build and the tests (full suite if `OpenSession.cs` or
`InUseDetector.cs` changed), and report the results.

## Layout

- `src/VaultCrypto.cs`: `.vkl` format, Lock/Unlock. AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC),
  format v3 (v1/v2 still readable, password only). Format is documented at the top of the file.
- `src/VaultKeys.cs`: per-item random data key + slots (password: PBKDF2-SHA256 600k; USB key: RSA-OAEP).
  Every item must keep a password slot.
- `src/KeyStore.cs`: USB security keys: private key file on the drive (`.vaultkeep\vaultkeep.vkkey`),
  public keys registered per PC in `keys.dat` (DPAPI). `AppPaths.DataDir` honours `VAULTKEEP_HOME` (test build only).
  Key files are VKKEY2 (VKKEY1 still read): ID + public half readable, private half optionally PIN-encrypted
  (`PinBox`: PBKDF2 600k + AES-256-CBC + HMAC over ID/public half). New keys need a PIN (min 6).
  Script mode stdin for open/unlock: line 1 = item password, line 2 = key PIN.
- `src/MainForm.cs`: window shown when the exe runs without arguments: right-click menu + key management.
- `src/Pbkdf2.cs`: PBKDF2 via native CNG (`BCryptDeriveKeyPBKDF2`), managed fallback.
- `src/Streaming.cs`: one-pass lock/unlock: HMAC on a background thread (`BackgroundHmac`, pooled 1 MB
  buffers), hashing read/write streams, `Progress` (thread-static percent hook). Unlock decrypts to a temp
  name and renames only after the HMAC matches; keep that order.
- `src/Workspace.cs`: private folder for opened items (`<DataDir>\workspace\<session>\<item>`); every delete
  there goes through `IsSessionDir` (allowlisted root, exactly one level below, name pattern, no links).
- `src/OpenSession.cs`: tray-icon session that watches an opened item (in the workspace) and re-locks it
  into its original .vkl (which stays in place while open), then guards
  15 min for late saves; `Recovery` (DPAPI-encrypted records in `%LOCALAPPDATA%\VaultKeep\open`)
  offers to re-lock items left open after a crash.
- `src/InUseDetector.cs`: "is it still open?": file handles, window titles, Explorer windows.
- `src/WindowsAuth.cs`: Windows sign-in check (CredUI + LogonUser) required before adding a key.
- `src/Dialogs.cs`: password and progress dialogs. `src/Shell.cs`: HKCU right-click menu + Run key.
- `src/Program.cs`: commands `install | uninstall | lock | open | unlock | recover`;
  `--password-stdin` (and `--no-launch` for open) give a dialog-free mode used by the tests.
- `tests/`: PowerShell tests driving the exe in script mode; scratch data only under `tests/out/`.

## Rules

- **C# 5 only** (the Windows-bundled compiler): no `$""`, `?.`, `nameof`, expression-bodied members.
- **Never lose user data.** The original is deleted only after the `.vkl` has been written in full;
  unlock writes to a temp name and renames. Keep these orders, and add a test for any new delete path.
- **Never change the `.vkl` format** without bumping `FormatVersion` and keeping old versions readable.
- Don't weaken crypto parameters. Passwords are never logged, written to disk or passed on a command line.
- Never run `install`/`uninstall`, or lock/open real user files, during development or tests. Use
  `tests/out/` and fake data. Installing the menu changes the user's registry and needs their OK.
- Tests must never touch the user's real keys or drives: always set `VAULTKEEP_HOME` (TestLib does)
  and pass `--no-drive-scan`, using `--key-dir <folder>` as a fake USB drive.
- Test-only behaviour lives behind `#if TESTHOOKS` and exists only in `bin\test\VaultKeep.exe`:
  `VAULTKEEP_HOME`, `--key-dir`, `--no-drive-scan` and silent `key-create`. The real exe must have no way
  to add a security key without `WindowsAuth.Verify` (Windows password). Never install the test build.
- A security key that fails (damaged or fake) must never block the password: always fall back to it.
- **Opening never writes an unlocked copy next to the .vkl** (sync apps would upload it): open decrypts into
  the workspace and keeps the .vkl. Only "Unlock permanently" restores in place.
- Run `/security-review` before a release and whenever crypto, file deletion, the registry
  integration or the open/re-lock logic changes.
- Write files as UTF-8 with the Write/Edit tools. Windows PowerShell 5.1 `Get-Content -Raw` /
  `Set-Content` garble non-ASCII text (`.\lint.ps1` catches it).
- UI changes: use the `winforms-ui-designer` agent (`.claude/agents/`).
