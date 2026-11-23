# VaultKeep

Windows Explorer add-on that password-protects files and folders. Right-click → "Lock with VaultKeep"
encrypts an item into `<name>.vkl`; double-clicking the `.vkl` asks for the password, restores the item in
place, opens it, and re-locks it automatically once it's closed. See README.md for user-facing behaviour.

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
  public keys registered per PC in `keys.dat` (DPAPI). `AppPaths.DataDir` honours `VAULTKEEP_HOME` (tests).
- `src/MainForm.cs`: window shown when the exe runs without arguments: right-click menu + key management.
- `src/Pbkdf2.cs`: PBKDF2 via native CNG (`BCryptDeriveKeyPBKDF2`), managed fallback.
- `src/OpenSession.cs`: tray-icon session that watches an opened item and re-locks it, then guards
  15 min for late saves; `Recovery` (DPAPI-encrypted records in `%LOCALAPPDATA%\VaultKeep\open`)
  offers to re-lock items left open after a crash.
- `src/InUseDetector.cs`: "is it still open?": file handles, window titles, Explorer windows.
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
- Run `/security-review` before a release and whenever crypto, file deletion, the registry
  integration or the open/re-lock logic changes.
- Write files as UTF-8 with the Write/Edit tools. Windows PowerShell 5.1 `Get-Content -Raw` /
  `Set-Content` garble non-ASCII text (`.\lint.ps1` catches it).
- UI changes: use the `winforms-ui-designer` agent (`.claude/agents/`).
