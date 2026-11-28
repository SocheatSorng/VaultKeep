## Install

1. Download the **VaultKeep-Setup** `.exe` below and run it. No administrator rights are needed:
   it installs for your Windows account only, into `%LOCALAPPDATA%\Programs\VaultKeep`.
2. Windows SmartScreen may say it "protected your PC", because the installer isn't code-signed.
   Click **More info** → **Run anyway** if the SHA-256 below matches your download
   (check with `Get-FileHash` in PowerShell).
3. Right-click any file or folder → **Lock with VaultKeep**.

Updating: run the new installer. Items that are open keep working. Uninstalling (Settings → Apps)
removes the right-click menu; your locked `.vkl` files and USB keys are not touched.
Keep the password: there is no password recovery.

SHA-256:
