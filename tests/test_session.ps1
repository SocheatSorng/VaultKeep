# "Open" sessions: item stays unlocked while in use and re-locks after it's closed.
# Needs an interactive desktop (opens Notepad and File Explorer briefly), so it is not run in CI.
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$t = New-TestDir 'session'
$pw = New-PasswordFile $t 'correct-horse-9'
$recDir = Join-Path $env:LOCALAPPDATA 'VaultKeep\open'
Add-Type -AssemblyName System.Security
# Records are DPAPI-encrypted; decrypt them the same way VaultKeep does to find ours.
function Get-Record([string]$path) {
    $entropy = [Text.Encoding]::ASCII.GetBytes('VaultKeep recovery v1')
    Get-ChildItem $recDir -Filter *.rec -ErrorAction SilentlyContinue | Where-Object {
        try {
            $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($_.FullName), $entropy, 'CurrentUser')
            ([Text.Encoding]::UTF8.GetString($plain) -split "`n")[1] -eq $path
        } catch { $false }
    }
}

Write-Host 'File held open by a program'
$file = Join-Path $t 'diary.txt'; Set-Content $file 'day 1'
Check ((Invoke-VaultKeep lock $file $pw).Code -eq 0) 'lock file'
$p = Start-OpenSession "$file.vkl" $pw
Check (Wait-Until { Test-Path $file } 10) 'open restores the file in place'
$rec = Get-Record $file
Check ($null -ne $rec) 'crash-recovery record written'
Check ($null -ne $rec -and -not [Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes($rec.FullName)).Contains('diary') -and
       -not [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($rec.FullName)).Contains('diary')) 'recovery record does not reveal the item name'
Add-Content $file 'day 2 (edited while open)'
$h = [IO.File]::Open($file, 'Open', 'ReadWrite', 'Read')
Start-Sleep 22
Check ((Test-Path $file) -and -not (Test-Path "$file.vkl")) 'stays unlocked while a program holds it'
$h.Close()
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $file) } 20) 're-locks after it is closed'
Check (Wait-Until { $p.HasExited } 10) 'session process exits'
Check ($null -eq (Get-Record $file)) 'recovery record removed'
Check ((Invoke-VaultKeep unlock "$file.vkl" $pw).Code -eq 0 -and (Get-Content $file -Raw) -match 'day 2') 'edits made while open are kept'

Write-Host 'File shown in Notepad (no handle kept)'
$null = Invoke-VaultKeep lock $file $pw
$p = Start-OpenSession "$file.vkl" $pw
$null = Wait-Until { Test-Path $file } 10
$np = Start-Process notepad.exe -ArgumentList "`"$file`"" -PassThru
Start-Sleep 22
Check ((Test-Path $file) -and -not (Test-Path "$file.vkl")) 'stays unlocked while open in Notepad'
$np | Stop-Process
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $file) } 20) 're-locks after Notepad closes'
$null = Wait-Until { $p.HasExited } 10

Write-Host 'Folder shown in File Explorer'
$folder = Join-Path $t 'Photos'; New-Item -ItemType Directory "$folder\2026" -Force | Out-Null; Set-Content "$folder\2026\a.txt" 'x'
Check ((Invoke-VaultKeep lock $folder $pw).Code -eq 0) 'lock folder'
$p = Start-OpenSession "$folder.vkl" $pw
$null = Wait-Until { Test-Path $folder } 10
$shell = New-Object -ComObject Shell.Application
Start-Process explorer.exe -ArgumentList "`"$folder\2026`""
Start-Sleep 22
Check ((Test-Path $folder) -and -not (Test-Path "$folder.vkl")) 'stays unlocked while a subfolder is open in Explorer'
foreach ($w in @($shell.Windows())) {
    try { if ($w.LocationURL -and ([Uri]$w.LocationURL).LocalPath -like "$folder*") { $w.Quit() } } catch { }
}
Check (Wait-Until { (Test-Path "$folder.vkl") -and -not (Test-Path $folder) } 20) 're-locks after the Explorer window closes'
$null = Wait-Until { $p.HasExited } 10

Write-Host 'Unused item'
$p = Start-OpenSession "$file.vkl" $pw
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $file) -and $p.HasExited } 30) 're-locks by itself when nothing opens it'

Write-Host 'Stale .vkl left next to the opened item'
# Simulates the .vkl not being deletable when opened (e.g. antivirus scanning it).
Copy-Item "$file.vkl" "$t\backup.vkl"
$p = Start-OpenSession "$file.vkl" $pw
$null = Wait-Until { Test-Path $file } 10
Set-Content $file 'version 3'
Copy-Item "$t\backup.vkl" "$file.vkl"
Check (Wait-Until { -not (Test-Path $file) -and $p.HasExited } 30) 're-locks even though an old .vkl is in the way'
Check ((Invoke-VaultKeep unlock "$file.vkl" $pw).Code -eq 0 -and (Get-Content $file) -eq 'version 3') 'the newest content won (stale copy replaced)'
Check ($null -eq (Get-ChildItem $t -Force -Filter '*.tmp')) 'no temp files left'

Write-Host 'Late save after re-lock (file)'
$null = Invoke-VaultKeep lock $file $pw
$p = Start-OpenSession "$file.vkl" $pw -GuardSeconds 60
$null = Wait-Until { Test-Path $file } 10
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $file) } 30) 're-locked after use'
Check (-not $p.HasExited) 'keeps guarding after re-lock'
Set-Content $file 'saved late by an app'
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $file) } 20) 'late save is locked again'
Check ((Invoke-VaultKeep unlock "$file.vkl" $pw).Code -eq 0 -and (Get-Content $file) -eq 'saved late by an app') 'the late save was kept inside the .vkl'
$p | Stop-Process -ErrorAction SilentlyContinue
$null = Invoke-VaultKeep lock $file $pw

Write-Host 'Wrong password'
$bad = New-PasswordFile $t 'nope-nope-1'
$p = Start-OpenSession "$file.vkl" $bad
$p.WaitForExit()
Check ($p.ExitCode -eq 4 -and (Test-Path "$file.vkl")) 'open with wrong password refused'

Remove-Item -Recurse -Force $t
