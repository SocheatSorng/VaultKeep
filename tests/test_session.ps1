# "Open" sessions: the item is decrypted into VaultKeep's private workspace (never next to the .vkl, so sync
# apps don't upload an unlocked copy), stays open while in use, and is written back into the .vkl afterwards.
# Needs an interactive desktop (opens Notepad and File Explorer briefly), so it is not run in CI.
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$t = New-TestDir 'session'
$pw = New-PasswordFile $t 'correct-horse-9'
$recDir = Join-Path $env:VAULTKEEP_HOME 'open'
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

# Stands in for a Google Drive / OneDrive folder: it must never see an unlocked copy appear
# (checked directly with a file watcher in the last section).
$synced = Join-Path $t 'GoogleDrive'; New-Item -ItemType Directory $synced | Out-Null

Write-Host 'File held open by a program'
$file = Join-Path $synced 'diary.txt'; Set-Content $file 'day 1'
Check ((Invoke-VaultKeep lock $file $pw).Code -eq 0) 'lock file'
$p = Start-OpenSession "$file.vkl" $pw
$copy = Get-OpenCopy $p
Check ($null -ne $copy -and $copy.StartsWith((Get-WorkspaceRoot) + '\') -and (Test-Path $copy)) 'open decrypts into the private workspace'
Check ((Test-Path "$file.vkl") -and -not (Test-Path $file)) 'the .vkl stays; nothing unlocked appears next to it'
$null = Wait-Until { $null -ne (Get-Record $copy) } 10   # written when the session starts
$rec = Get-Record $copy
Check ($null -ne $rec) 'crash-recovery record written'
Check ($null -ne $rec -and -not [Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes($rec.FullName)).Contains('diary') -and
       -not [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($rec.FullName)).Contains('diary')) 'recovery record does not reveal the item name'
Add-Content $copy 'day 2 (edited while open)'
$h = [IO.File]::Open($copy, 'Open', 'ReadWrite', 'Read')
Start-Sleep 22
Check (Test-Path $copy) 'stays open while a program holds it'
$h.Close()
Check (Wait-Until { -not (Test-Path $copy) } 20) 'the open copy is removed after it is closed'
Check (Wait-Until { $p.HasExited } 10) 'session process exits'
Check ((Get-WorkspaceSessions).Count -eq 0) 'its private session folder is removed too'
Check ($null -eq (Get-Record $copy)) 'recovery record removed'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content $file -Raw) -match 'day 2') 'edits made while open were saved into the .vkl'

Write-Host 'File shown in Notepad (no handle kept)'
$null = Invoke-VaultKeep lock $file $pw
$p = Start-OpenSession "$file.vkl" $pw
$copy = Get-OpenCopy $p
$np = Start-Process notepad.exe -ArgumentList "`"$copy`"" -PassThru
Start-Sleep 22
Check (Test-Path $copy) 'stays open while shown in Notepad'
$np | Stop-Process
Check (Wait-Until { -not (Test-Path $copy) } 20) 're-locks after Notepad closes'
$null = Wait-Until { $p.HasExited } 10

Write-Host 'Folder shown in File Explorer'
$folder = Join-Path $synced 'Testing'; New-Item -ItemType Directory "$folder\2026" -Force | Out-Null; Set-Content "$folder\2026\a.txt" 'x'
Check ((Invoke-VaultKeep lock $folder $pw).Code -eq 0) 'lock folder'
$p = Start-OpenSession "$folder.vkl" $pw
$copy = Get-OpenCopy $p
Check ($null -ne $copy -and (Test-Path "$copy\2026\a.txt") -and -not (Test-Path $folder)) 'folder opens in the workspace, not next to the .vkl'
$shell = New-Object -ComObject Shell.Application
Start-Process explorer.exe -ArgumentList "`"$copy\2026`""
Start-Sleep 22
Check (Test-Path $copy) 'stays open while a subfolder is open in Explorer'
foreach ($w in @($shell.Windows())) {
    try { if ($w.LocationURL -and ([Uri]$w.LocationURL).LocalPath -like "$copy*") { $w.Quit() } } catch { }
}
Check (Wait-Until { -not (Test-Path $copy) } 20) 're-locks after the Explorer window closes'
$null = Wait-Until { $p.HasExited } 10
$r = Invoke-VaultKeep unlock "$folder.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content "$folder\2026\a.txt") -eq 'x') 'folder content intact in the .vkl'
$null = Invoke-VaultKeep lock $folder $pw

Write-Host 'Back and Up in File Explorer lead to the original folder'
function Get-ExplorerAt([string]$path) {
    foreach ($w in @($shell.Windows())) {
        try {
            if ($w.LocationURL -and ([Uri]$w.LocationURL).LocalPath.TrimEnd('\') -ieq $path.TrimEnd('\')) { return $w }
        } catch { }
    }
    return $null
}
# Explorer refuses a navigation while it is still busy with the previous one (HRESULT 0x800700AA): retry.
function Invoke-Explorer($window, [scriptblock]$action) {
    for ($i = 0; $i -lt 20; $i++) {
        try { & $action $window; return } catch { Start-Sleep -Milliseconds 250 }
    }
    & $action $window
}
Start-Process explorer.exe -ArgumentList "`"$synced`""
$null = Wait-Until { $null -ne (Get-ExplorerAt $synced) } 15
$win = Get-ExplorerAt $synced
$p = Start-OpenSession "$folder.vkl" $pw 0 @() -Launch   # like double-clicking Testing.vkl in that window
$copy = Get-OpenCopy $p
Check ($null -ne $copy -and (Wait-Until { $null -ne (Get-ExplorerAt $copy) } 15)) 'the folder opens in the same Explorer window'
Check ($null -ne $win -and (([Uri]$win.LocationURL).LocalPath.TrimEnd('\') -ieq $copy.TrimEnd('\'))) '...the very window the .vkl was double-clicked in'
function Get-WinPath { try { ([Uri]$win.LocationURL).LocalPath.TrimEnd('\') } catch { '' } }
Invoke-Explorer $win { param($w) $w.GoBack() }
Check (Wait-Until { (Get-WinPath) -ieq $synced } 10) 'Back returns to the original folder'
Start-Sleep 1
Invoke-Explorer $win { param($w) $w.Navigate2($copy) }
$null = Wait-Until { (Get-WinPath) -ieq $copy.TrimEnd('\') } 10
Start-Sleep 1
Invoke-Explorer $win { param($w) $w.Navigate2((Split-Path $copy)) }   # what the Up button does
Check (Wait-Until { (Get-WinPath) -ieq $synced } 10) 'Up into the private folder goes to the original folder instead'
Start-Sleep 1
Invoke-Explorer $win { param($w) $w.Navigate2((Get-WorkspaceRoot)) }
Check (Wait-Until { (Get-WinPath) -ieq $synced } 10) 'the workspace itself redirects to the original folder too'
Invoke-Explorer $win { param($w) $w.Quit() }
Check (Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 40) 're-locks after the window closes'

Write-Host 'Unused item'
$p = Start-OpenSession "$file.vkl" $pw
$copy = Get-OpenCopy $p
Check (Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 30) 're-locks by itself when nothing opens it'

Write-Host 'Opened but not changed: the .vkl is not rewritten'
function Get-VklState([string]$vkl) { (Get-FileHash $vkl).Hash + '|' + (Get-Item $vkl).LastWriteTimeUtc.Ticks }
$before = Get-VklState "$file.vkl"
$p = Start-OpenSession "$file.vkl" $pw
$copy = Get-OpenCopy $p
Check (Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 30) 'unchanged file: open copy removed on close'
Check ((Get-VklState "$file.vkl") -eq $before) 'unchanged file: .vkl left exactly as it was (not re-encrypted)'
Check ((Get-WorkspaceSessions).Count -eq 0) 'unchanged file: nothing left in the private folder'

$before = Get-VklState "$folder.vkl"
$p = Start-OpenSession "$folder.vkl" $pw
$copy = Get-OpenCopy $p
Check (Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 30) 'unchanged folder: open copy removed on close'
Check ((Get-VklState "$folder.vkl") -eq $before) 'unchanged folder: .vkl left exactly as it was'

Write-Host 'Edits that keep the same size are still saved'
$p = Start-OpenSession "$file.vkl" $pw
$copy = Get-OpenCopy $p
$text = Get-Content $copy -Raw
$same = ($text.ToCharArray() | ForEach-Object { if ($_ -eq 'd') { 'D' } else { $_ } }) -join ''
[IO.File]::WriteAllText($copy, $same)
Check ((Get-Item $copy).Length -eq [Text.Encoding]::UTF8.GetByteCount($text)) 'edit keeps the same size'
$null = Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 30
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content $file -Raw) -ceq $same) 'same-size edit was saved into the .vkl'
$null = Invoke-VaultKeep lock $file $pw

Write-Host 'Opening the same .vkl twice'
$p = Start-OpenSession "$file.vkl" $pw 0
$copy = Get-OpenCopy $p
$h = [IO.File]::Open($copy, 'Open', 'Read', 'Read')   # keep it "in use"
$p2 = Start-OpenSession "$file.vkl" $pw 0
$copy2 = Get-OpenCopy $p2
$p2.WaitForExit()
Check ($copy2 -eq $copy -and (Get-WorkspaceSessions).Count -eq 1) 'second open reuses the open copy (no second copy)'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 1 -and (Test-Path "$file.vkl") -and -not (Test-Path $file)) 'unlock permanently is refused while it is open'
$h.Close()
$null = Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 30

Write-Host 'Late save after re-lock (file)'
$p = Start-OpenSession "$file.vkl" $pw -GuardSeconds 60
$copy = Get-OpenCopy $p
Check (Wait-Until { -not (Test-Path $copy) } 30) 're-locked after use'
Check (-not $p.HasExited) 'keeps guarding after re-lock'
New-Item -ItemType Directory (Split-Path $copy) -Force | Out-Null
Set-Content $copy 'saved late by an app'
Check (Wait-Until { -not (Test-Path $copy) } 20) 'late save is locked again'
$p | Stop-Process -ErrorAction SilentlyContinue
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content $file) -eq 'saved late by an app') 'the late save was kept inside the .vkl'
$null = Invoke-VaultKeep lock $file $pw

Write-Host 'Wrong password'
$bad = New-PasswordFile $t 'nope-nope-1'
$before = (Get-WorkspaceSessions).Count
$p = Start-OpenSession "$file.vkl" $bad
$p.WaitForExit()
Check ($p.ExitCode -eq 4 -and (Test-Path "$file.vkl")) 'open with wrong password refused'
Check ((Get-WorkspaceSessions).Count -eq $before) 'no private session folder left behind'

Write-Host 'Synced folder during a whole open session'
Set-Content "$synced\notes.txt" 'private'
$null = Invoke-VaultKeep lock "$synced\notes.txt" $pw
$seen2 = New-Object System.Collections.Concurrent.ConcurrentBag[string]
$w2 = New-Object IO.FileSystemWatcher $synced
$w2.IncludeSubdirectories = $true; $w2.EnableRaisingEvents = $true
$s2 = @('Created', 'Renamed') | ForEach-Object {
    Register-ObjectEvent $w2 $_ -MessageData $seen2 -Action { $Event.MessageData.Add($Event.SourceEventArgs.Name) }
}
$p = Start-OpenSession "$synced\notes.txt.vkl" $pw
$copy = Get-OpenCopy $p
Add-Content $copy 'edited'
$null = Wait-Until { -not (Test-Path $copy) -and $p.HasExited } 40
Start-Sleep 1
$names = @($seen2.ToArray())
Check (@($names | Where-Object { $_ -eq 'notes.txt' }).Count -eq 0) "unlocked 'notes.txt' never appeared in the synced folder (saw: $($names -join ', '))"
# Allowed: the .vkl, VaultKeep's encrypted temp file, and Windows' own backup of the old .vkl made by
# ReplaceFile (notes.txt.vkl~RF*.TMP), which is the previous encrypted version.
$other = @($names | Where-Object { $_ -ne 'notes.txt.vkl' -and $_ -notlike '.notes.txt.vkl-*.tmp' -and $_ -notlike 'notes.txt.vkl~RF*.TMP' })
Check ($other.Count -eq 0) "only encrypted files changed there (unexpected: $($other -join ', '))"
$s2 | ForEach-Object { Unregister-Event -SourceIdentifier $_.Name }
$w2.Dispose()

Remove-Item -Recurse -Force $t
