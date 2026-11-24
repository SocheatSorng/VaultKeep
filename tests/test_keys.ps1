# USB security keys: a key opens items without the password, the password always still works,
# removed keys stop being added, and items opened with a key keep their password. Headless (CI-safe).
# "Drives" are plain folders under tests\out passed with --key-dir; real drives are never scanned.
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$t = New-TestDir 'keys'
$pw = New-PasswordFile $t 'correct-horse-9'
$bad = New-PasswordFile $t 'wrong-pass-1'
$usb1 = Join-Path $t 'usb1'; $usb2 = Join-Path $t 'usb2'
New-Item -ItemType Directory $usb1, $usb2 | Out-Null

function Get-SlotCount([string]$vkl) { ([IO.File]::ReadAllBytes($vkl))[6] }

Write-Host 'Create keys'
$r = Invoke-VaultKeep key-create $usb1 $null @('--label', 'Blue USB')
Check ($r.Code -eq 0) "key-create exits 0 $($r.Err)"
$id1 = $r.Out.Trim()
$keyFile = Join-Path $usb1 '.vaultkeep\vaultkeep.vkkey'
Check (Test-Path $keyFile) 'key file written to the drive'
Check (((Get-Item (Join-Path $usb1 '.vaultkeep') -Force).Attributes -band [IO.FileAttributes]::Hidden) -ne 0) 'key folder is hidden'
$r = Invoke-VaultKeep key-list x $null
Check ($r.Out -match [regex]::Escape($id1) -and $r.Out -match 'Blue USB') 'key registered on this PC'
$r = Invoke-VaultKeep key-create $usb1 $null
Check ($r.Code -eq 1) 'creating a second key on the same drive is refused'

Write-Host 'Drive paths as Explorer passes them'
# Runs VaultKeep with a raw command line (no extra quoting), like Explorer's right-click command does.
function Invoke-Raw([string]$commandLine) {
    $p = Start-Process $script:Exe -ArgumentList $commandLine -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $script:Out 'raw.out') -RedirectStandardError (Join-Path $script:Out 'raw.err')
    $null = $p.Handle; $p.WaitForExit(); return $p.ExitCode
}
# Old registry command: key-create "%1" -> "X:\" -> the program received X:" (Illegal characters in path).
$usbQ = Join-Path $t 'usbquoted'; New-Item -ItemType Directory $usbQ | Out-Null
$code = Invoke-Raw "key-create --quiet --no-drive-scan --label Quoted `"$usbQ\`""
Check ($code -eq 0 -and (Test-Path (Join-Path $usbQ '.vaultkeep\vaultkeep.vkkey'))) 'quoted path ending in \ (escaped quote) works'
# Current registry command: key-create %1 -> X:\ unquoted.
$usbU = Join-Path $t 'usbunquoted'; New-Item -ItemType Directory $usbU | Out-Null
$code = Invoke-Raw "key-create $usbU\ --quiet --no-drive-scan --label Unquoted"
Check ($code -eq 0 -and (Test-Path (Join-Path $usbU '.vaultkeep\vaultkeep.vkkey'))) 'unquoted path ending in \ works'
foreach ($idLine in (Invoke-VaultKeep key-list x $null).Out -split "`r?`n") {
    if ($idLine -match '^(\w+)\t(Quoted|Unquoted)$') { $null = Invoke-VaultKeep key-remove $Matches[1] $null }
}

Write-Host 'Key opens items; password still works'
$file = Join-Path $t 'secret.txt'; Set-Content $file 'top secret'
Check ((Invoke-VaultKeep lock $file $pw).Code -eq 0) 'lock'
Check ((Get-SlotCount "$file.vkl") -eq 2) '.vkl has a password slot and a key slot'
$r = Invoke-VaultKeep unlock "$file.vkl" $bad @('--key-dir', $usb1)
Check ($r.Code -eq 0 -and $r.Out -match "`tkey" -and (Get-Content $file) -eq 'top secret') 'key plugged in: opens without the password'
$null = Invoke-VaultKeep lock $file $pw
$r = Invoke-VaultKeep unlock "$file.vkl" $bad
Check ($r.Code -eq 4 -and (Test-Path "$file.vkl")) 'key not plugged in: wrong password still refused'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and $r.Out -match "`tpassword") 'key not plugged in: password works'

Write-Host "Someone else's USB drive can't open your items"
$null = Invoke-VaultKeep lock $file $pw
# Another person makes a VaultKeep key with their own copy of VaultKeep (their own key list).
$theirHome = Join-Path $t 'their-pc'; $theirUsb = Join-Path $t 'their-usb'
New-Item -ItemType Directory $theirHome, $theirUsb | Out-Null
$env:VAULTKEEP_HOME = $theirHome
$null = Invoke-VaultKeep key-create $theirUsb $null @('--label', 'Not yours')
$env:VAULTKEEP_HOME = $script:VkHome
$r = Invoke-VaultKeep unlock "$file.vkl" $bad @('--key-dir', $theirUsb)
Check ($r.Code -eq 4 -and (Test-Path "$file.vkl") -and -not (Test-Path $file)) 'a key made elsewhere cannot open it'
# They copy your key's ID (visible in the .vkl) into their key file to impersonate your key.
$forged = Join-Path $t 'forged-usb'; New-Item -ItemType Directory "$forged\.vaultkeep" -Force | Out-Null
$theirKey = [IO.File]::ReadAllBytes((Join-Path $theirUsb '.vaultkeep\vaultkeep.vkkey'))
$yourKey = [IO.File]::ReadAllBytes($keyFile)
[Array]::Copy($yourKey, 6, $theirKey, 6, 16)   # magic(6) | key id(16) | ...
[IO.File]::WriteAllBytes("$forged\.vaultkeep\vaultkeep.vkkey", $theirKey)
$r = Invoke-VaultKeep unlock "$file.vkl" $bad @('--key-dir', $forged)
Check ($r.Code -eq 4 -and (Test-Path "$file.vkl") -and -not (Test-Path $file)) 'a forged key with your key ID cannot open it'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw @('--key-dir', $forged)
Check ($r.Code -eq 0 -and $r.Out -match "`tpassword") 'with a forged key plugged in, your password still works'
# The real app has no silent way to add a key: it needs Windows sign-in (the window / right-click).
$sneaky = Join-Path $t 'sneaky-usb'; New-Item -ItemType Directory $sneaky | Out-Null
$p = Start-Process $script:RealExe -ArgumentList 'key-create', "`"$sneaky`"", '--quiet' -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $script:Out 'real.out') -RedirectStandardError (Join-Path $script:Out 'real.err')
$null = $p.Handle; $p.WaitForExit()
Check ($p.ExitCode -eq 1 -and -not (Test-Path (Join-Path $sneaky '.vaultkeep'))) 'real app refuses to add a key without Windows sign-in'

Write-Host 'Two keys (main + backup)'
$r = Invoke-VaultKeep key-create $usb2 $null @('--label', 'Backup USB')
$id2 = $r.Out.Trim()
$null = Invoke-VaultKeep lock $file $pw
Check ((Get-SlotCount "$file.vkl") -eq 3) 'new items get a slot for each key'
$r = Invoke-VaultKeep unlock "$file.vkl" $bad @('--key-dir', $usb2)
Check ($r.Code -eq 0) 'backup key opens it on its own'

Write-Host 'Opened with a key, re-locked: password and keys still work'
$null = Invoke-VaultKeep lock $file $pw
$p = Start-OpenSession "$file.vkl" $bad 0 @('--key-dir', $usb1)
$copy = Get-OpenCopy $p
Check ($null -ne $copy -and (Test-Path $copy)) 'open with key restores the item (in the private workspace)'
Add-Content $copy 'edited'
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $copy) -and $p.HasExited } 40) 're-locked after use'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content $file -Raw) -match 'edited') 'password still opens it after a key-only session'
$null = Invoke-VaultKeep lock $file $pw

Write-Host 'Removing a key'
$r = Invoke-VaultKeep key-remove $id1 $null
Check ($r.Code -eq 0) 'key-remove exits 0'
$other = Join-Path $t 'new.txt'; Set-Content $other 'new'
$null = Invoke-VaultKeep lock $other $pw
Check ((Get-SlotCount "$other.vkl") -eq 2) 'items locked after removal have no slot for it'
$r = Invoke-VaultKeep unlock "$other.vkl" $bad @('--key-dir', $usb1)
Check ($r.Code -eq 4) 'removed key cannot open new items'
$p = Start-OpenSession "$file.vkl" $pw 0
$null = Get-OpenCopy $p
Check (Wait-Until { (Test-Path "$file.vkl") -and $p.HasExited } 40) 'older item re-locked after opening'
Check ((Get-SlotCount "$file.vkl") -eq 2) 're-lock dropped the removed key slot'
$r = Invoke-VaultKeep unlock "$file.vkl" $bad @('--key-dir', $usb1)
Check ($r.Code -eq 4) 'removed key no longer opens the re-locked item'

Write-Host 'Old items get key slots when re-locked'
Set-Content "$t\plain.txt" 'before keys'
Remove-Item (Join-Path $env:VAULTKEEP_HOME 'keys.dat')
$null = Invoke-VaultKeep lock "$t\plain.txt" $pw
Check ((Get-SlotCount "$t\plain.txt.vkl") -eq 1) 'locked with no keys: password slot only'
$usb3 = Join-Path $t 'usb3'; New-Item -ItemType Directory $usb3 | Out-Null
$null = Invoke-VaultKeep key-create $usb3 $null
$p = Start-OpenSession "$t\plain.txt.vkl" $pw 0
$null = Get-OpenCopy $p
$null = Wait-Until { (Test-Path "$t\plain.txt.vkl") -and $p.HasExited } 40
$r = Invoke-VaultKeep unlock "$t\plain.txt.vkl" $bad @('--key-dir', $usb3)
Check ($r.Code -eq 0) 'item locked before the key existed opens with it after one use'

Write-Host 'Damaged keys and tampering'
$null = Invoke-VaultKeep lock "$t\plain.txt" $pw
$broken = Join-Path $t 'broken'; New-Item -ItemType Directory "$broken\.vaultkeep" -Force | Out-Null
[IO.File]::WriteAllBytes("$broken\.vaultkeep\vaultkeep.vkkey", [byte[]](1..50))
$r = Invoke-VaultKeep unlock "$t\plain.txt.vkl" $pw @('--key-dir', $broken)
Check ($r.Code -eq 0 -and $r.Out -match "`tpassword") 'damaged key file is ignored, password works'
$null = Invoke-VaultKeep lock "$t\plain.txt" $pw
$raw = [IO.File]::ReadAllBytes("$t\plain.txt.vkl")
$raw[200] = $raw[200] -bxor 1   # inside the key slot
[IO.File]::WriteAllBytes("$t\plain.txt.vkl", $raw)
$r = Invoke-VaultKeep unlock "$t\plain.txt.vkl" $pw
Check ($r.Code -eq 4 -and -not (Test-Path "$t\plain.txt")) 'tampered key slot: file rejected even with the right password'

Remove-Item -Recurse -Force $t
