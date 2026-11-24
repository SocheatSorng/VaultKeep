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

Write-Host 'Security key with a PIN'
# stdin for unlock/open: line 1 = item password, line 2 = key PIN.
function New-Stdin([string[]]$lines) {
    $f = Join-Path $t ('in-' + [Guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($f, ($lines -join "`r`n") + "`r`n", [Text.Encoding]::ASCII)
    return $f
}
function Get-KeyProtection([string]$keyPath) {
    $r = New-Object IO.BinaryReader([IO.File]::OpenRead($keyPath))
    try {
        $magic = [Text.Encoding]::ASCII.GetString($r.ReadBytes(6)); $null = $r.ReadBytes(16); $null = $r.ReadString()
        $null = $r.ReadBytes($r.ReadInt32()); $null = $r.ReadBytes($r.ReadInt32())
        return "$magic/$($r.ReadByte())"
    } finally { $r.Close() }
}
$usbP = Join-Path $t 'usb-pin'; New-Item -ItemType Directory $usbP | Out-Null
$r = Invoke-VaultKeep key-create $usbP (New-Stdin @('12345')) @('--with-pin')
Check ($r.Code -eq 1 -and -not (Test-Path (Join-Path $usbP '.vaultkeep\vaultkeep.vkkey'))) 'a PIN shorter than 6 characters is refused'
$r = Invoke-VaultKeep key-create $usbP (New-Stdin @('blue-42-sky')) @('--with-pin', '--label', 'PIN key')
$pinKey = Join-Path $usbP '.vaultkeep\vaultkeep.vkkey'
Check ($r.Code -eq 0 -and (Get-KeyProtection $pinKey) -eq 'VKKEY2/1') "key created with its private half PIN-encrypted $($r.Err)"

$item = Join-Path $t 'pin-item.txt'; Set-Content $item 'guarded by a PIN'
$null = Invoke-VaultKeep lock $item $pw
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1', 'blue-42-sky')) @('--key-dir', $usbP)
Check ($r.Code -eq 0 -and $r.Out -match "`tkey") 'key + right PIN opens it without the password'
$null = Invoke-VaultKeep lock $item $pw
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1', 'not-the-pin')) @('--key-dir', $usbP)
Check ($r.Code -eq 4 -and (Test-Path "$item.vkl")) 'key + wrong PIN does not open it'
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('correct-horse-9', 'not-the-pin')) @('--key-dir', $usbP)
Check ($r.Code -eq 0 -and $r.Out -match "`tpassword") 'wrong PIN falls back to the password'

$null = Invoke-VaultKeep lock $item $pw
$stolen = Join-Path $t 'stolen-copy'; New-Item -ItemType Directory $stolen | Out-Null
Copy-Item (Join-Path $usbP '.vaultkeep') $stolen -Recurse -Force
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1')) @('--key-dir', $stolen)
Check ($r.Code -eq 4 -and (Test-Path "$item.vkl")) 'a copied key file without the PIN opens nothing'

Write-Host 'Changing a PIN'
$r = Invoke-VaultKeep key-pin $usbP (New-Stdin @('not-the-pin', 'new-pin-77'))
Check ($r.Code -eq 4) 'changing the PIN needs the current PIN'
$r = Invoke-VaultKeep key-pin $usbP (New-Stdin @('blue-42-sky', 'new-pin-77'))
Check ($r.Code -eq 0 -and (Get-KeyProtection $pinKey) -eq 'VKKEY2/1') 'PIN changed'
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1', 'blue-42-sky')) @('--key-dir', $usbP)
Check ($r.Code -eq 4) 'the old PIN no longer works'
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1', 'new-pin-77')) @('--key-dir', $usbP)
Check ($r.Code -eq 0 -and $r.Out -match "`tkey") 'the new PIN works'

Write-Host 'Adding a PIN to a key that had none'
$usbN = Join-Path $t 'usb-nopin'; New-Item -ItemType Directory $usbN | Out-Null
$null = Invoke-VaultKeep key-create $usbN $null
$noPinKey = Join-Path $usbN '.vaultkeep\vaultkeep.vkkey'
Check ((Get-KeyProtection $noPinKey) -eq 'VKKEY2/0') 'key without a PIN'
$null = Invoke-VaultKeep lock $item $pw
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1')) @('--key-dir', $usbN)
Check ($r.Code -eq 0) 'a key without a PIN opens it on its own'
$null = Invoke-VaultKeep lock $item $pw
$r = Invoke-VaultKeep key-pin $usbN (New-Stdin @('', 'fresh-pin-1'))
Check ($r.Code -eq 0 -and (Get-KeyProtection $noPinKey) -eq 'VKKEY2/1') 'PIN added'
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1')) @('--key-dir', $usbN)
Check ($r.Code -eq 4) 'now it needs the PIN'
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1', 'fresh-pin-1')) @('--key-dir', $usbN)
Check ($r.Code -eq 0) '...and opens with it'

Write-Host 'Keys from VaultKeep 0.2 (VKKEY1) still work'
# Rebuild an old-format file from an unprotected key: VKKEY1 | id | label | modulus | exponent | 6 private parts.
$usbOld = Join-Path $t 'usb-old'; New-Item -ItemType Directory $usbOld | Out-Null
$null = Invoke-VaultKeep key-create $usbOld $null
$oldKey = Join-Path $usbOld '.vaultkeep\vaultkeep.vkkey'
$null = Invoke-VaultKeep lock $item $pw   # locked after the key is registered, so it has a slot for it
$bytes = [IO.File]::ReadAllBytes($oldKey)
$r2 = New-Object IO.BinaryReader((New-Object IO.MemoryStream(, $bytes)))
$null = $r2.ReadBytes(6); $null = $r2.ReadBytes(16); $null = $r2.ReadString()
$null = $r2.ReadBytes($r2.ReadInt32()); $null = $r2.ReadBytes($r2.ReadInt32())
$headerEnd = $r2.BaseStream.Position
$null = $r2.ReadByte(); $blobLen = $r2.ReadInt32(); $blob = $r2.ReadBytes($blobLen)
$v1 = [byte[]]([Text.Encoding]::ASCII.GetBytes('VKKEY1') + $bytes[6..($headerEnd - 1)] + $blob)
[IO.File]::WriteAllBytes($oldKey, $v1)
$r = Invoke-VaultKeep unlock "$item.vkl" (New-Stdin @('wrong-pass-1')) @('--key-dir', $usbOld)
Check ($r.Code -eq 0 -and $r.Out -match "`tkey") 'old key file (no PIN) still opens items'

Remove-Item -Recurse -Force $t
