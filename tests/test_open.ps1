# Opening: an edit made as soon as the open copy appears is never mistaken for "unchanged" and lost.
# The session fingerprints the copy to skip re-locking unchanged items; that fingerprint must be taken
# before the copy is announced or launched. --start-delay-ms (test build) widens the gap between the
# announcement and the session starting, so a late fingerprint would include the edit and drop it.
# Headless: nothing is launched.
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$t = New-TestDir 'open'
$pw = New-PasswordFile $t 'correct-horse-9'
$file = Join-Path $t 'notes.txt'
Set-Content $file 'original' -Encoding ascii

Write-Host 'Edit right after the copy appears'
$null = Invoke-VaultKeep lock $file $pw
$p = Start-OpenSession "$file.vkl" $pw 0 @('--start-delay-ms', '2500')
$copy = Get-OpenCopy $p
Check ($null -ne $copy -and (Test-Path $copy)) 'open copy announced'
Add-Content $copy 'edited'
Check (Wait-Until { (Test-Path "$file.vkl") -and -not (Test-Path $copy) -and $p.HasExited } 40) 're-locked after use'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content $file -Raw) -match 'edited') 'the early edit is in the .vkl'
