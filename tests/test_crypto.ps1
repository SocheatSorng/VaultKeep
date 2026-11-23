# Lock / unlock round trips, wrong passwords, tampering and safety checks. Runs headless (CI-safe).
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$t = New-TestDir 'crypto'
$pw = New-PasswordFile $t 'correct-horse-9'
$bad = New-PasswordFile $t 'wrong-pass-1'

Write-Host 'Folder round trip'
$folder = Join-Path $t 'My Secrets'
New-Item -ItemType Directory "$folder\sub\deeper" -Force | Out-Null
New-Item -ItemType Directory "$folder\empty" | Out-Null
Set-Content "$folder\note.txt" 'hello vault'
Set-Content "$folder\sub\$([char]0x1781)$([char]0x17D2)$([char]0x1798)$([char]0x17C2)$([char]0x179A).txt" 'unicode name'
$bytes = New-Object byte[] (3MB + 17); (New-Object Random 42).NextBytes($bytes)
[IO.File]::WriteAllBytes("$folder\sub\deeper\blob.bin", $bytes)
Set-Content "$folder\ro.txt" 'read only'; Set-ItemProperty "$folder\ro.txt" IsReadOnly $true
$before = Get-TreeHashes $folder

$r = Invoke-VaultKeep lock $folder $pw
Check ($r.Code -eq 0) "lock folder exits 0 $($r.Err)"
Check (-not (Test-Path $folder)) 'original folder removed'
Check (Test-Path "$folder.vkl") '.vkl created'
$raw = [IO.File]::ReadAllBytes("$folder.vkl")
Check (-not [Text.Encoding]::UTF8.GetString($raw).Contains('hello vault')) 'no plaintext inside .vkl'
# v3: magic(4) version(1) kind(1) slots(1) | password slot: type(1) len(2) iterations(4) ...
Check ($raw[4] -eq 3 -and $raw[6] -eq 1 -and $raw[7] -eq 1 -and [BitConverter]::ToInt32($raw, 10) -eq 600000) 'format v3, one password slot with 600,000 PBKDF2 rounds'
Check ($null -eq (Get-ChildItem $t -Force -Filter '*.tmp')) 'no temp file left after lock'

$r = Invoke-VaultKeep unlock "$folder.vkl" $bad
Check ($r.Code -eq 4) "wrong password rejected (exit $($r.Code))"
Check ((Test-Path "$folder.vkl") -and -not (Test-Path $folder)) '.vkl untouched after wrong password'

$r = Invoke-VaultKeep unlock "$folder.vkl" $pw
Check ($r.Code -eq 0) "unlock folder exits 0 $($r.Err)"
Check (-not (Test-Path "$folder.vkl")) '.vkl removed after unlock'
Check (Test-Path "$folder\empty") 'empty subfolder restored'
$after = Get-TreeHashes $folder
Check ($null -eq (Compare-Object $before $after)) "all $($after.Count) files identical"
Check ($null -eq (Get-ChildItem $t -Force | Where-Object Name -like '*.vkpart*')) 'no temp leftovers'

Write-Host 'Single file round trip'
$file = Join-Path $t 'report.pdf'
[IO.File]::WriteAllBytes($file, $bytes[0..99999])
$hash = (Get-FileHash $file).Hash; $mtime = (Get-Item $file).LastWriteTimeUtc
$r = Invoke-VaultKeep lock $file $pw
Check ($r.Code -eq 0 -and -not (Test-Path $file) -and (Test-Path "$file.vkl")) 'lock file'
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 0 -and (Get-FileHash $file).Hash -eq $hash) 'unlock file, content identical'
Check ((Get-Item $file).LastWriteTimeUtc -eq $mtime) 'modified time preserved'

Write-Host 'Empty file'
$empty = Join-Path $t 'empty.txt'; New-Item -ItemType File $empty | Out-Null
$r = Invoke-VaultKeep lock $empty $pw
$r2 = Invoke-VaultKeep unlock "$empty.vkl" $pw
Check ($r.Code -eq 0 -and $r2.Code -eq 0 -and (Get-Item $empty).Length -eq 0) 'empty file round trip'

Write-Host 'Version 1 files still open'
# Build a v1 file independently with .NET's managed PBKDF2 (64-byte key). VaultKeep reads it with
# native CNG PBKDF2, so this also proves both implementations agree.
function New-V1File([string]$path, [string]$name, [byte[]]$content, [string]$password) {
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($salt); $rng.GetBytes($iv)
    $iter = 10000
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes(([Text.Encoding]::UTF8.GetBytes($password)), $salt, $iter, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(64); $enc = $key[0..31]; $mac = $key[32..63]
    $ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter($ms, [Text.Encoding]::UTF8)
    $w.Write($name); $w.Write([long](Get-Date).ToUniversalTime().Ticks); $w.Write([long]$content.Length); $w.Write($content); $w.Flush()
    $aes = New-Object Security.Cryptography.AesCryptoServiceProvider; $aes.Key = $enc; $aes.IV = $iv
    $plain = $ms.ToArray(); $cipher = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
    $header = [byte[]](0x56, 0x4B, 0x4C, 0x31, 1, 0) + [BitConverter]::GetBytes([int]$iter) + $salt + $iv
    $body = [byte[]]($header + $cipher)
    $tag = (New-Object Security.Cryptography.HMACSHA256(, $mac)).ComputeHash($body)
    [IO.File]::WriteAllBytes($path, [byte[]]($body + $tag))
}
New-V1File "$t\legacy.txt.vkl" 'legacy.txt' ([Text.Encoding]::UTF8.GetBytes('made by v1')) 'correct-horse-9'
$r = Invoke-VaultKeep unlock "$t\legacy.txt.vkl" $pw
Check ($r.Code -eq 0 -and (Get-Content "$t\legacy.txt") -eq 'made by v1') "v1 file unlocks with the right password $($r.Err)"
New-V1File "$t\legacy2.txt.vkl" 'legacy2.txt' ([byte[]](1, 2, 3)) 'correct-horse-9'
$r = Invoke-VaultKeep unlock "$t\legacy2.txt.vkl" $bad
Check ($r.Code -eq 4) 'v1 file rejects a wrong password'

Write-Host 'Tamper detection'
$r = Invoke-VaultKeep lock $file $pw
$raw = [IO.File]::ReadAllBytes("$file.vkl"); $raw[100] = $raw[100] -bxor 1; [IO.File]::WriteAllBytes("$file.vkl", $raw)
$r = Invoke-VaultKeep unlock "$file.vkl" $pw
Check ($r.Code -eq 4 -and -not (Test-Path $file)) 'modified .vkl rejected, nothing written'
[IO.File]::WriteAllBytes("$t\junk.vkl", [byte[]](1..10))
$r = Invoke-VaultKeep unlock "$t\junk.vkl" $pw
Check ($r.Code -eq 1) 'non-VaultKeep file rejected'

Write-Host 'Safety checks'
Set-Content "$t\dup.txt" 'a'; $null = Invoke-VaultKeep lock "$t\dup.txt" $pw; Set-Content "$t\dup.txt" 'b'
$r = Invoke-VaultKeep unlock "$t\dup.txt.vkl" $pw
Check ($r.Code -eq 1 -and (Get-Content "$t\dup.txt") -eq 'b' -and (Test-Path "$t\dup.txt.vkl")) 'unlock never overwrites an existing item'
Set-Content "$t\x.txt" 'x'; $short = New-PasswordFile $t 'abcd123'
$r = Invoke-VaultKeep lock "$t\x.txt" $short
Check ($r.Code -eq 1 -and (Test-Path "$t\x.txt")) 'password shorter than 8 characters refused'
Set-Content "$t\stale.txt" 'new'; Copy-Item "$t\dup.txt.vkl" "$t\stale.txt.vkl"
$r = Invoke-VaultKeep lock "$t\stale.txt" $pw
Check ($r.Code -eq 1 -and (Get-Content "$t\stale.txt") -eq 'new') 'plain lock never overwrites an existing .vkl'
$r = Invoke-VaultKeep lock "$t\x.txt" $pw
$r = Invoke-VaultKeep lock "$t\x.txt.vkl" $pw
Check ($r.Code -eq 1 -and (Test-Path "$t\x.txt.vkl")) 'locking an already-locked file refused'
Set-Content "$t\busy.txt" 'busy'
$h = [IO.File]::Open("$t\busy.txt", 'Open', 'Read', 'None')
try {
    $r = Invoke-VaultKeep lock "$t\busy.txt" $pw
    Check ($r.Code -ne 0 -and -not (Test-Path "$t\busy.txt.vkl")) 'file in use by another program: lock fails cleanly'
} finally { $h.Close() }
Check ((Get-Content "$t\busy.txt") -eq 'busy') 'original intact after failed lock'

Remove-Item -Recurse -Force $t
