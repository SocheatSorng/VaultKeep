# Shared helpers for VaultKeep tests. Dot-source this file.
# Tests drive bin\VaultKeep.exe in script mode (--password-stdin / --quiet), so no dialogs appear,
# and only ever touch throwaway data under tests\out\. VAULTKEEP_HOME points VaultKeep's own data
# (registered keys, crash-recovery records) at tests\out\home, and --no-drive-scan stops it from
# looking at real USB drives, so the user's real keys are never read or changed.
$ErrorActionPreference = 'Stop'
$script:Exe = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\VaultKeep.exe'
$script:Out = Join-Path $PSScriptRoot 'out'
$script:Failures = 0
$script:Passes = 0

if (-not (Test-Path $script:Exe)) { throw "Build first: $script:Exe not found (run .\build.ps1)" }

$script:VkHome = Join-Path $script:Out 'home'
if (Test-Path $script:VkHome) { Remove-Item -Recurse -Force $script:VkHome }
New-Item -ItemType Directory $script:VkHome -Force | Out-Null
$env:VAULTKEEP_HOME = $script:VkHome

function New-TestDir([string]$name) {
    $dir = Join-Path $script:Out $name
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory $dir | Out-Null
    return $dir
}

function New-PasswordFile([string]$dir, [string]$password) {
    $f = Join-Path $dir ('pw-' + [Guid]::NewGuid().ToString('N') + '.txt')
    Set-Content $f $password -Encoding ascii
    return $f
}

function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  PASS  $msg"; $script:Passes++ }
    else { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++ }
}

# Runs VaultKeep to completion. Returns @{ Code; Out; Err }.
# $passwordFile is fed to stdin (use an empty file when none is needed); $extra are more arguments.
function Invoke-VaultKeep([string]$verb, [string]$path, [string]$passwordFile, [string[]]$extra = @()) {
    $id = [Guid]::NewGuid().ToString('N')
    $o = Join-Path $script:Out "$id.out"; $e = Join-Path $script:Out "$id.err"
    if (-not $passwordFile) { $passwordFile = Join-Path $script:Out "$id.in"; Set-Content $passwordFile '' }
    $argList = @($verb, "`"$path`"", '--password-stdin', '--no-drive-scan') + ($extra | ForEach-Object { "`"$_`"" })
    $p = Start-Process $script:Exe -ArgumentList $argList `
        -RedirectStandardInput $passwordFile -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -NoNewWindow
    $null = $p.Handle  # keeps the handle so ExitCode is available after exit
    $p.WaitForExit()
    $r = @{ Code = $p.ExitCode; Out = (Get-Content $o -Raw); Err = (Get-Content $e -Raw) }
    Remove-Item $o, $e, (Join-Path $script:Out "$id.in") -ErrorAction SilentlyContinue
    return $r
}

# Starts an "open" session in the background (no app is launched). Returns the Process.
# GuardSeconds: how long the session keeps watching for late saves after re-locking (0 = exit at once).
function Start-OpenSession([string]$vkl, [string]$passwordFile, [int]$GuardSeconds = 0, [string[]]$extra = @()) {
    $id = [Guid]::NewGuid().ToString('N')
    $argList = @('open', "`"$vkl`"", '--password-stdin', '--no-drive-scan', '--no-launch', '--guard-seconds', $GuardSeconds) +
        ($extra | ForEach-Object { "`"$_`"" })
    $p = Start-Process $script:Exe -ArgumentList $argList `
        -RedirectStandardInput $passwordFile -RedirectStandardOutput (Join-Path $script:Out "$id.out") `
        -RedirectStandardError (Join-Path $script:Out "$id.err") -PassThru
    $null = $p.Handle
    return $p
}

function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $seconds) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-TreeHashes([string]$dir) {
    Get-ChildItem $dir -Recurse -File | Sort-Object FullName | ForEach-Object {
        $_.FullName.Substring($dir.Length) + '=' + (Get-FileHash $_.FullName).Hash
    }
}
