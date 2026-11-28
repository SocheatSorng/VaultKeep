# Release safety: the installer ships only the real app (never the TESTHOOKS build), registers and removes
# the menu silently, never closes a running VaultKeep, and the release workflow is pinned, tests before it
# publishes, and checks the tag against the version. Static checks plus the built exe's version. Headless.
. (Join-Path $PSScriptRoot 'TestLib.ps1')
$repo = Split-Path $PSScriptRoot -Parent
$iss = Get-Content (Join-Path $repo 'installer.iss') -Raw
$wf = Get-Content (Join-Path $repo '.github\workflows\release.yml') -Raw
$program = Get-Content (Join-Path $repo 'src\Program.cs') -Raw
$readme = Get-Content (Join-Path $repo 'README.md') -Raw

Write-Host 'Version'
$versions = @('AssemblyVersion', 'AssemblyFileVersion', 'AssemblyInformationalVersion') | ForEach-Object {
    if ($program -match ($_ + '\("(\d+\.\d+\.\d+)(\.0)?"\)')) { $Matches[1] } else { "missing $_" }
}
Check (@($versions | Select-Object -Unique).Count -eq 1 -and $versions[0] -match '^\d+\.\d+\.\d+$') "the three version attributes agree ($($versions -join ', '))"
$fileVersion = (Get-Item $script:RealExe).VersionInfo.FileVersion
Check ($fileVersion -eq "$($versions[0]).0") "bin\VaultKeep.exe has file version $($versions[0]).0 (got $fileVersion)"

Write-Host 'Installer script'
$sources = [regex]::Matches($iss, '(?m)^Source:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
Check ($sources.Count -gt 0) 'installer.iss has [Files] entries'
Check (-not ($sources | Where-Object { $_ -notin @('bin\VaultKeep.exe', 'LICENSE') })) "ships only bin\VaultKeep.exe and LICENSE (got: $($sources -join ', '))"
$issCode = ($iss -split "`n" | Where-Object { $_ -notmatch '^\s*;' }) -join "`n"
Check ($issCode -notmatch '(?i)bin\\test') 'never references the test build (bin\test) outside comments'
Check ($iss -match '(?m)^PrivilegesRequired=lowest\s*$') 'installs per user, no admin rights'
Check ($iss -match '(?m)^CloseApplications=no\s*$') 'never closes a running VaultKeep (an item may be open)'
Check ($iss -match 'Parameters: "install --quiet"') 'runs "install --quiet" after installing'
Check ($iss -match '(?s)\[UninstallRun\].*Parameters: "uninstall --quiet"') 'runs "uninstall --quiet" when uninstalling'
Check ($iss -match 'function InitializeUninstall') 'uninstall refuses while VaultKeep is running'
Check ($iss -notmatch '(?i)WbemScripting|Win32_Process') 'running check does not depend on WMI'
Check ($iss -match '(?s)function ExeInUse.*except\s+Result := True;') 'running check fails closed (an error counts as in use)'
Check ($iss -notmatch '(?i)\{localappdata\}\\VaultKeep|DelTree|filesandordirs') 'never deletes VaultKeep''s data folder or whole folders'

Write-Host '--quiet install/uninstall (installer runs them hidden)'
foreach ($cmd in 'install', 'uninstall') {
    Check ($program -match "(?s)case ""$cmd"":\s*Shell\.\w+\(\);\s*if \(!quiet\) Info\(") "$cmd shows no message with --quiet"
}

Write-Host 'Release workflow'
$uses = [regex]::Matches($wf, '(?m)^\s*(?:-\s*)?uses:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value }
Check (-not ($uses | Where-Object { $_ -notmatch '@[0-9a-f]{40}$' })) 'every action is pinned to a full commit SHA'
Check ($wf -match '(?m)^permissions: \{\}\s*$') 'workflow-level permissions are empty'
Check ($wf -match 'persist-credentials: false') 'checkout does not keep the token'
Check ($wf -match 'step-security/harden-runner') 'harden-runner is used'
Check ($wf -notmatch '(?m)^\s*run:.*\$\{\{') 'no ${{ }} expressions inside run scripts (template injection)'
$iTag = $wf.IndexOf('does not match the app version'); $iTest = $wf.IndexOf('.\test.ps1'); $iPub = $wf.IndexOf('gh release create')
Check ($iTag -ge 0 -and $iTest -gt $iTag -and $iPub -gt $iTest) 'checks the tag, then tests, then publishes'
Check ($wf -match '\.\\build\.ps1 -Installer') 'builds the installer with build.ps1 -Installer'
Check ($wf -match 'merge-base --is-ancestor \$env:GITHUB_SHA origin/main') 'only releases commits that are on main'
$jobs = $wf -split '(?m)^  publish:'
Check ($jobs.Count -eq 2 -and $jobs[0] -notmatch 'contents: write' -and $jobs[1] -match 'contents: write') 'only the publish job can write'
Check ($jobs.Count -eq 2 -and $jobs[1] -notmatch '\.ps1|actions/checkout') 'the publish job runs no repo scripts'
Check ($wf -notmatch 'Get-Content|Set-Content') 'release notes are read/written as UTF-8 (not PS 5.1 Get/Set-Content)'

Write-Host 'Docs'
Check (Test-Path (Join-Path $repo 'LICENSE')) 'LICENSE exists'
Check ($readme -match 'releases/latest' -and $readme -match 'build\.ps1 -Installer') 'README explains downloading and building the installer'
