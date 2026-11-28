; VaultKeep installer (Inno Setup 6). Built by `.\build.ps1 -Installer`:
;   iscc /DAppVersion=1.0.0 installer.iss  ->  dist\VaultKeep-Setup-1.0.0.exe
;
; Installs for the current user only (no administrator rights) into %LOCALAPPDATA%\Programs\VaultKeep,
; then runs `VaultKeep.exe install --quiet` to add the right-click menu (HKCU only). The uninstaller runs
; `VaultKeep.exe uninstall --quiet` first. Locked .vkl files, security keys and VaultKeep's data folder
; (%LOCALAPPDATA%\VaultKeep: registered keys, workspace, crash-recovery notes) are never touched.
;
; Only the real app (bin\VaultKeep.exe) is shipped, never the test build in bin\test.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{35EF7758-FE39-4C59-BF6F-981B30A588CB}
AppName=VaultKeep
AppVersion={#AppVersion}
AppVerName=VaultKeep {#AppVersion}
AppPublisher=VaultKeep
AppPublisherURL=https://github.com/SocheatSorng/VaultKeep
AppSupportURL=https://github.com/SocheatSorng/VaultKeep/issues
AppUpdatesURL=https://github.com/SocheatSorng/VaultKeep/releases
DefaultDirName={localappdata}\Programs\VaultKeep
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=VaultKeep-Setup-{#AppVersion}
UninstallDisplayIcon={app}\VaultKeep.exe
UninstallDisplayName=VaultKeep
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; A running VaultKeep may be guarding an open item. Never close it: PrepareToInstall moves its exe aside
; instead (Windows allows renaming a running exe), the same way build.ps1 does.
CloseApplications=no
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName=VaultKeep

[Files]
Source: "bin\VaultKeep.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\VaultKeep"; Filename: "{app}\VaultKeep.exe"; Comment: "Right-click menu and USB security keys"

[Run]
; Adds "Lock with VaultKeep" to the right-click menu (or points it at this copy if an older one was there).
Filename: "{app}\VaultKeep.exe"; Parameters: "install --quiet"; StatusMsg: "Adding the right-click menu..."; Flags: runhidden waituntilterminated
Filename: "{app}\VaultKeep.exe"; Description: "Open VaultKeep (set up a USB security key)"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
Filename: "{app}\VaultKeep.exe"; Parameters: "uninstall --quiet"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveMenu"

[UninstallDelete]
; Copies moved aside by an update while they were running (see PrepareToInstall).
Type: files; Name: "{app}\VaultKeep.old-*.exe"

[Code]
// True if the exe can't be opened for exclusive writing: Windows keeps a running program's file locked.
// Any other failure also counts as "in use" (fail closed), the same probe build.ps1 uses.
function ExeInUse(const FileName: String): Boolean;
var
  S: TFileStream;
begin
  Result := False;
  try
    S := TFileStream.Create(FileName, fmOpenReadWrite or fmShareExclusive);
    S.Free;
  except
    Result := True;
  end;
end;

// True if a VaultKeep in the install folder is running (an item is open, or it is still watching a
// just-closed item for late saves, up to 15 minutes): VaultKeep.exe or a copy moved aside by an update.
function RunningFromApp(): Boolean;
var
  Found: TFindRec;
begin
  Result := False;
  if FindFirst(ExpandConstant('{app}\VaultKeep*.exe'), Found) then
  begin
    try
      repeat
        if ExeInUse(ExpandConstant('{app}\') + Found.Name) then Result := True;
      until Result or not FindNext(Found);
    finally
      FindClose(Found);
    end;
  end;
end;

// Update while VaultKeep is running: rename its exe so the running copy keeps working and the new one
// can be written. Old renamed copies are removed once nothing uses them.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Exe, Aside: String;
  Found: TFindRec;
begin
  Result := '';
  if FindFirst(ExpandConstant('{app}\VaultKeep.old-*.exe'), Found) then
  begin
    try
      repeat
        DeleteFile(ExpandConstant('{app}\') + Found.Name);
      until not FindNext(Found);
    finally
      FindClose(Found);
    end;
  end;
  Exe := ExpandConstant('{app}\VaultKeep.exe');
  if FileExists(Exe) and ExeInUse(Exe) then
  begin
    Aside := ExpandConstant('{app}\VaultKeep.old-') + GetDateTimeString('yyyymmddhhnnss', #0, #0) + '.exe';
    if not RenameFile(Exe, Aside) then
      Result := 'VaultKeep is running and its program file could not be replaced. ' +
        'Close any items you opened with VaultKeep, wait a few minutes, and run Setup again.';
  end;
end;

// Uninstalling while an item is open would leave it unlocked with nothing to re-lock it: refuse.
function InitializeUninstall(): Boolean;
begin
  Result := not RunningFromApp();
  if not Result then
    SuppressibleMsgBox('VaultKeep is still running: an item is open, or VaultKeep is watching a ' +
      'just-closed item for late saves (up to 15 minutes).' + #13#10#13#10 +
      'Close the items you opened with VaultKeep, wait a few minutes, and uninstall again.',
      mbError, MB_OK, IDOK);
end;
