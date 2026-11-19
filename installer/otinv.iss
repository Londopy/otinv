; otinv - Inno Setup script
;
; Built by the release workflow with
;   ISCC.exe /DAppVersion=1.0.0 installer\otinv.iss
; Run `cargo build --release` first so ..\target\release\otinv.exe exists.
;
; Output: installer\output\otinv-<version>-setup-x64.exe
;
; otinv is a command-line tool, so this is leaner than the GUI apps' script:
; no desktop icon, no Start menu shortcut to the exe (a console window would
; open and close at once), no startup entry and no "launch after install".
; The one integration is putting otinv on PATH, an opt-in task.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

; Folder holding the built exe, relative to this script. CI passes
; /DBinDir=..\target\x86_64-pc-windows-msvc\release when it builds with --target.
#ifndef BinDir
  #define BinDir "..\target\release"
#endif

; VersionInfoVersion must be plain numeric (x.x.x[.x]); strip any prerelease
; suffix like "-rc1" so prerelease tags still compile.
#if Pos("-", AppVersion) > 0
  #define NumericVersion Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define NumericVersion AppVersion
#endif

#define AppName      "otinv"
#define AppPublisher "Londopy"
#define AppURL       "https://github.com/Londopy/otinv"
#define AppExeName   "otinv.exe"

[Setup]
; Unique GUID - do NOT reuse this for a different app.
; The doubled opening brace is Inno's escape for a literal "{".
AppId={{351A41A2-53BA-49DA-AC0B-CAD0A18661EF}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases

; Per-user install, no UAC prompt. The dialog still lets the user pick an
; all-users install if they want one.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; With lowest privileges {autopf} resolves to %LOCALAPPDATA%\Programs.
DefaultDirName={autopf}\{#AppName}
; The Start menu folder only holds the uninstall entry, so it can be skipped.
DefaultGroupName={#AppName}
AllowNoIcons=yes

LicenseFile=..\LICENSE

OutputDir=output
OutputBaseFilename=otinv-{#AppVersion}-setup-x64
; No SetupIconFile: otinv has no icon yet, so setup shows Inno's own.

; Compression
Compression=lzma2/ultra64
SolidCompression=yes

; Windows 10+ only (64-bit)
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

WizardStyle=modern

; The PATH task edits the environment; this tells Windows, so terminals
; opened afterwards see the change without signing out.
ChangesEnvironment=yes

; Restart Manager asks to close a running otinv before its exe is replaced.
; There's no forced taskkill as in the GUI apps' script: a running otinv may
; be halfway through writing a report.
CloseApplications=yes
CloseApplicationsFilter=*.exe
RestartApplications=no

UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
VersionInfoVersion={#NumericVersion}
VersionInfoDescription={#AppName} {#AppVersion} setup
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Opt-in, like every extra integration: puts {app} on the user's PATH (the
; machine's PATH for an all-users install), so any new terminal finds otinv.
Name: "addtopath"; \
  Description: "Add {#AppName} to the &PATH"; \
  GroupDescription: "Environment:"; \
  Flags: unchecked

[Files]
; Main binary - built before running iscc
Source: "{#BinDir}\{#AppExeName}"; \
  DestDir: "{app}"; \
  Flags: ignoreversion

[Icons]
; Start menu: only the uninstall entry. otinv runs in a terminal, so a
; shortcut to the exe would just flash a console window.
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

; No [Run] entry: there is no window to launch after install.

; No [UninstallRun] yet. The template's --londopy-unregister entry comes back
; when otinv registers the .londopy file type; today it only reads and writes
; .londopy files (src/londopy.rs has just the container half).

[UninstallDelete]
; `otinv update` renames the running exe to otinv.exe.old and deletes that
; the next time otinv starts: remove one that is still there, and the
; otinv.exe.new of an update that was cut off. otinv keeps nothing in
; AppData, so there's no {userappdata} folder to clean up.
Type: files; Name: "{app}\{#AppExeName}.old"
Type: files; Name: "{app}\{#AppExeName}.new"

[Code]
// PATH handling (from nexium): append {app} to the user's PATH, or the
// machine's for an all-users install, and take it out again on uninstall.

function EnvKey(): string;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function EnvRoot(): Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

procedure EnvAddPath(Dir: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(EnvRoot(), EnvKey(), 'Path', Paths) then
    Paths := '';
  // already there (a reinstall): leave PATH as it is
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    exit;
  if (Paths <> '') and (Paths[Length(Paths)] <> ';') then
    Paths := Paths + ';';
  Paths := Paths + Dir;
  RegWriteExpandStringValue(EnvRoot(), EnvKey(), 'Path', Paths);
end;

procedure EnvRemovePath(Dir: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot(), EnvKey(), 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  // P is the ';' in front of Dir in the padded string, which is Paths[P - 1].
  // When Dir is the first entry that ';' is the padding, so drop "Dir;"
  // instead. (Delete at index 0 does nothing, which used to leave a first
  // entry in PATH after uninstall.)
  if P = 1 then
    Delete(Paths, 1, Length(Dir) + 1)
  else
    Delete(Paths, P - 1, Length(Dir) + 1);
  RegWriteExpandStringValue(EnvRoot(), EnvKey(), 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    EnvAddPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}'));
end;
