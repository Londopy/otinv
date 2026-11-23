# Installs, checks and uninstalls otinv's Windows installers on this machine.
# Meant for a throwaway CI runner: it changes PATH and Program Files.
#
#   pwsh scripts/smoke_install.ps1 -Dir <folder with the setup.exe and x64 msi> -Version 0.1.0
#
# Each installer must put otinv.exe and otinv-gui.exe where expected, add a
# Start menu shortcut to the GUI, make `otinv --version` work from a new
# shell (the PATH entry), and leave nothing behind when uninstalled.

param(
    [Parameter(Mandatory)] [string]$Dir,
    [Parameter(Mandatory)] [string]$Version
)

$ErrorActionPreference = 'Stop'
$AppId = '{351A41A2-53BA-49DA-AC0B-CAD0A18661EF}'
$UserDir = Join-Path $env:LOCALAPPDATA 'Programs\otinv'
$MachineDir = Join-Path $env:ProgramFiles 'otinv'
$UserMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$MachineMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
# the setup.exe makes an otinv folder in the Start menu, the MSI a shortcut at the top
$SetupShortcut = "$UserMenu\otinv\otinv.lnk"
$MsiShortcut = "$UserMenu\otinv.lnk"
$MachineShortcut = "$MachineMenu\otinv.lnk"

function Fail([string]$Message) {
    Write-Host "FAIL: $Message"
    exit 1
}

# PATH as a freshly started shell would see it, read from the registry
function Get-FreshPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    "$machine;$user"
}

function Get-PathHas([string]$Folder) {
    (Get-FreshPath) -split ';' | Where-Object { $_.TrimEnd('\') -ieq $Folder.TrimEnd('\') }
}

# runs `otinv --version` in a child shell with only the fresh PATH
function Test-OnPath([string]$Expected) {
    $out = pwsh -NoProfile -Command {
        param($p)
        $env:Path = $p
        $cmd = Get-Command otinv -ErrorAction SilentlyContinue
        if (-not $cmd) { 'not found'; return }
        "$($cmd.Source)|$(otinv --version)"
    } -args (Get-FreshPath)
    $source, $got = "$out" -split '\|', 2
    if ($source -eq 'not found') { Fail "otinv isn't on the PATH after install" }
    if ($source -notlike "$Expected*") { Fail "PATH finds $source, expected one in $Expected" }
    if ($got -ne "otinv $Version") { Fail "otinv --version says '$got', expected 'otinv $Version'" }
    Write-Host "  PATH ok: $source -> $got"
}

# the GUI exe is installed and the Start menu shortcut opens it; releases
# before 0.3.0 had no GUI, and the Installers workflow can still test them
function Test-Gui([string]$Folder, [string]$Shortcut) {
    if ([version]($Version -split '-')[0] -lt [version]'0.3.0') { return }
    if (-not (Test-Path "$Folder\otinv-gui.exe")) { Fail "otinv-gui.exe isn't in $Folder" }
    if (-not (Test-Path $Shortcut)) { Fail "no Start menu shortcut at $Shortcut" }
    $target = (New-Object -ComObject WScript.Shell).CreateShortcut($Shortcut).TargetPath
    if ($target -ine "$Folder\otinv-gui.exe") { Fail "the shortcut opens $target, not otinv-gui.exe" }
    Write-Host "  GUI ok: $Shortcut -> $target"
}

function Wait-Gone([string]$Path) {
    # Inno's uninstaller copies itself to %TEMP% and finishes after it returns
    foreach ($i in 1..60) {
        if (-not (Test-Path $Path)) { return }
        Start-Sleep -Seconds 1
    }
    Fail "$Path is still there after uninstall: $((Get-ChildItem $Path -Recurse -Force | ForEach-Object Name) -join ', ')"
}

function Invoke-Msi([string[]]$MsiArgs, [string]$Log) {
    $p = Start-Process msiexec.exe -ArgumentList ($MsiArgs + @('/qn', '/norestart', '/l*v', $Log)) -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $Log -Tail 40 | Write-Host
        Fail "msiexec $($MsiArgs[0]) exited $($p.ExitCode)"
    }
}

$setup = Join-Path $Dir "otinv-$Version-setup-x64.exe"
$msi = Join-Path $Dir "otinv-$Version-x64.msi"
foreach ($f in $setup, $msi) { if (-not (Test-Path $f)) { Fail "missing $f" } }
$logs = Join-Path $env:RUNNER_TEMP 'install-logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

Write-Host '== setup.exe, per-user, with the PATH task'
$p = Start-Process $setup -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER',
    '/MERGETASKS=addtopath', "/LOG=$logs\setup.log" -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "setup.exe exited $($p.ExitCode)" }
if (-not (Test-Path "$UserDir\otinv.exe")) { Fail "setup.exe didn't install $UserDir\otinv.exe" }
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\${AppId}_is1")) {
    Fail 'setup.exe left no Add/Remove Programs entry'
}
Test-OnPath $UserDir
Test-Gui $UserDir $SetupShortcut
$p = Start-Process "$UserDir\unins000.exe" -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "the uninstaller exited $($p.ExitCode)" }
Wait-Gone $UserDir
if (Get-PathHas $UserDir) { Fail 'uninstall left otinv on the PATH' }
if (Test-Path $SetupShortcut) { Fail 'uninstall left the Start menu shortcut' }
if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\${AppId}_is1") {
    Fail 'uninstall left the Add/Remove Programs entry'
}
Write-Host '  uninstall ok'

Write-Host '== MSI, default (per-user)'
Invoke-Msi @('/i', $msi) "$logs\msi-user.log"
if (-not (Test-Path "$UserDir\otinv.exe")) { Fail "the MSI didn't install $UserDir\otinv.exe" }
if ((Get-Content "$UserDir\install.ini" -Raw) -notmatch 'source\s*=\s*msi') {
    Fail "the MSI's install.ini doesn't say source=msi (otinv update relies on it)"
}
Test-OnPath $UserDir
Test-Gui $UserDir $MsiShortcut
Invoke-Msi @('/x', $msi) "$logs\msi-user-uninstall.log"
Wait-Gone $UserDir
if (Get-PathHas $UserDir) { Fail 'MSI uninstall left otinv on the PATH' }
if (Test-Path $MsiShortcut) { Fail 'MSI uninstall left the Start menu shortcut' }
Write-Host '  uninstall ok'

Write-Host '== MSI, all users'
Invoke-Msi @('/i', $msi, 'ALLUSERS=2', 'MSIINSTALLPERUSER=') "$logs\msi-machine.log"
if (-not (Test-Path "$MachineDir\otinv.exe")) { Fail "the all-users MSI didn't install $MachineDir\otinv.exe" }
$got = & "$MachineDir\otinv.exe" --version
if ($got -ne "otinv $Version") { Fail "installed otinv says '$got'" }
Test-Gui $MachineDir $MachineShortcut
Invoke-Msi @('/x', $msi, 'ALLUSERS=2', 'MSIINSTALLPERUSER=') "$logs\msi-machine-uninstall.log"
Wait-Gone $MachineDir
if (Get-PathHas $MachineDir) { Fail 'all-users MSI uninstall left otinv on the PATH' }
if (Test-Path $MachineShortcut) { Fail 'all-users MSI uninstall left the Start menu shortcut' }
Write-Host '  uninstall ok'

Write-Host 'all installers passed'
