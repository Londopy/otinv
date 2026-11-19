# Installs, checks and uninstalls otinv's Windows installers on this machine.
# Meant for a throwaway CI runner: it changes PATH and Program Files.
#
#   pwsh scripts/smoke_install.ps1 -Dir <folder with the setup.exe and x64 msi> -Version 0.1.0
#
# Each installer must put otinv.exe where expected, make `otinv --version`
# work from a new shell (the PATH entry), and leave nothing behind when
# uninstalled.

param(
    [Parameter(Mandatory)] [string]$Dir,
    [Parameter(Mandatory)] [string]$Version
)

$ErrorActionPreference = 'Stop'
$AppId = '{351A41A2-53BA-49DA-AC0B-CAD0A18661EF}'
$UserDir = Join-Path $env:LOCALAPPDATA 'Programs\otinv'
$MachineDir = Join-Path $env:ProgramFiles 'otinv'

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
    $source, $version = "$out" -split '\|', 2
    if ($source -eq 'not found') { Fail "otinv isn't on the PATH after install" }
    if ($source -notlike "$Expected*") { Fail "PATH finds $source, expected one in $Expected" }
    if ($version -ne "otinv $Version") { Fail "otinv --version says '$version', expected 'otinv $Version'" }
    Write-Host "  PATH ok: $source -> $version"
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
$p = Start-Process "$UserDir\unins000.exe" -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "the uninstaller exited $($p.ExitCode)" }
Wait-Gone $UserDir
if (Get-PathHas $UserDir) { Fail 'uninstall left otinv on the PATH' }
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
Invoke-Msi @('/x', $msi) "$logs\msi-user-uninstall.log"
Wait-Gone $UserDir
if (Get-PathHas $UserDir) { Fail 'MSI uninstall left otinv on the PATH' }
Write-Host '  uninstall ok'

Write-Host '== MSI, all users'
Invoke-Msi @('/i', $msi, 'ALLUSERS=2', 'MSIINSTALLPERUSER=') "$logs\msi-machine.log"
if (-not (Test-Path "$MachineDir\otinv.exe")) { Fail "the all-users MSI didn't install $MachineDir\otinv.exe" }
$version = & "$MachineDir\otinv.exe" --version
if ($version -ne "otinv $Version") { Fail "installed otinv says '$version'" }
Invoke-Msi @('/x', $msi, 'ALLUSERS=2', 'MSIINSTALLPERUSER=') "$logs\msi-machine-uninstall.log"
Wait-Gone $MachineDir
if (Get-PathHas $MachineDir) { Fail 'all-users MSI uninstall left otinv on the PATH' }
Write-Host '  uninstall ok'

Write-Host 'all installers passed'
