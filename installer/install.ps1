<#
.SYNOPSIS
    Installs otinv from its latest GitHub release.

.DESCRIPTION
    One-liner (PowerShell 5.1 or 7):
        irm https://github.com/Londopy/otinv/releases/latest/download/install.ps1 | iex

    With options, run it as a script block (this one also puts otinv on PATH):
        & ([scriptblock]::Create((irm https://github.com/Londopy/otinv/releases/latest/download/install.ps1))) -AddToPath

    What it does:
      - picks the right download for this PC (x64, x86 or arm64)
      - verifies it against the release's SHA256SUMS.txt and refuses on a mismatch
      - x64: runs the setup.exe silently (per-user, no admin prompt)
      - x86 / arm64, or -Msi: runs the .msi instead
      - -Portable: no installer, just otinv.exe and otinv-gui.exe in a folder

    otinv-gui.exe is the window; the setup.exe and the MSI add a Start menu
    shortcut to it. otinv.exe is the command line: the MSI puts it on your
    PATH; with the setup.exe and -Portable, add -AddToPath for that.

.PARAMETER Version
    Install this version (for example 1.2.3) instead of the latest.
.PARAMETER Msi
    Use the .msi instead of the setup.exe.
.PARAMETER AllUsers
    Install for every user on this PC (asks for admin).
.PARAMETER Portable
    Skip the installer: put otinv.exe and otinv-gui.exe in -Dir.
.PARAMETER Dir
    Folder for -Portable. Default: %LOCALAPPDATA%\Programs\otinv
.PARAMETER AddToPath
    Put otinv on your PATH, so new terminals find it. The setup.exe and
    -Portable only do this with this switch; the MSI always does.
.PARAMETER DryRun
    Show what would be downloaded and run, then stop.
#>
# Write-Host is right for an interactive installer; the parameters are read
# inside Install-App, which the analyzer can't see
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
param(
    [string]$Version,
    [switch]$Msi,
    [switch]$AllUsers,
    [switch]$Portable,
    [string]$Dir,
    [switch]$AddToPath,
    [switch]$DryRun,
    # for testing against a mock API; leave as is
    [string]$ApiBase = 'https://api.github.com'
)

# no `exit` anywhere: under `irm | iex` it would close the user's window

$AppName = 'otinv'
$Repo = 'Londopy/otinv'

function Get-NativeArch {
    # the registry has the real CPU even when this PowerShell is emulated
    # (x64 PowerShell on an arm64 PC reports AMD64 in its own environment)
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $arch = $null
    try { $arch = (Get-ItemProperty -Path $key -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE } catch { $arch = $null }
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'ARM64' { return 'arm64' }
        'x86' { return 'x86' }
        default { return 'x64' }
    }
}

function Get-Release {
    param([string]$Tag)
    $headers = @{ 'User-Agent' = "$AppName-installer"; 'Accept' = 'application/vnd.github+json' }
    if ($Tag) {
        $url = "$ApiBase/repos/$Repo/releases/tags/$Tag"
    } else {
        $url = "$ApiBase/repos/$Repo/releases/latest"
    }
    Invoke-RestMethod -Uri $url -Headers $headers -UseBasicParsing
}

function Get-ChecksumTable {
    param($Release)
    $asset = $Release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
    if (-not $asset) { throw "This release has no SHA256SUMS.txt, so downloads can't be verified." }
    $text = (Invoke-WebRequest -Uri $asset.browser_download_url -UseBasicParsing).Content
    if ($text -is [byte[]]) { $text = [System.Text.Encoding]::UTF8.GetString($text) }
    $sums = @{}
    foreach ($line in ($text -split "`r?`n")) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -eq 2) { $sums[$parts[1].TrimStart('*')] = $parts[0].ToLowerInvariant() }
    }
    return $sums
}

# which file to download; $null when the release doesn't have it
function Select-Download {
    param($Names, [string]$Arch, [bool]$WantMsi, [bool]$WantPortable)
    if ($WantPortable) {
        # otinv-v1.2.3-x64-portable.exe and otinv-gui-v1.2.3-x64-portable.exe
        $exe = $Names | Where-Object { $_ -like "otinv-v*-$Arch-portable.exe" } | Select-Object -First 1
        $gui = $Names | Where-Object { $_ -like "otinv-gui-v*-$Arch-portable.exe" } | Select-Object -First 1
        # releases before 0.3.0 have no GUI; install the command line alone
        if ($exe) { return @{ Kind = 'exe'; Name = $exe; Gui = $gui } }
        return $null
    }
    # the setup.exe is x64 only; other CPUs (and -Msi) get the msi
    if (-not $WantMsi -and $Arch -eq 'x64') {
        $setup = $Names | Where-Object { $_ -like '*-setup-x64.exe' } | Select-Object -First 1
        if ($setup) { return @{ Kind = 'setup'; Name = $setup } }
    }
    $msiName = $Names | Where-Object { $_ -like "*-$Arch.msi" } | Select-Object -First 1
    if ($msiName) { return @{ Kind = 'msi'; Name = $msiName } }
    # last resort for an x64 PC asking for -Msi when no msi was published
    if ($Arch -eq 'x64') {
        $setup = $Names | Where-Object { $_ -like '*-setup-x64.exe' } | Select-Object -First 1
        if ($setup) { return @{ Kind = 'setup'; Name = $setup } }
    }
    return $null
}

function Save-Verified {
    param($Release, [string]$Name, $Sums)
    if (-not $Sums.ContainsKey($Name)) { throw "SHA256SUMS.txt has no entry for $Name; not installing it." }
    $asset = $Release.assets | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    $path = Join-Path ([System.IO.Path]::GetTempPath()) $Name
    Write-Host "Downloading $Name ..."
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $path -UseBasicParsing
    $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sums[$Name]) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        throw "SHA-256 mismatch for $Name (expected $($Sums[$Name]), got $actual). Nothing was installed."
    }
    Write-Host 'SHA-256 verified.'
    return $path
}

function Add-UserPath {
    param([string]$Folder)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($current) { $parts = $current -split ';' | Where-Object { $_ } }
    if ($parts -contains $Folder) { return }
    [Environment]::SetEnvironmentVariable('Path', (($parts + $Folder) -join ';'), 'User')
    Write-Host "Added $Folder to your PATH (open a new terminal to use it)."
}

function Install-App {
    $ErrorActionPreference = 'Stop'
    # PowerShell 5.1 shows a very slow progress bar while downloading
    $ProgressPreference = 'SilentlyContinue'
    # PowerShell 5.1 on older .NET doesn't offer TLS 1.2 by default; GitHub needs it
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $arch = Get-NativeArch
    $tag = $null
    if ($Version) { $tag = 'v' + $Version.TrimStart('v') }
    $release = Get-Release -Tag $tag
    $names = @($release.assets | ForEach-Object { $_.name })
    $pick = Select-Download -Names $names -Arch $arch -WantMsi $Msi.IsPresent -WantPortable $Portable.IsPresent
    if (-not $pick) {
        throw "$($release.tag_name) has no download for this PC ($arch). See https://github.com/$Repo/releases"
    }
    Write-Host "$AppName $($release.tag_name) for $arch -> $($pick.Name)"
    if ($DryRun) { return $pick }

    $sums = Get-ChecksumTable -Release $release
    $file = Save-Verified -Release $release -Name $pick.Name -Sums $sums
    $guiFile = $null
    if ($pick.Gui) { $guiFile = Save-Verified -Release $release -Name $pick.Gui -Sums $sums }

    switch ($pick.Kind) {
        'setup' {
            $scope = '/CURRENTUSER'
            if ($AllUsers) { $scope = '/ALLUSERS' }
            $setupArgs = @('/SILENT', '/SP-', '/SUPPRESSMSGBOXES', '/NORESTART', '/CLOSEAPPLICATIONS', $scope)
            # the setup's "Add otinv to the PATH" task is unchecked unless asked for
            if ($AddToPath) { $setupArgs += '/MERGETASKS=addtopath' }
            $p = Start-Process -FilePath $file -Wait -PassThru -ArgumentList $setupArgs
            if ($p.ExitCode -ne 0) { throw "Setup exited with code $($p.ExitCode)." }
        }
        'msi' {
            # the msi puts otinv on PATH by default (ADDTOPATH=1)
            $msiArgs = "/i `"$file`" /passive /norestart"
            if ($AllUsers) { $msiArgs += ' ALLUSERS=2 MSIINSTALLPERUSER=""' }
            $p = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList $msiArgs
            # 3010 = installed, restart recommended
            if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec exited with code $($p.ExitCode)." }
        }
        'exe' {
            $target = $Dir
            if (-not $target) { $target = Join-Path $env:LOCALAPPDATA "Programs\$AppName" }
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            $dest = Join-Path $target "$AppName.exe"
            Copy-Item -Path $file -Destination $dest -Force
            if ($guiFile) {
                Copy-Item -Path $guiFile -Destination (Join-Path $target "$AppName-gui.exe") -Force
                Remove-Item -Path $guiFile -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "This release has no otinv-gui; only the command line was installed."
            }
            Write-Host "Installed to $target"
            if ($AddToPath) { Add-UserPath -Folder $target }
        }
    }
    Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
    Write-Host "$AppName $($release.tag_name) is installed."
    if ($pick.Kind -ne 'exe') { Write-Host "Open it from the Start menu, or run $AppName-gui." }
    if ($AddToPath -or $pick.Kind -eq 'msi') {
        Write-Host "Open a new terminal and run: $AppName --help"
    } else {
        Write-Host "$AppName isn't on your PATH: run this again with -AddToPath, or run $AppName.exe by its full path."
    }
}

Install-App
