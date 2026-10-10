#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the FIDO2 BLE fingerprint logon tile (credential provider) and the fido2-ble-logon CLI.

.DESCRIPTION
    Run from an elevated 64-bit Windows PowerShell started with -NoProfile (see the examples). The script:
      1. copies the sources of the provider, Fido2BleLogon.Core and the CLI (without bin\ and obj\) into a new
         admin-only staging folder under C:\Windows\Temp and publishes them there (Release, win-x64,
         framework-dependent) with the machine-wide .NET SDK and a clean build environment: no per-user
         environment variables, NuGet configuration, package cache or MSBuild extensions, no Directory.Build.*
         files, no build servers; packages come from nuget.org only,
      2. makes C:\Program Files\Fido2BleLogon admin-only (owner Administrators; SYSTEM, Administrators and
         TrustedInstaller full control, Users read) and copies the result to its provider\ and cli\ folders,
         then stops if anything there can be changed by anyone else; creates (or re-secures) the data folder
         C:\ProgramData\Fido2BleLogon admin-only, and refuses one someone else created,
      3. registers the provider's COM class with regsvr32 (the .NET comhost writes HKLM\SOFTWARE\Classes\CLSID\{CLSID}),
      4. activates the installed provider once from a separate Windows PowerShell (.NET Framework) process, which
         loads the installed comhost, the installed managed code and its dependencies the way LogonUI does (no key,
         no Bluetooth), checks that it refuses Credential UI, and stops if any of that fails,
      5. adds HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID},
         which puts the tile on the logon and lock screen (skipped with -RegisterOnly).
    It is safe to run again (it updates an existing installation). Files that LogonUI still has loaded are moved
    aside and deleted at the next restart.

.PARAMETER RegisterOnly
    Register the COM class only, without the Credential Providers entry: the tile stays OFF the logon screen.
    For testing with "fido2-ble-logon-cphost --com" (simulate, or "credui --com" to check that Credential UI is refused;
    both run the harness's own build of the provider code; step 4 above is what checks the installed files).
    Removes the entry if it exists.

.NOTES
    What running this script elevated trusts
      The provider runs as SYSTEM on the logon screen. This script builds it from the repository it sits in, so
      running it elevated trusts that repository (this script and the sources) as they are at that moment: review
      them first, especially if other software runs under your account, which can change them without
      elevation. The build itself runs on a copy in an admin-only folder with a clean environment, so per-user
      settings (environment variables, NuGet configuration and cache, MSBuild user extensions, Directory.Build.*
      files) don't feed into it. The elevated PowerShell that runs this script still starts from your account:
      start it with -NoProfile, as in the examples.

    Credential UI in elevated apps
      The tile is offered on the logon and lock screens only: the provider refuses Credential UI
      (CredUIPromptForWindowsCredentials), whose caller could read the password it returns. But it is registered
      machine-wide, so every 64-bit process that opens that dialog still creates it, and creating it loads the
      provider's .NET comhost and .NET 10 before the provider can refuse. The comhost finds the runtime through the
      environment first: DOTNET_ROOT_X64 or DOTNET_ROOT, when set, replace the machine-wide C:\Program Files\dotnet
      (.NET's COM host does not support a self-contained component that would carry its own runtime), and other
      DOTNET_*, COREHOST_*, CORECLR_* or COMPlus_* variables configure the host and runtime. In an elevated app
      these come partly from your per-user environment (HKCU\Environment), which programs running under your
      account can change without elevation. LogonUI (SYSTEM) does not see them. Keep no such per-user variables;
      the script warns if it finds any.

    The key's PIN can stand in for the fingerprint
      The key releases the secret that decrypts the stored password after any user verification: a fingerprint
      match or its PIN (FIDO2 treats both alike, and the computer can't tell which one was used). So the factors
      are "the key + (fingerprint OR key PIN)". Someone who has the key, knows its PIN and can read
      C:\ProgramData\Fido2BleLogon\enrollment.json (admin-only while Windows runs, but readable from an
      unencrypted disk) can recover the Windows password. Use a strong key PIN and turn on device encryption or
      BitLocker.

    Crash dumps of LogonUI
      During a fingerprint sign-in the Windows password is in LogonUI's memory for a moment. Keep crash dumps of
      LogonUI.exe as minidumps: a full dump (Windows Error Reporting LocalDumps with DumpType 2) would contain
      it. The script warns if one is configured.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 -RegisterOnly
#>
[CmdletBinding()]
param(
    [switch]$RegisterOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Must equal SecurityKeyProvider.ClassIdString in src\Fido2BleLogon.CredentialProvider\SecurityKeyProvider.cs
# (the regsvr32 step checks that regsvr32 registered exactly this CLSID).
$Clsid = '{35e15797-dd2e-44f3-b82c-839eeb10aebd}'
$ProviderDisplayName = 'Security key fingerprint'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SourceProjects = @('Fido2BleLogon.Core', 'Fido2BleLogon.CredentialProvider', 'Fido2BleLogon.Cli') # copied to the staging folder
$ProviderProjectFile = 'src\Fido2BleLogon.CredentialProvider\Fido2BleLogon.CredentialProvider.csproj'
$CliProjectFile = 'src\Fido2BleLogon.Cli\Fido2BleLogon.Cli.csproj'

# Known folders, not environment variables (those come partly from the user's environment).
$WindowsDir = [Environment]::GetFolderPath('Windows')
$System32 = [Environment]::GetFolderPath('System')
$ProgramFilesDir = [Environment]::GetFolderPath('ProgramFiles')
$ProgramDataDir = [Environment]::GetFolderPath('CommonApplicationData')
$DotnetDir = Join-Path $ProgramFilesDir 'dotnet'
$Dotnet = Join-Path $DotnetDir 'dotnet.exe'
$WindowsPowerShell = Join-Path $System32 'WindowsPowerShell\v1.0\powershell.exe'

$InstallRoot = Join-Path $ProgramFilesDir 'Fido2BleLogon'
$ProviderDir = Join-Path $InstallRoot 'provider'
$CliDir = Join-Path $InstallRoot 'cli'
$ComHostName = 'Fido2BleLogon.CredentialProvider.comhost.dll'
$ComHostPath = Join-Path $ProviderDir $ComHostName
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$CredentialProvidersKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$ProviderListKey = "$CredentialProvidersKey\$Clsid"
$DataDir = Join-Path $ProgramDataDir 'Fido2BleLogon'
$Stamp = Get-Date -Format 'yyyyMMddHHmmss'
$script:RebootPending = $false

$SidSystem = 'S-1-5-18'
$SidAdministrators = 'S-1-5-32-544'
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$SidCreatorOwner = 'S-1-3-0'
$SidUsers = 'S-1-5-32-545'
$SidAllApplicationPackages = 'S-1-15-2-1'
$SidAllRestrictedApplicationPackages = 'S-1-15-2-2'

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Info([string]$Text) { Write-Host "    $Text" }
function Write-Warn([string]$Text) { Write-Host "    WARNING: $Text" -ForegroundColor Yellow }
function Stop-Install([string]$Text) {
    Write-Host ''
    Write-Host "ERROR: $Text" -ForegroundColor Red
    exit 1
}

function Initialize-Native {
    if (-not ('Fido2BleLogonSetup.Native' -as [type])) {
        Add-Type -Namespace Fido2BleLogonSetup -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
    }
}

function Register-DeleteAtReboot([string]$Path) {
    Initialize-Native
    $MOVEFILE_DELAY_UNTIL_REBOOT = 4
    if ([Fido2BleLogonSetup.Native]::MoveFileEx($Path, [NullString]::Value, $MOVEFILE_DELAY_UNTIL_REBOOT)) {
        $script:RebootPending = $true
        Write-Info "in use; will be deleted at the next restart: $Path"
    } else {
        Write-Warn "could not schedule $Path for deletion (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))."
    }
}

function Test-IsLink([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return ($null -ne $item) -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

# Replaces one file. A DLL that LogonUI still has loaded can't be overwritten but can be renamed: move it aside
# (deleted at the next restart) so new LogonUI instances load the new file.
function Copy-FileSafely([string]$Source, [string]$Destination) {
    try {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        return
    } catch {
        if (-not (Test-Path -LiteralPath $Destination)) { throw }
    }
    $aside = "$Destination.old-$Stamp"
    try {
        Rename-Item -LiteralPath $Destination -NewName (Split-Path -Leaf $aside) -Force
    } catch {
        Stop-Install "$Destination is in use and could not be replaced. Restart Windows (or sign out), then run this script again."
    }
    Register-DeleteAtReboot $aside
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Remove-FileSafely([string]$Path) {
    try {
        Remove-Item -LiteralPath $Path -Force
    } catch {
        Register-DeleteAtReboot $Path
    }
}

# Makes $Target an exact copy of $Source (new and changed files copied, files the new build lacks removed).
function Sync-Directory([string]$Source, [string]$Target) {
    if (Test-IsLink $Target) { Stop-Install "$Target is a link (junction/symlink). Delete it and run this script again." }
    if (-not (Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target -Force | Out-Null }
    $sourceRoot = (Resolve-Path -LiteralPath $Source).ProviderPath.TrimEnd('\')
    $targetRoot = (Resolve-Path -LiteralPath $Target).ProviderPath.TrimEnd('\')

    foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Force) {
        $relative = $file.FullName.Substring($sourceRoot.Length).TrimStart('\')
        $destination = Join-Path $targetRoot $relative
        $folder = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        Copy-FileSafely $file.FullName $destination
    }
    foreach ($file in Get-ChildItem -LiteralPath $targetRoot -Recurse -File -Force) {
        $relative = $file.FullName.Substring($targetRoot.Length).TrimStart('\')
        if ($relative -like '*.old-*') { continue } # already scheduled for deletion
        if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot $relative))) {
            Write-Info "removing stale file $relative"
            Remove-FileSafely $file.FullName
        }
    }
}

# ----- Permissions ------------------------------------------------------------------------------------------

# A protected DACL (nothing inherited from the parent), inherited by everything below, owner Administrators.
function New-ProtectedDirectorySecurity([string[]]$FullControl, [string[]]$ReadExecute) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner((New-Object Security.Principal.SecurityIdentifier($SidAdministrators)))
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in $FullControl) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $propagation, $allow)))
    }
    foreach ($sid in $ReadExecute) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), [Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $propagation, $allow)))
    }
    return $security
}

# Stops unless $Path is a real directory (not a junction/symlink) owned by SYSTEM, Administrators or TrustedInstaller.
function Assert-AdminOwnedDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-Install "$Path is a link (junction/symlink). Delete it and run this script again." }
    $owner = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@($SidSystem, $SidAdministrators, $SidTrustedInstaller) -notcontains $owner) {
        Stop-Install "$Path is owned by $owner, not by Administrators. Someone else created it; delete it and run this script again."
    }
}

# %ProgramData%\Fido2BleLogon holds the enrollment and the provider's log. Standard users may create folders in
# ProgramData, so the script creates it here, admin-only, before the provider is registered, rather than leaving
# that to the first program that needs it. One that someone else made, or a link, is refused. Same permissions
# as 'fido2-ble-logon enroll' sets: owner Administrators, SYSTEM and Administrators only.
function Initialize-DataDirectory([string]$Path) {
    foreach ($folder in @($Path, (Join-Path $Path 'logs'))) {
        $security = New-ProtectedDirectorySecurity -FullControl @($SidSystem, $SidAdministrators) -ReadExecute @()
        if (Test-Path -LiteralPath $folder) {
            Assert-AdminOwnedDirectory $folder
            try {
                (Get-Item -LiteralPath $folder -Force).SetAccessControl($security)
            } catch {
                Stop-Install "Could not set the permissions of ${folder}: $($_.Exception.Message)"
            }
        } else {
            [void][IO.Directory]::CreateDirectory($folder, $security)
            Assert-AdminOwnedDirectory $folder
        }
    }
}

# The staging folder: created with its protected DACL in one step (SYSTEM and Administrators only), under a
# random name, and checked afterwards in case someone else created that name first.
function New-AdminOnlyDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Stop-Install "$Path already exists." }
    $security = New-ProtectedDirectorySecurity -FullControl @($SidSystem, $SidAdministrators) -ReadExecute @()
    [void][IO.Directory]::CreateDirectory($Path, $security)
    Assert-AdminOwnedDirectory $Path
}

# The install folder: owner Administrators; SYSTEM, Administrators and TrustedInstaller full control; Users and
# app packages read and execute (as Program Files itself); inherited by everything below it.
function Set-InstallFolderSecurity([string]$Path) {
    $security = New-ProtectedDirectorySecurity -FullControl @($SidSystem, $SidAdministrators, $SidTrustedInstaller) `
        -ReadExecute @($SidUsers, $SidAllApplicationPackages, $SidAllRestrictedApplicationPackages)
    try {
        if (Test-Path -LiteralPath $Path) {
            (Get-Item -LiteralPath $Path -Force).SetAccessControl($security)
        } else {
            [void][IO.Directory]::CreateDirectory($Path, $security)
        }
    } catch {
        Stop-Install "Could not set the permissions of ${Path}: $($_.Exception.Message)"
    }
}

# The provider runs as SYSTEM inside LogonUI: anyone who can change a file or folder under the install folder,
# or who owns one (an owner can always rewrite its permissions), can run code on the logon screen. Checks the
# folder and everything below it, and stops on any such principal other than SYSTEM, Administrators and
# TrustedInstaller.
function Assert-AdminOnlyTree([string]$Root) {
    $trusted = @($SidSystem, $SidAdministrators, $SidTrustedInstaller, $SidCreatorOwner)
    # WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete, WriteDAC, WriteOwner,
    # GENERIC_ALL (0x10000000), GENERIC_WRITE (0x40000000): how inherit-only ACEs often show up.
    $writeMask = 2 + 4 + 16 + 64 + 256 + 65536 + 262144 + 524288 + 0x10000000 + 0x40000000
    $problems = New-Object System.Collections.Generic.List[string]
    $items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $problems.Add("$($item.FullName) is a link (junction/symlink)")
            continue
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $owner) { $problems.Add("$($item.FullName) is owned by $owner") }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if (([int]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
            $sid = $rule.IdentityReference.Value
            if ($trusted -notcontains $sid) { $problems.Add("$sid can change $($item.FullName)") }
        }
    }
    if ($problems.Count -gt 0) {
        foreach ($problem in $problems) { Write-Warn $problem }
        Stop-Install "Only SYSTEM, Administrators and TrustedInstaller may be able to change $Root (LogonUI runs its files as SYSTEM). Fix the permissions above, or delete the folder, then run this script again."
    }
}

# ----- Building in a clean, admin-only place --------------------------------------------------------------

# Copies a project folder without the top-level folders in $Skip (bin, obj), refusing links: the elevated build
# only gets real files from the repository, and never the repository's restore output (obj\*.nuget.g.props).
function Copy-SourceTree([string]$Source, [string]$Target, [string[]]$Skip = @()) {
    if (Test-IsLink $Source) { Stop-Install "$Source is a link (junction/symlink); the build copies only real files." }
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { Stop-Install "Not found: $Source. Run the script from the repository's scripts folder." }
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    foreach ($child in @(Get-ChildItem -LiteralPath $Source -Force)) {
        if ($Skip -contains $child.Name) { continue }
        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-Install "$($child.FullName) is a link (junction/symlink); the build copies only real files. Remove it and run this script again."
        }
        $destination = Join-Path $Target $child.Name
        if ($child.PSIsContainer) {
            Copy-SourceTree $child.FullName $destination
        } else {
            Copy-Item -LiteralPath $child.FullName -Destination $destination -Force
        }
    }
}

# nuget.config (nuget.org only) and global.json for the staging folder, and the folders the clean environment
# points at. dotnet looks for global.json from the working directory upwards, MSBuild and NuGet look for their
# files from the project upwards; C:\Windows\Temp above the staging folder is writable by everyone, so this
# global.json ends dotnet's search inside the staging folder, and the publish switches below turn the others off.
function Initialize-BuildFolder([string]$Stage) {
    $utf8 = New-Object Text.UTF8Encoding($false)
    $nugetConfig = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <fallbackPackageFolders>
    <clear />
  </fallbackPackageFolders>
</configuration>
'@
    [IO.File]::WriteAllText((Join-Path $Stage 'nuget.config'), $nugetConfig, $utf8)
    [IO.File]::WriteAllText((Join-Path $Stage 'global.json'), "{`r`n}`r`n", $utf8)
    foreach ($name in @('home\AppData\Roaming', 'home\AppData\Local', 'tmp', 'packages', 'nuget\http-cache', 'nuget\plugins-cache', 'out')) {
        New-Item -ItemType Directory -Path (Join-Path $Stage $name) -Force | Out-Null
    }
}

# The environment for the build and the activation check: fixed values and known folders only, nothing from the
# user's environment (variables there become MSBuild properties, select the .NET host, NuGet folders...).
function Get-CleanEnvironment([string]$Stage) {
    $buildHome = Join-Path $Stage 'home'
    $temp = Join-Path $Stage 'tmp'
    $environment = @{
        'SystemRoot' = $WindowsDir
        'windir' = $WindowsDir
        'SystemDrive' = $WindowsDir.Substring(0, 2)
        'ComSpec' = Join-Path $System32 'cmd.exe'
        'PATHEXT' = '.COM;.EXE;.BAT;.CMD'
        'Path' = (@($System32, $WindowsDir, (Join-Path $System32 'Wbem'), (Join-Path $System32 'WindowsPowerShell\v1.0'), $DotnetDir) -join ';')
        'OS' = 'Windows_NT'
        'NUMBER_OF_PROCESSORS' = [string][Environment]::ProcessorCount
        'COMPUTERNAME' = [Environment]::MachineName
        'USERNAME' = [Environment]::UserName
        'ProgramFiles' = $ProgramFilesDir
        'ProgramW6432' = $ProgramFilesDir
        'ProgramFiles(x86)' = [Environment]::GetFolderPath('ProgramFilesX86')
        'CommonProgramFiles' = [Environment]::GetFolderPath('CommonProgramFiles')
        'CommonProgramW6432' = [Environment]::GetFolderPath('CommonProgramFiles')
        'CommonProgramFiles(x86)' = [Environment]::GetFolderPath('CommonProgramFilesX86')
        'ProgramData' = $ProgramDataDir
        'ALLUSERSPROFILE' = $ProgramDataDir
        'USERPROFILE' = $buildHome
        'APPDATA' = Join-Path $buildHome 'AppData\Roaming'
        'LOCALAPPDATA' = Join-Path $buildHome 'AppData\Local'
        'TEMP' = $temp
        'TMP' = $temp
        'DOTNET_CLI_HOME' = $buildHome
        'NUGET_PACKAGES' = Join-Path $Stage 'packages'
        'NUGET_HTTP_CACHE_PATH' = Join-Path $Stage 'nuget\http-cache'
        'NUGET_PLUGINS_CACHE_PATH' = Join-Path $Stage 'nuget\plugins-cache'
        'DOTNET_NOLOGO' = '1'
        'DOTNET_CLI_TELEMETRY_OPTOUT' = '1'
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE' = '1'
        'DOTNET_GENERATE_ASPNET_CERTIFICATE' = 'false'
        'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH' = 'false'
        'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE' = 'true'
        'MSBUILDDISABLENODEREUSE' = '1'
    }
    $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    if (-not [string]::IsNullOrEmpty($architecture)) { $environment['PROCESSOR_ARCHITECTURE'] = $architecture }
    return $environment
}

# Quotes one argument for CommandLineToArgvW (and the .NET and MSBuild command-line parsers).
function ConvertTo-CommandLineArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $escaped = [regex]::Replace($escaped, '(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    return '"' + $escaped + '"'
}

# Runs a program with exactly $Environment (nothing inherited) and waits for it. Its output goes to this console.
function Invoke-Clean([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory, [hashtable]$Environment) {
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (@($Arguments | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join ' ')
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.EnvironmentVariables.Clear()
    foreach ($name in $Environment.Keys) { $startInfo.EnvironmentVariables[$name] = [string]$Environment[$name] }
    $process = [Diagnostics.Process]::Start($startInfo)
    try {
        $process.WaitForExit()
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-Publish([string]$Project, [string]$Output, [string]$Stage, [hashtable]$Environment) {
    $arguments = @(
        'publish', $Project, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'false', '-o', $Output,
        '--nologo', '--disable-build-servers', '-noAutoResponse',
        # NuGet: only the staging folder's nuget.config (nuget.org) and package folder.
        "-p:RestoreConfigFile=$(Join-Path $Stage 'nuget.config')",
        "-p:RestorePackagesPath=$(Join-Path $Stage 'packages')",
        # No Directory.Build.*/Directory.Packages.props from folders above the sources, no user MSBuild extensions.
        '-p:ImportDirectoryBuildProps=false', '-p:ImportDirectoryBuildTargets=false', '-p:ImportDirectoryPackagesProps=false',
        '-p:ImportUserLocationsByWildcardBeforeMicrosoftCommonProps=false', '-p:ImportUserLocationsByWildcardAfterMicrosoftCommonProps=false',
        '-p:ImportUserLocationsByWildcardBeforeMicrosoftCommonTargets=false', '-p:ImportUserLocationsByWildcardAfterMicrosoftCommonTargets=false',
        '-p:ImportUserLocationsByWildcardBeforeMicrosoftCSharpTargets=false', '-p:ImportUserLocationsByWildcardAfterMicrosoftCSharpTargets=false'
    )
    $exitCode = Invoke-Clean $Dotnet $arguments $Stage $Environment
    if ($exitCode -ne 0) { Stop-Install "dotnet publish failed for $Project (exit code $exitCode)." }
}

# Every file the provider's deps.json lists must be in the provider folder: LogonUI resolves the provider's
# dependencies from there (a harness run can't tell, it brings its own copies).
function Assert-DepsComplete([string]$Folder, [string]$DepsFile) {
    $depsPath = Join-Path $Folder $DepsFile
    if (-not (Test-Path -LiteralPath $depsPath)) { Stop-Install "The provider build did not produce $DepsFile." }
    $deps = Get-Content -LiteralPath $depsPath -Raw | ConvertFrom-Json
    $missing = @()
    foreach ($target in $deps.targets.PSObject.Properties) {
        foreach ($library in $target.Value.PSObject.Properties) {
            $runtime = $library.Value.PSObject.Properties['runtime']
            if ($null -eq $runtime) { continue }
            foreach ($asset in $runtime.Value.PSObject.Properties) {
                $file = Split-Path -Leaf $asset.Name
                if (-not (Test-Path -LiteralPath (Join-Path $Folder $file)) -and $missing -notcontains $file) { $missing += $file }
            }
        }
    }
    if ($missing.Count -gt 0) { Stop-Install "The provider build lacks files its $DepsFile lists: $($missing -join ', ')." }
}

# ----- Checking the installed provider -------------------------------------------------------------------

# Runs in a separate Windows PowerShell (.NET Framework) process with the clean environment. None of the
# provider's assemblies are known there, so the installed comhost starts .NET 10 itself and every managed
# dependency comes from the installed folder through its deps.json, as in LogonUI (a .NET harness would run its
# own copies instead). SetUsageScenario(CPUS_CHANGE_PASSWORD) and SetUsageScenario(CPUS_CREDUI) touch no key and
# no Bluetooth; the provider answers E_NOTIMPL to both once Fido2BleLogon.Core has loaded (the second one also
# shows that the installed provider refuses Credential UI, whose caller could read the password).
$ProbeScript = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Plain text straight to stdout: PowerShell's own streams come out as CLIXML when the output is redirected.
function Say([string]$Text) { [Console]::Out.WriteLine($Text) }
$expectedComHost = '__COMHOST__'
$machineRuntime = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'dotnet\shared\Microsoft.NETCore.App\'
$source = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Fido2BleLogonProbe
{
    [ComImport, Guid("d27c3481-5a1c-45b2-8aaa-c20ebbe8229e"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICredentialProvider
    {
        [PreserveSig] int SetUsageScenario(int cpus, uint dwFlags);
    }

    public sealed class Result
    {
        public int HResult;
        public int CredUiHResult;
        public string ComHost = "";
        public string Runtime = "";
    }

    public static class Probe
    {
        public static Result Run(Guid clsid)
        {
            Type type = Type.GetTypeFromCLSID(clsid, true);
            object instance = Activator.CreateInstance(type);
            try
            {
                ICredentialProvider provider = (ICredentialProvider)instance;
                Result result = new Result();
                result.HResult = provider.SetUsageScenario(3, 0); // CPUS_CHANGE_PASSWORD
                result.CredUiHResult = provider.SetUsageScenario(4, 0); // CPUS_CREDUI, as a plain dialog caller asks
                result.ComHost = ModulePath("Fido2BleLogon.CredentialProvider.comhost.dll");
                result.Runtime = ModulePath("coreclr.dll");
                return result;
            }
            finally
            {
                Marshal.FinalReleaseComObject(instance);
            }
        }

        private static string ModulePath(string name)
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (string.Equals(module.ModuleName, name, StringComparison.OrdinalIgnoreCase))
                    return module.FileName;
            }
            return "";
        }
    }
}
"@
try {
    Add-Type -TypeDefinition $source
    $result = [Fido2BleLogonProbe.Probe]::Run([Guid]'__CLSID__')
} catch {
    $e = $_.Exception
    while ($null -ne $e.InnerException) { $e = $e.InnerException }
    Say ("    FAIL: the provider could not be created: {0} (HRESULT 0x{1:X8})" -f $e.Message, $e.HResult)
    exit 1
}
Say "    comhost loaded:  $($result.ComHost)"
Say "    .NET runtime:    $($result.Runtime)"
Say ("    SetUsageScenario(CPUS_CHANGE_PASSWORD) -> 0x{0:X8}" -f $result.HResult)
Say ("    SetUsageScenario(CPUS_CREDUI)          -> 0x{0:X8}" -f $result.CredUiHResult)
$ok = $true
if ($result.ComHost -ne $expectedComHost) {
    Say "    FAIL: expected the installed comhost $expectedComHost"
    $ok = $false
}
if (-not $result.Runtime.StartsWith($machineRuntime, [StringComparison]::OrdinalIgnoreCase)) {
    Say "    FAIL: expected the machine-wide .NET runtime under $machineRuntime (LogonUI uses that one)"
    $ok = $false
}
if ($result.HResult -ne -2147467263) {
    Say '    FAIL: expected E_NOTIMPL (0x80004001): the provider code or one of its dependencies did not load'
    $ok = $false
}
if ($result.CredUiHResult -ne -2147467263) {
    Say '    FAIL: expected E_NOTIMPL (0x80004001) for Credential UI: this provider build would show its tile in the credential dialog'
    $ok = $false
}
if ($ok) { exit 0 } else { exit 1 }
'@

function Test-InstalledProvider([string]$Stage, [hashtable]$Environment) {
    $probe = $ProbeScript.Replace('__CLSID__', $Clsid.Trim('{', '}')).Replace('__COMHOST__', $ComHostPath.Replace("'", "''"))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $exitCode = Invoke-Clean $WindowsPowerShell @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-OutputFormat', 'Text', '-EncodedCommand', $encoded) $Stage $Environment
    return ($exitCode -eq 0)
}

# ----- Warnings about the user's environment -----------------------------------------------------------------

# Per-user .NET host/runtime variables reach elevated apps that open the credential dialog (see .NOTES).
function Test-UserRuntimeVariables {
    $key = Get-Item -LiteralPath 'HKCU:\Environment' -ErrorAction SilentlyContinue
    $names = @()
    if ($null -ne $key) { $names = @($key.GetValueNames() | Where-Object { $_ -match '^(DOTNET_|COREHOST_|CORECLR_|COMPLUS_)' }) }
    if ($names.Count -eq 0) {
        Write-Info 'no per-user .NET host or runtime variables (DOTNET_*, COREHOST_*, CORECLR_*, COMPlus_*)'
        return
    }
    Write-Warn "per-user .NET variables in HKCU\Environment: $($names -join ', ')."
    Write-Warn 'Elevated apps that open the Windows credential dialog create this provider (it then refuses to show its tile there) and so load the .NET runtime these variables select or configure; programs running under your account can change them without elevation. LogonUI is not affected. Remove them unless you set them on purpose.'
}

# A full crash dump of LogonUI could contain the Windows password during a fingerprint sign-in (see .NOTES).
function Test-LogonUiCrashDumps {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
    $global = Get-Item -LiteralPath $base -ErrorAction SilentlyContinue
    if ($null -eq $global) { return }
    $dumpType = $global.GetValue('DumpType', $null)
    $app = Get-Item -LiteralPath "$base\LogonUI.exe" -ErrorAction SilentlyContinue
    if ($null -ne $app -and $null -ne $app.GetValue('DumpType', $null)) { $dumpType = $app.GetValue('DumpType', $null) }
    if ($null -ne $dumpType -and @(0, 2) -contains [int]$dumpType) {
        Write-Warn "Windows Error Reporting keeps local crash dumps of LogonUI with DumpType $dumpType (custom or full). A full dump taken during a fingerprint sign-in can contain the Windows password; use DumpType 1 (minidump) for LogonUI.exe."
    }
}

# ---------------------------------------------------------------------------------------------------------

Write-Host 'FIDO2 BLE fingerprint logon - install' -ForegroundColor White
if ($RegisterOnly) { Write-Host '(-RegisterOnly: COM registration only, the tile stays off the logon screen)' }

Write-Step 'Checking prerequisites'
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Stop-Install 'Run this script in Windows PowerShell 5.1 (powershell.exe), not in PowerShell 7 (pwsh.exe).'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Install 'This script must run elevated. Right-click Windows PowerShell, choose "Run as administrator", and run it again (with -NoProfile).'
}
Write-Info 'running as administrator'
if (-not [Environment]::Is64BitProcess) {
    Stop-Install "This is 32-bit PowerShell. Use the 64-bit one ($WindowsPowerShell): LogonUI is 64-bit."
}
Write-Info '64-bit Windows PowerShell'
foreach ($name in $SourceProjects) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot "src\$name\$name.csproj"))) {
        Stop-Install "Not found: $(Join-Path $RepoRoot "src\$name\$name.csproj"). Run the script from the repository's scripts folder."
    }
}
# Only the machine-wide .NET (admin-only folder): not a dotnet.exe found through the user's PATH.
if (-not (Test-Path -LiteralPath $Dotnet)) { Stop-Install "$Dotnet not found. Install the .NET 10 SDK (machine-wide)." }
$sdk10 = @(Get-ChildItem -LiteralPath (Join-Path $DotnetDir 'sdk') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '10.*' })
if ($sdk10.Count -eq 0) { Stop-Install "No .NET 10 SDK in $(Join-Path $DotnetDir 'sdk'). Install the .NET 10 SDK (machine-wide)." }
Write-Info "dotnet: $Dotnet (SDK $(($sdk10 | ForEach-Object { $_.Name }) -join ', '))"
# LogonUI runs as SYSTEM and does not see a per-user DOTNET_ROOT: the runtime must be the machine-wide one.
$machineRuntimes = Join-Path $DotnetDir 'shared\Microsoft.NETCore.App'
$runtime10 = @(Get-ChildItem -LiteralPath $machineRuntimes -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '10.*' })
if ($runtime10.Count -eq 0) {
    Stop-Install "The .NET 10 runtime is not installed in $machineRuntimes. LogonUI (SYSTEM) loads it from there."
}
Write-Info "machine-wide .NET runtime: $(($runtime10 | ForEach-Object { $_.Name }) -join ', ')"
Test-UserRuntimeVariables
Test-LogonUiCrashDumps

$stage = Join-Path (Join-Path $WindowsDir 'Temp') ('Fido2BleLogon-install-' + [guid]::NewGuid().ToString('N'))
try {
    Write-Step 'Preparing an admin-only build folder'
    New-AdminOnlyDirectory $stage
    foreach ($name in $SourceProjects) {
        Copy-SourceTree (Join-Path $RepoRoot "src\$name") (Join-Path $stage "src\$name") -Skip @('bin', 'obj')
    }
    Initialize-BuildFolder $stage
    $cleanEnvironment = Get-CleanEnvironment $stage
    Write-Info "$stage (sources copied from $RepoRoot)"

    Write-Step 'Building the credential provider (dotnet publish, Release, win-x64)'
    $stageProvider = Join-Path $stage 'out\provider'
    Invoke-Publish (Join-Path $stage $ProviderProjectFile) $stageProvider $stage $cleanEnvironment
    foreach ($name in @($ComHostName, 'Fido2BleLogon.CredentialProvider.dll', 'Fido2BleLogon.CredentialProvider.runtimeconfig.json', 'Fido2BleLogon.Core.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $stageProvider $name))) { Stop-Install "The provider build did not produce $name." }
    }
    Assert-DepsComplete $stageProvider 'Fido2BleLogon.CredentialProvider.deps.json'
    $runtimeConfig = Get-Content -LiteralPath (Join-Path $stageProvider 'Fido2BleLogon.CredentialProvider.runtimeconfig.json') -Raw
    if ($runtimeConfig -notmatch 'LoadComponentInDefaultContext') {
        Write-Warn 'the runtimeconfig.json lacks LoadComponentInDefaultContext; CsWinRT would load in an isolated context.'
    }

    Write-Step 'Building the fido2-ble-logon CLI (dotnet publish, Release, win-x64)'
    $stageCli = Join-Path $stage 'out\cli'
    Invoke-Publish (Join-Path $stage $CliProjectFile) $stageCli $stage $cleanEnvironment

    Write-Step "Installing files to $InstallRoot"
    if (Test-IsLink $InstallRoot) { Stop-Install "$InstallRoot is a link (junction/symlink). Delete it and run this script again." }
    Set-InstallFolderSecurity $InstallRoot
    Write-Info 'permissions: owner Administrators; SYSTEM, Administrators, TrustedInstaller full control; Users read'
    Sync-Directory $stageProvider $ProviderDir
    Write-Info "provider -> $ProviderDir"
    Sync-Directory $stageCli $CliDir
    Write-Info "CLI      -> $CliDir"
    Assert-AdminOnlyTree $InstallRoot
    Write-Info 'checked: only SYSTEM, Administrators and TrustedInstaller can change anything there'

    Write-Step "Preparing $DataDir (enrollment and logs)"
    Initialize-DataDirectory $DataDir
    Write-Info 'admin-only: owner Administrators; SYSTEM and Administrators only'

    Write-Step "Registering the COM class (regsvr32 /s $ComHostName)"
    $regsvr32 = Join-Path $System32 'regsvr32.exe'
    $process = Start-Process -FilePath $regsvr32 -ArgumentList @('/s', "`"$ComHostPath`"") -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { Stop-Install "regsvr32 failed (exit code $($process.ExitCode))." }
    $inproc = Get-Item -LiteralPath "$ClsidKey\InprocServer32" -ErrorAction SilentlyContinue
    if ($null -eq $inproc) {
        Stop-Install "regsvr32 succeeded but $ClsidKey does not exist: the CLSID in this script does not match the provider's [Guid]."
    }
    $registeredPath = [string]$inproc.GetValue('')
    if ($registeredPath -ne $ComHostPath) {
        Stop-Install "$ClsidKey\InprocServer32 points to '$registeredPath', not '$ComHostPath'."
    }
    Write-Info "$Clsid -> $registeredPath (ThreadingModel $($inproc.GetValue('ThreadingModel')))"

    Write-Step 'Checking the installed provider (activated from Windows PowerShell; no key, no Bluetooth)'
    if (-not (Test-InstalledProvider $stage $cleanEnvironment)) {
        if (Test-Path -LiteralPath $ProviderListKey) {
            Remove-Item -LiteralPath $ProviderListKey -Recurse -Force
            Write-Info "removed $ProviderListKey, so LogonUI does not load a provider that fails"
        }
        Stop-Install 'The installed provider could not be activated (see above). The tile is not on the logon screen; your password and PIN are unaffected. Fix the problem and run this script again.'
    }
    Write-Info 'the installed comhost, managed code and dependencies load, and the provider refuses the scenarios it does not offer (Credential UI included)'
} finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $stage) { Write-Warn "could not delete the build folder $stage completely; delete it later." }
    }
}

if ($RegisterOnly) {
    Write-Step 'Keeping the tile off the logon screen (-RegisterOnly)'
    if (Test-Path -LiteralPath $ProviderListKey) {
        Remove-Item -LiteralPath $ProviderListKey -Recurse -Force
        Write-Info "removed $ProviderListKey"
    } else {
        Write-Info 'no Credential Providers entry (as intended)'
    }
} else {
    Write-Step 'Adding the tile to the logon and lock screen'
    if (-not (Test-Path -LiteralPath $ProviderListKey)) {
        New-Item -Path $CredentialProvidersKey -Name $Clsid -Force | Out-Null
    }
    Set-ItemProperty -LiteralPath $ProviderListKey -Name '(default)' -Value $ProviderDisplayName
    Write-Info "$ProviderListKey = '$ProviderDisplayName'"
    $disabled = (Get-Item -LiteralPath $ProviderListKey).GetValue('Disabled', $null)
    if ($null -ne $disabled -and $disabled -ne 0) {
        Write-Warn "the key has Disabled = $disabled, so Windows will not load the tile. Delete that value to enable it."
    }
}

Write-Step 'Checking the enrollment'
if (Test-Path -LiteralPath (Join-Path $DataDir 'disabled')) {
    Write-Warn "the kill-switch file $(Join-Path $DataDir 'disabled') exists: the tile stays hidden until you delete it."
}
if (Test-Path -LiteralPath (Join-Path $DataDir 'enrollment.json')) {
    Write-Info "enrollment found in $DataDir"
} else {
    Write-Warn "nothing is enrolled yet, so the tile stays hidden. Run (elevated): `"$(Join-Path $CliDir 'fido2-ble-logon.exe')`" enroll"
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
if ($script:RebootPending) {
    Write-Host 'Some old files were still loaded (by LogonUI); they are deleted at the next restart. Restart before testing the logon screen.' -ForegroundColor Yellow
}
if ($RegisterOnly) {
    Write-Host 'Test without the logon screen: fido2-ble-logon-cphost --com (elevated); fido2-ble-logon-cphost credui --com checks'
    Write-Host 'that Credential UI is refused. (Both run the harness''s own build of the provider code; the check above covered'
    Write-Host 'the installed files.)'
} else {
    Write-Host 'Test: lock the PC (Windows+L), choose "Sign-in options" and the fingerprint icon, then follow the tile.'
}
Write-Host "Provider log: $(Join-Path $DataDir 'logs\provider.log')"
Write-Host ''
Write-Host 'If the logon screen misbehaves (keep this somewhere you can read from another device):' -ForegroundColor White
Write-Host '  - Your password and PIN keep working: choose them under "Sign-in options".'
Write-Host "  - Kill switch (elevated): New-Item -ItemType File '$(Join-Path $DataDir 'disabled')'  -> the tile is gone at the next lock or sign-in."
Write-Host '  - Safe Mode never loads third-party tiles (Shift+Restart > Troubleshoot > Advanced options > Startup Settings > 4).'
Write-Host '    From there run scripts\uninstall.ps1, or delete the registry key below.'
Write-Host "  - Registry key that puts the tile on the logon screen: $($ProviderListKey -replace '^HKLM:', 'HKEY_LOCAL_MACHINE')"
Write-Host '    (delete it, or add the DWORD value Disabled = 1).'
Write-Host '  - Uninstall: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1 (elevated).'
Write-Host ''
Write-Host 'Good to know:' -ForegroundColor White
Write-Host '  - The key''s PIN releases the stored password just like your fingerprint. Use a strong key PIN, and turn on'
Write-Host '    device encryption or BitLocker: without it, someone with the key and its PIN could read the enrollment off the disk.'
exit 0
