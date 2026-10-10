#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the FIDO2 BLE fingerprint logon tile (credential provider) and the fido2-ble-logon CLI.

.DESCRIPTION
    Run from an elevated 64-bit PowerShell. In this order (so LogonUI never looks for a missing COM class):
      1. removes HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID},
      2. unregisters the COM class (regsvr32 /u /s, then removes HKLM\SOFTWARE\Classes\CLSID\{CLSID} if left over),
      3. deletes C:\Program Files\Fido2BleLogon. Files that LogonUI still has loaded are deleted at the next restart.
    The enrollment and logs in C:\ProgramData\Fido2BleLogon are kept unless -RemoveData is given.
    Safe to run more than once; it also works from Safe Mode.

.PARAMETER RemoveData
    Also delete C:\ProgramData\Fido2BleLogon (the enrollment with the encrypted password, the logs and the
    kill-switch file).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1
    (-NoProfile: the elevated PowerShell should not run your profile script, which programs running under your
    account can change without elevation.)
#>
[CmdletBinding()]
param(
    [switch]$RemoveData
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Must equal SecurityKeyProvider.ClassIdString in src\Fido2BleLogon.CredentialProvider\SecurityKeyProvider.cs.
$Clsid = '{35e15797-dd2e-44f3-b82c-839eeb10aebd}'
$ProgId = 'Fido2BleLogon.CredentialProvider.SecurityKeyProvider' # comhost's default ProgID: the provider's .NET type name

$InstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Fido2BleLogon'
$ComHostPath = Join-Path $InstallRoot 'provider\Fido2BleLogon.CredentialProvider.comhost.dll'
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$ProviderListKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"
$DataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Fido2BleLogon'
$script:RebootPending = $false

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Info([string]$Text) { Write-Host "    $Text" }
function Write-Warn([string]$Text) { Write-Host "    WARNING: $Text" -ForegroundColor Yellow }
function Stop-Uninstall([string]$Text) {
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
        Write-Warn "could not delete or schedule $Path (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))."
    }
}

# Deletes a tree without ever following a junction or symlink (a link is removed itself, never its target).
# Files that can't be deleted now (loaded by LogonUI) are scheduled for deletion at the next restart; their
# folders after them, so the folders are empty by then.
function Remove-TreeSafely([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    $isLink = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if ($item.PSIsContainer -and -not $isLink) {
        foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force)) { Remove-TreeSafely $child.FullName }
    }
    try {
        if (($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
            $item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
        }
        if ($item.PSIsContainer) {
            [IO.Directory]::Delete($item.FullName, $false)
        } else {
            [IO.File]::Delete($item.FullName)
        }
    } catch {
        Register-DeleteAtReboot $item.FullName
    }
}

# ---------------------------------------------------------------------------------------------------------

Write-Host 'FIDO2 BLE fingerprint logon - uninstall' -ForegroundColor White

Write-Step 'Checking prerequisites'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Uninstall 'This script must run elevated. Right-click PowerShell, choose "Run as administrator", and run it again.'
}
Write-Info 'running as administrator'
if (-not [Environment]::Is64BitProcess) {
    Stop-Uninstall 'This is 32-bit PowerShell. Use the 64-bit one (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe).'
}
Write-Info '64-bit PowerShell'

Write-Step 'Removing the tile from the logon and lock screen'
if (Test-Path -LiteralPath $ProviderListKey) {
    Remove-Item -LiteralPath $ProviderListKey -Recurse -Force
    Write-Info "removed $ProviderListKey"
} else {
    Write-Info 'not on the logon screen (no Credential Providers entry)'
}

Write-Step 'Unregistering the COM class'
if (Test-Path -LiteralPath $ComHostPath) {
    $regsvr32 = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
    $process = Start-Process -FilePath $regsvr32 -ArgumentList @('/u', '/s', "`"$ComHostPath`"") -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -eq 0) {
        Write-Info 'regsvr32 /u succeeded'
    } else {
        Write-Warn "regsvr32 /u failed (exit code $($process.ExitCode)); removing the registration directly."
    }
} else {
    Write-Info "$ComHostPath is not there; checking the registry directly"
}
if (Test-Path -LiteralPath $ClsidKey) {
    Remove-Item -LiteralPath $ClsidKey -Recurse -Force
    Write-Info "removed $ClsidKey"
} else {
    Write-Info 'COM class not registered'
}
# comhost also registers a ProgID (the .NET type name); remove it if regsvr32 /u could not, and only if it is ours.
$progIdKey = "HKLM:\SOFTWARE\Classes\$ProgId"
if (Test-Path -LiteralPath "$progIdKey\CLSID") {
    $progIdClsid = [string](Get-Item -LiteralPath "$progIdKey\CLSID").GetValue('')
    if ($progIdClsid -eq $Clsid) {
        Remove-Item -LiteralPath $progIdKey -Recurse -Force
        Write-Info "removed $progIdKey"
    }
}

Write-Step "Deleting $InstallRoot"
if (Test-Path -LiteralPath $InstallRoot) {
    Remove-TreeSafely $InstallRoot
    if (Test-Path -LiteralPath $InstallRoot) {
        Write-Info 'some files are still loaded (by LogonUI); they go at the next restart'
    } else {
        Write-Info 'deleted'
    }
} else {
    Write-Info 'not installed'
}

if ($RemoveData) {
    Write-Step "Deleting the enrollment and logs in $DataDir"
    if (Test-Path -LiteralPath $DataDir) {
        Remove-TreeSafely $DataDir
        Write-Info 'deleted'
    } else {
        Write-Info 'nothing there'
    }
} else {
    Write-Step "Keeping $DataDir"
    Write-Info 'it holds the enrollment (password encrypted under the key) and the logs; run with -RemoveData to delete it'
}

Write-Host ''
Write-Host 'Done. The security key tile is gone from the logon screen; password and PIN sign-in are unchanged.' -ForegroundColor Green
if ($script:RebootPending) {
    Write-Host 'Some files were in use by LogonUI and will be deleted at the next restart. Restart Windows, or run this script again after a restart.' -ForegroundColor Yellow
}
exit 0
