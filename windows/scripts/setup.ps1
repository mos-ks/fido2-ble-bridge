#Requires -Version 5.1
<#
.SYNOPSIS
    One-command setup of fingerprint sign-in with a Bluetooth FIDO2 security key.

.DESCRIPTION
    Double-click setup.cmd, or run: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
    It asks for administrator rights once, then:
      1. makes sure the .NET 10 SDK is installed (offers to install it with winget),
      2. builds and installs the logon tile and the fido2-ble-logon CLI (scripts\install.ps1),
      3. pairs the key if no key is paired yet (put it in pairing mode when asked),
      4. enrolls your account: your Windows password, then two touches on the fingerprint sensor.
         This also makes the fingerprint tile the preselected sign-in option.
    Running it again updates the installation; it asks before replacing an existing enrollment.
    Run it from the account you want to sign in to (it must be an administrator).
#>
[CmdletBinding()]
param(
    # Set by the script itself when it relaunches elevated: the SID of the account that started it.
    [string]$InvokingSid
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

$windowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$me = [Security.Principal.WindowsIdentity]::GetCurrent()

if (-not (Test-Admin)) {
    Write-Host 'Asking for administrator rights (approve the prompt)...'
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-InvokingSid', $me.User.Value)
    try {
        $process = Start-Process $windowsPowerShell -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        exit $process.ExitCode
    }
    catch {
        Write-Host 'Setup needs administrator rights; nothing was changed.' -ForegroundColor Red
        exit 1
    }
}

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Stop-Setup([string]$Text) { throw $Text }

$exitCode = 1
try {
    Write-Host 'FIDO2 BLE fingerprint logon - setup' -ForegroundColor White

    # Enrollment is for the account running this elevated window. If an administrator's credentials were typed
    # into the prompt for a standard account, that is a different account.
    if ($InvokingSid -and $InvokingSid -ne $me.User.Value) {
        Stop-Setup "The administrator prompt switched to another account ($($me.Name)). Fingerprint sign-in would be set up for that account, not yours. Run setup from an administrator account."
    }

    Write-Step 'Checking for the .NET 10 SDK'
    $sdks = @()
    if (Get-Command dotnet -ErrorAction SilentlyContinue) { $sdks = @(& dotnet --list-sdks 2>$null) }
    if (-not ($sdks -match '^10\.')) {
        $answer = Read-Host '    The .NET 10 SDK is needed to build the tile. Install it now with winget? [Y/n]'
        if ($answer -match '^(n|no)$') { Stop-Setup 'The .NET 10 SDK is required. Install it, then run setup again.' }
        & winget install --id Microsoft.DotNet.SDK.10 --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { Stop-Setup "winget could not install the .NET 10 SDK (exit $LASTEXITCODE)." }
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    }
    else {
        Write-Host "    found $(($sdks -match '^10\.')[0])"
    }

    Write-Step 'Installing the logon tile and the CLI'
    & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install.ps1')
    if ($LASTEXITCODE -ne 0) { Stop-Setup 'The installation failed (see above). Nothing on the logon screen changed unless it said so.' }

    $cli = Join-Path $env:ProgramFiles 'Fido2BleLogon\cli\fido2-ble-logon.exe'

    Write-Step 'Pairing the key'
    & $cli pair
    if ($LASTEXITCODE -ne 0) { Stop-Setup 'Pairing failed (see above). Run setup again when the key is in pairing mode.' }

    Write-Step 'Enrolling your account'
    & $cli status *> $null
    $enroll = $true
    if ($LASTEXITCODE -eq 0) {
        $answer = Read-Host '    You are already enrolled. Enroll again (for example after changing your Windows password)? [y/N]'
        $enroll = $answer -match '^(y|yes)$'
    }
    if ($enroll) {
        & $cli enroll
        if ($LASTEXITCODE -ne 0) { Stop-Setup 'Enrollment failed (see above). Run setup again to retry.' }
    }
    else {
        & $cli default on
    }

    Write-Host ''
    Write-Host 'All set.' -ForegroundColor Green
    Write-Host 'Lock the PC (Windows+L): the fingerprint tile is preselected. Press the key''s button if it asks, then touch the sensor.'
    Write-Host 'Your password and PIN stay available under "Sign-in options".'
    $exitCode = 0
}
catch {
    Write-Host ''
    Write-Host "Setup stopped: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Host ''
    Read-Host 'Press Enter to close this window' | Out-Null
}
exit $exitCode
