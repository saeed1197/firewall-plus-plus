<#
.SYNOPSIS
    Starts the Firewall++ console - a local web UI for reviewing and editing
    the Windows Defender Firewall.

.DESCRIPTION
    Binds an HTTP listener to 127.0.0.1 only, mints a random session token, and
    opens the UI in your default browser. Administrator rights are required to
    change anything; without them the console starts in read-only mode.

.PARAMETER Port
    TCP port for the local console. Default 8777.

.PARAMETER NoElevate
    Do not prompt for elevation. The console runs read-only.

.PARAMETER NoBrowser
    Do not open a browser automatically; just print the URL.

.EXAMPLE
    .\Start-Firewall++.ps1
.EXAMPLE
    .\Start-Firewall++.ps1 -Port 9001 -NoBrowser
#>
[CmdletBinding()]
param(
    [int]$Port = 8777,
    [switch]$NoElevate,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find the next free TCP port starting from $Port
function Find-FreePort ([int]$Start) {
    $used = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() |
            ForEach-Object { $_.Port }
    $p = $Start
    while ($used -contains $p) { $p++ }
    return $p
}

Write-Host ''
Write-Host '  Firewall++ - Windows Firewall console' -ForegroundColor Cyan
Write-Host '  --------------------------------------' -ForegroundColor DarkGray

if (-not (Test-Admin) -and -not $NoElevate) {
    Write-Host '  Administrator rights are needed to modify firewall rules.'
    Write-Host '  Relaunching elevated (approve the UAC prompt)...' -ForegroundColor Yellow

    $exe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Port', $Port)
    if ($NoBrowser) { $args += '-NoBrowser' }
    try {
        Start-Process -FilePath $exe -ArgumentList $args -Verb RunAs
        Write-Host '  Elevated window started. You can close this one.' -ForegroundColor DarkGray
        exit 0
    } catch {
        Write-Host '  Elevation was declined - continuing in read-only mode.' -ForegroundColor Yellow
    }
}

# Resolve the actual port to use (auto-advance if requested port is busy)
$resolvedPort = Find-FreePort -Start $Port
if ($resolvedPort -ne $Port) {
    Write-Host "  Port $Port is in use - using port $resolvedPort instead." -ForegroundColor Yellow
}

# 32 hex chars of CSPRNG output, sent as the X-FW-Token header on every API call.
$bytes = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$token = -join ($bytes | ForEach-Object { $_.ToString('x2') })

$url = "http://127.0.0.1:$resolvedPort/#$token"
if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        param($u)
        Start-Sleep -Milliseconds 900
        Start-Process $u
    } -ArgumentList $url | Out-Null
}

& (Join-Path $root 'server\Server.ps1') -Port $resolvedPort -Token $token
