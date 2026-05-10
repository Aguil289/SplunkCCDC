<#
.SYNOPSIS
  Splunk Universal Forwarder installer (Windows)
.DESCRIPTION
  Prompts for indexer IP, admin username, and admin password.
  Auto-selects MSI based on Windows build:
    Server 2016 (build 14393)        -> UF 9.4.8
    Server 2019+ / Win10 1809+       -> UF 9.4.11
  Configures basic Windows Event Log forwarding to <indexer>:9997.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# ---------- Config ----------
$SplunkHome = "${env:ProgramFiles}\SplunkUniversalForwarder"
$LocalConf  = Join-Path $SplunkHome "etc\system\local"
$SplunkExe  = Join-Path $SplunkHome "bin\splunk.exe"
$WorkDir    = "C:\SplunkUF"
$LogFile    = Join-Path $WorkDir "uf-install.log"

# MSI options — edit here if you need a different version
$MSI_SERVER2016 = @{
    Name = "splunkforwarder-9.4.8-c543277b24fa-windows-x64.msi"
    Url  = "https://download.splunk.com/products/universalforwarder/releases/9.4.8/windows/splunkforwarder-9.4.8-c543277b24fa-windows-x64.msi"
}
$MSI_NEWER = @{
    Name = "splunkforwarder-9.4.11-bbcbf19b5450-windows-x64.msi"
    Url  = "https://download.splunk.com/products/universalforwarder/releases/9.4.11/windows/splunkforwarder-9.4.11-bbcbf19b5450-windows-x64.msi"
}

# ---------- Helpers ----------
function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run PowerShell as Administrator." }
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Read-PasswordTwice([string]$Prompt) {
    while ($true) {
        $p1 = Read-Host -Prompt $Prompt -AsSecureString
        $p2 = Read-Host -Prompt "Confirm password" -AsSecureString

        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
        $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
        try {
            $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b1)
            $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b2)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
        }

        if ($plain1 -ne $plain2) {
            Write-Host "Passwords do not match. Try again." -ForegroundColor Yellow
            continue
        }
        if ($plain1.Length -lt 8) {
            Write-Host "Password must be at least 8 characters." -ForegroundColor Yellow
            continue
        }
        return $plain1
    }
}

function Pick-MSI {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    Write-Host "[INFO] OS: $($os.Caption) (build $build)"

    if ($build -lt 14393) {
        throw "Windows build $build is older than Server 2016 (14393). Unsupported by this script."
    }

    if ($build -le 14393) {
        Write-Host "[INFO] Selecting UF 9.4.8 (Server 2016)"
        return $MSI_SERVER2016
    } else {
        Write-Host "[INFO] Selecting UF 9.4.11 (Server 2019+ / Win10 1809+)"
        return $MSI_NEWER
    }
}

function Download-MSI([string]$Url, [string]$OutFile) {
    Write-Host "[INFO] Downloading $Url"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    try {
        Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
        return
    } catch {
        Write-Host "[WARN] BITS failed; falling back to Invoke-WebRequest"
    }
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
}

function Install-MSI([string]$MsiPath) {
    Write-Host "[INFO] Installing UF (silent)..."
    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "AGREETOLICENSE=Yes",
        "INSTALLDIR=`"$SplunkHome`"",
        "/qn", "/norestart"
    )
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec failed: ExitCode=$($p.ExitCode)" }
    Write-Host "[OK] Install complete"
}

function Write-Config([string]$Username, [string]$Password, [string]$IndexerHost) {
    Ensure-Dir $LocalConf

    # user-seed.conf — Splunk consumes this on first start
    $userSeed = @"
[user_info]
USERNAME = $Username
PASSWORD = $Password
"@
    $seedPath = Join-Path $LocalConf "user-seed.conf"
    $userSeed | Out-File -FilePath $seedPath -Encoding ascii -Force
    # Lock ACL down to SYSTEM + Administrators only
    icacls $seedPath /inheritance:r /grant "SYSTEM:(F)" "Administrators:(F)" | Out-Null

    # server.conf
    @"
[general]
serverName = $($env:COMPUTERNAME)-uf
"@ | Out-File -FilePath (Join-Path $LocalConf "server.conf") -Encoding ascii -Force

    # outputs.conf
    @"
[tcpout]
defaultGroup = primary

[tcpout:primary]
server = ${IndexerHost}:9997
"@ | Out-File -FilePath (Join-Path $LocalConf "outputs.conf") -Encoding ascii -Force

    # inputs.conf — standard Windows event logs
    @"
[default]
index = main

[WinEventLog://Application]
disabled = 0
renderXml = true

[WinEventLog://System]
disabled = 0
renderXml = true

[WinEventLog://Security]
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true
"@ | Out-File -FilePath (Join-Path $LocalConf "inputs.conf") -Encoding ascii -Force

    Write-Host "[OK] Configs written to $LocalConf"
}

function Start-UF {
    if (-not (Test-Path $SplunkExe)) { throw "splunk.exe not found at $SplunkExe" }
    & $SplunkExe start --accept-license --answer-yes --no-prompt | Out-Null

    $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($null -eq $svc) { throw "SplunkForwarder service not found after install." }
    if ($svc.Status -ne "Running") { Start-Service -Name "SplunkForwarder" }
    Write-Host "[OK] Service running"
}

function Cleanup-UserSeed {
    # Splunk processes user-seed.conf on first start and writes to etc/passwd
    $userPasswd = Join-Path $SplunkHome "etc\passwd"
    $seedPath   = Join-Path $LocalConf "user-seed.conf"
    if ((Test-Path $userPasswd) -and (Test-Path $seedPath)) {
        Remove-Item $seedPath -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed user-seed.conf (creds consumed by Splunk)"
    } else {
        Write-Host "[WARN] user-seed.conf still present — Splunk may not have processed it yet."
    }
}

# ---------- Main ----------
Require-Admin
Ensure-Dir $WorkDir
Start-Transcript -Path $LogFile -Append | Out-Null

try {
    # --- Prompts ---
    $Indexer = Read-Host "Enter indexer IP/hostname"
    if ([string]::IsNullOrWhiteSpace($Indexer)) { throw "Indexer cannot be empty." }

    $AdminUser = Read-Host "Enter Splunk admin username [admin]"
    if ([string]::IsNullOrWhiteSpace($AdminUser)) { $AdminUser = "admin" }

    $AdminPass = Read-PasswordTwice "Enter Splunk admin password (>=8 chars)"

    # --- Download + install ---
    $msi = Pick-MSI
    $msiPath = Join-Path $WorkDir $msi.Name
    if (-not (Test-Path $msiPath)) {
        Download-MSI -Url $msi.Url -OutFile $msiPath
    } else {
        Write-Host "[INFO] MSI already present at $msiPath"
    }

    if (-not (Test-Path $SplunkExe)) {
        Install-MSI -MsiPath $msiPath
    } else {
        Write-Host "[INFO] UF already installed at $SplunkHome"
    }

    # --- Configure + start ---
    Write-Config -Username $AdminUser -Password $AdminPass -IndexerHost $Indexer
    Remove-Variable AdminPass -ErrorAction SilentlyContinue

    Start-UF
    Start-Sleep -Seconds 5
    Cleanup-UserSeed

    # --- Verify ---
    Write-Host ""
    Write-Host "=== Service status ==="
    Get-Service SplunkForwarder | Format-Table Status, Name, DisplayName -AutoSize

    Write-Host "=== Forwarding connection (waiting 10s for handshake) ==="
    Start-Sleep -Seconds 10
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemotePort -eq 9997 }
    if ($conns) {
        $conns | Format-Table LocalAddress, RemoteAddress, RemotePort, State -AutoSize
        Write-Host "[OK] Established connection to indexer on :9997"
    } else {
        Write-Host "[WARN] No established :9997 connection yet. Check firewall + indexer reachability."
    }

    Write-Host ""
    Write-Host "DONE. Log: $LogFile"
    Write-Host "Search in Splunk: index=main host=$($env:COMPUTERNAME)"
}
finally {
    Stop-Transcript | Out-Null
}
