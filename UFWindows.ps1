<#
CCDC Splunk Universal Forwarder (Windows) installer/config
- Downloads UF MSI (BITS first, fallback to Invoke-WebRequest)
- Configures outputs.conf, server.conf, inputs.conf
- Monitors key Windows Event Logs (+ optional Sysmon/IIS/Firewall logs if present)
- Emits test events
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$Indexer = "",

  [Parameter(Mandatory=$false)]
  [string]$GitHubRepo = "",   # e.g. https://raw.githubusercontent.com/team/ccdc/main

  [Parameter(Mandatory=$false)]
  [switch]$FastDeploy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# One-run bypass only (does not persist)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# ---------- Config ----------
$SplunkHome = "${env:ProgramFiles}\SplunkUniversalForwarder"
$LocalConf  = Join-Path $SplunkHome "etc\system\local"
$SplunkExe  = Join-Path $SplunkHome "bin\splunk.exe"
$WorkDir    = "C:\CCDC\SplunkUF"
$LogDir     = "C:\CCDC\logs"
$LogFile    = Join-Path $LogDir "ccdc-uf-install.log"
$MsiName = ""
$MsiUrl  = ""



# ---------- UF download selection ----------
function Select-UFPackage {
  Write-Host ""
  Write-Host "Select Windows OS / target:"
  Write-Host "1) Windows Server 2016 (use UF 9.2.11 x64)"
  Write-Host "2) Windows Server 2019/2022 (use UF 10.2.0 x64)"
  Write-Host "3) Windows 10/11 (use UF 10.2.0 x64)"
  $choice = Read-Host "Choice [1-3]"

  switch ($choice) {
    "1" {
      $script:MsiName = "splunkforwarder-9.2.11-45e7d4c09780-x64-release.msi"
      $script:MsiUrl  = "https://download.splunk.com/products/universalforwarder/releases/9.2.11/windows/$($script:MsiName)"
    }
    "2" {
      $script:MsiName = "splunkforwarder-10.2.0-d749cb17ea65-windows-x64.msi"
      $script:MsiUrl  = "https://download.splunk.com/products/universalforwarder/releases/10.2.0/windows/$($script:MsiName)"
    }
    "3" {
      $script:MsiName = "splunkforwarder-10.2.0-d749cb17ea65-windows-x64.msi"
      $script:MsiUrl  = "https://download.splunk.com/products/universalforwarder/releases/10.2.0/windows/$($script:MsiName)"
    }
    default {
      Write-Host "[WARN] Invalid choice; defaulting to UF 10.2.0"
      $script:MsiName = "splunkforwarder-10.2.0-d749cb17ea65-windows-x64.msi"
      $script:MsiUrl  = "https://download.splunk.com/products/universalforwarder/releases/10.2.0/windows/$($script:MsiName)"
    }
  }

  Write-Host "[INFO] Selected MSI: $script:MsiName"
}

# ---------- Helpers ----------
function Ensure-Dir([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  if (-not $isAdmin) { throw "Run PowerShell as Administrator." }
}

function Assert-OSCompatibility {
  $os = Get-CimInstance Win32_OperatingSystem
  $caption = $os.Caption
  $ver = [Version]$os.Version
  $build = [int]$os.BuildNumber

  Write-Host "[INFO] OS: $caption ($ver / build $build)"

  # SetThreadDescription is supported starting Win10 1607 / Server 2016.
  # Win10 1607 build is 14393.
  if ($build -lt 14393) {
    throw "This Windows build is too old for UF 10.x (missing SetThreadDescription). Upgrade OS or use an older UF (9.x/8.x)."
  }
}

function Download-File([string]$Url, [string]$OutFile) {
  Write-Host "[DOWNLOAD] $Url"

  # Force TLS 1.2 for older PowerShell/WinHTTP stacks
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  # Prefer BITS (more reliable)
  try {
    Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
    return $true
  } catch {
    Write-Host "[WARN] BITS failed, trying Invoke-WebRequest..."
  }

  try {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    return $true
  } catch {
    return $false
  }
}

function Write-TextFile([string]$Path, [string]$Content) {
  Ensure-Dir (Split-Path -Parent $Path)
  $Content | Out-File -FilePath $Path -Encoding ascii -Force
}

function Install-UF([string]$MsiPath) {
  Write-Host "[INFO] Installing UF MSI..."
  $args = @(
    "/i", "`"$MsiPath`"",
    "AGREETOLICENSE=Yes",
    "INSTALLDIR=`"$SplunkHome`"",
    "/qn", "/norestart"
  )

  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "MSI install failed. ExitCode=$($p.ExitCode)" }
}

function Start-UF {
  if (Test-Path $SplunkExe) {
    & $SplunkExe start --accept-license --answer-yes --no-prompt | Out-Null
  }

  $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
  if ($null -eq $svc) { throw "SplunkForwarder service not found. UF may not have installed correctly." }

  if ($svc.Status -ne "Running") { Start-Service -Name "SplunkForwarder" }
}

function Restart-UF {
  $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
  if ($null -eq $svc) { throw "SplunkForwarder service not found." }
  Restart-Service -Name "SplunkForwarder" -Force
}

function Configure-Forwarding([string]$IndexerHost) {
  Ensure-Dir $LocalConf

  $serverConf = @"
[general]
serverName = $($env:COMPUTERNAME)-splunkfwd
"@

  $outputsConf = @"
[tcpout]
defaultGroup = primary

[tcpout:primary]
server = $IndexerHost`:9997
"@

  Write-TextFile (Join-Path $LocalConf "server.conf")  $serverConf
  Write-TextFile (Join-Path $LocalConf "outputs.conf") $outputsConf
  Write-Host "[OK] Wrote outputs.conf + server.conf"
}

function Configure-Inputs {
  Ensure-Dir $LocalConf

  $inputs = @"
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

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
"@

  $iis = "C:\inetpub\logs\LogFiles"
  if (Test-Path $iis) {
    $inputs += @"

[monitor://$iis]
disabled = 0
index = main
sourcetype = iis
crcSalt = <SOURCE>
"@
  }

  $fwlog = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
  if (Test-Path $fwlog) {
    $inputs += @"

[monitor://$fwlog]
disabled = 0
index = main
sourcetype = pfirewall
crcSalt = <SOURCE>
"@
  }

  Write-TextFile (Join-Path $LocalConf "inputs.conf") $inputs
  Write-Host "[OK] Wrote inputs.conf"
}

function Verify-UF {
  Write-Host ""
  Write-Host "=== Service ==="
  Get-Service SplunkForwarder | Format-Table Status,Name,DisplayName -AutoSize

  Write-Host ""
  Write-Host "=== Config files present ==="
  Get-ChildItem "$LocalConf\outputs.conf","$LocalConf\inputs.conf","$LocalConf\server.conf" -ErrorAction SilentlyContinue |
    Format-Table Name,Length,LastWriteTime -AutoSize

  Write-Host ""
  Write-Host "=== Forwarding connection (UF -> Indexer:9997) ==="
  Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemotePort -eq 9997 } |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State |
    Format-Table -AutoSize
}


function Emit-TestEvents {
  Write-Host "[TEST] Writing Application log event..."
  & eventcreate /T INFORMATION /ID 133 /L APPLICATION /SO CCDC_UF_TEST /D "CCDC_UF_TEST $env:COMPUTERNAME $(Get-Date -Format o)" | Out-Null

  Write-Host "[TEST] Generating Security log noise..."
  cmd.exe /c "whoami /all" | Out-Null
}

# ---------- Main ----------
Require-Admin
Select-UFPackage
Assert-OSCompatibility

Ensure-Dir $WorkDir
Ensure-Dir $LogDir
Start-Transcript -Path $LogFile -Append | Out-Null

try {
  if (-not $FastDeploy) {
    if ([string]::IsNullOrWhiteSpace($Indexer)) {
      $Indexer = Read-Host "Enter Indexer IP/hostname"
      if ([string]::IsNullOrWhiteSpace($Indexer)) { throw "Indexer cannot be empty." }
    }
  } else {
    if ([string]::IsNullOrWhiteSpace($Indexer)) { throw "FastDeploy requires -Indexer <ip/host>" }
    Write-Host "[FAST] Using indexer: $Indexer"
  }

  $msiPath = Join-Path $WorkDir $MsiName

  $downloaded = $false
  if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
    $ghUrl = "$GitHubRepo/splunk/$MsiName"
    Write-Host "[INFO] Trying GitHub repo first: $ghUrl"
    $downloaded = Download-File -Url $ghUrl -OutFile $msiPath
    if (-not $downloaded) { Write-Host "[WARN] GitHub download failed, falling back to Splunk..." }
  }
  if (-not $downloaded) {
    $downloaded = Download-File -Url $MsiUrl -OutFile $msiPath
  }
  if (-not $downloaded) { throw "Failed to download UF MSI." }

  if (-not (Test-Path $SplunkExe)) {
    Install-UF -MsiPath $msiPath
  } else {
    Write-Host "[INFO] UF already present at $SplunkHome"
  }

  Configure-Forwarding -IndexerHost $Indexer
  Configure-Inputs

  Start-UF
  Restart-UF

  Verify-UF
  Emit-TestEvents

  Write-Host ""
  Write-Host "DONE."
  Write-Host "Log: $LogFile"
  Write-Host "Search: index=main host=$($env:COMPUTERNAME) (CCDC_UF_TEST OR sourcetype=`"WinEventLog:*`")"
}
finally {
  Stop-Transcript | Out-Null
}
