<#
  MT CNC-Group server-plant - full setup for IIS on Windows Server
  Started by INSTALL-SERVER-PLANT.bat (Run as administrator).

  Result:
    Users open   http://172.32.2.96:3001/   (IIS: frontend.html + proxy)
    Node runs on 127.0.0.1:3000 only        (scheduled task "Server-Plant", starts at boot)
#>
param(
  [string] $Source     = (Split-Path $PSScriptRoot -Parent),
  [string] $AppPath    = "C:\server-plant",
  [string] $SiteName   = "",
  [string] $SiteIP     = "172.32.2.96",
  [int]    $Port       = 3001,
  [string] $NodeVersion = "22.22.0",
  [switch] $CheckOnly
)

$ErrorActionPreference = "Stop"
$NodePort = 3000                      # backend.js always uses 3000 in production
$log = Join-Path $PSScriptRoot "setup-log.txt"
try { Start-Transcript -Path $log -Force | Out-Null } catch {}
$script:failed = 0
function Step($t) { Write-Host ""; Write-Host "==== $t" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Info($t) { Write-Host "         $t" -ForegroundColor Gray }
function Warn($t) { Write-Host "  [WARN] $t" -ForegroundColor Yellow }
function Bad($t)  { Write-Host "  [FAIL] $t" -ForegroundColor Red; $script:failed++ }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$utf8 = New-Object System.Text.UTF8Encoding($false)   # .env must NOT have a BOM
$inetsrv = Join-Path $env:windir "System32\inetsrv"
$appcmd  = Join-Path $inetsrv "appcmd.exe"
$TaskName = "Server-Plant"

function Test-Url($url) {
  try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
    return [pscustomobject]@{ Code = [int]$r.StatusCode; Body = [string]$r.Content }
  } catch {
    $code = 0; $body = $_.Exception.Message
    if ($_.Exception.Response) {
      $code = [int]$_.Exception.Response.StatusCode
      try { $body = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch {}
    }
    return [pscustomobject]@{ Code = $code; Body = $body }
  }
}
function Read-Password($label) {
  while ($true) {
    $a = Read-Host "  Enter the new $label password" -AsSecureString
    $b = Read-Host "  Type it again" -AsSecureString
    $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
    $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
    if ($pa.Length -lt 6) { Warn "Use at least 6 characters."; continue }
    if ($pa -ne $pb)      { Warn "The two entries do not match. Try again."; continue }
    return $pa
  }
}
function Get-Hash($node, $plain) {
  $env:MTC_PW = $plain
  try { $h = & $node (Join-Path $AppPath "setup\hash.js") } finally { Remove-Item Env:\MTC_PW -ErrorAction SilentlyContinue }
  if ($h -notmatch '^\$2[aby]\$\d\d\$') { throw "Could not create the password hash." }
  return $h.Trim()
}
function Find-Site {
  Import-Module WebAdministration
  if ($SiteName) { if (Test-Path "IIS:\Sites\$SiteName") { return $SiteName } else { return $null } }
  foreach ($s in Get-Website) {
    foreach ($b in $s.bindings.Collection) { if ($b.bindingInformation -match ":$($Port):") { return $s.name } }
  }
  return $null
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run as administrator." }

if (-not $CheckOnly) {
# 1 ----------------------------------------------------------------------------
Step "1/8  Checking IIS, URL Rewrite and ARR"
if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
  Install-WindowsFeature Web-Server, Web-WebSockets, Web-Mgmt-Console | Out-Null
}
if (Test-Path (Join-Path $inetsrv "rewrite.dll")) { Ok "URL Rewrite is installed" } else { Bad "URL Rewrite 2.1 is missing - run INSTALL-MTCNC.bat once, or install it from iis.net" }
$arr = (Test-Path "$env:ProgramFiles\IIS\Application Request Routing\requestRouter.dll") -or (Test-Path (Join-Path $inetsrv "requestRouter.dll"))
if ($arr) { Ok "Application Request Routing is installed" } else { Bad "ARR 3.0 is missing - install it from iis.net" }
if ($script:failed) { throw "Install the missing IIS modules, then run this again." }
& $appcmd set config -section:system.webServer/proxy /enabled:"True" /preserveHostHeader:"True" /commit:apphost | Out-Null
Ok "ARR proxy is switched on"

# 2 ----------------------------------------------------------------------------
Step "2/8  Stopping the old MTCNC v3 service (it is replaced by server-plant)"
foreach ($old in "MTCNC-Intranet", $TaskName) {
  $t = Get-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue
  if ($t) {
    Stop-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue
    if ($old -ne $TaskName) { Disable-ScheduledTask -TaskName $old | Out-Null; Ok "Task '$old' stopped and disabled (not deleted)" }
  }
}
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {
  $_.CommandLine -match 'server\.js|backend\.js'
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Info "Stopped node.exe (PID $($_.ProcessId))" }
Start-Sleep 2
$busy = Get-NetTCPConnection -LocalPort $NodePort -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  $p = Get-Process -Id $busy[0].OwningProcess -ErrorAction SilentlyContinue
  throw "Port $NodePort is used by '$($p.ProcessName)' (PID $($busy[0].OwningProcess)). Stop that program, then run this again."
}
Ok "Port $NodePort is free"

# 3 ----------------------------------------------------------------------------
Step "3/8  Copying the application to $AppPath"
New-Item -ItemType Directory -Force -Path $AppPath, (Join-Path $AppPath "logs") | Out-Null
if ((Resolve-Path $Source).Path.TrimEnd('\') -ne (Resolve-Path $AppPath).Path.TrimEnd('\')) {
  & robocopy $Source $AppPath /E /NFL /NDL /NJH /NJS /NP /XF ".env" "execute.txt" "setup-log.txt" /XD "logs" "runtime" | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "Copy failed (robocopy code $LASTEXITCODE)" }
}
Remove-Item (Join-Path $AppPath "execute.txt") -Force -ErrorAction SilentlyContinue
Ok "Files copied (an existing .env is kept)"

# 4 ----------------------------------------------------------------------------
Step "4/8  Node.js $NodeVersion (private copy for this app)"
$runtime = Join-Path $AppPath "runtime"
$node = Join-Path $runtime "node.exe"
$have = if (Test-Path $node) { (& $node -v) } else { "" }
if ($have -ne "v$NodeVersion") {
  $zipName = "node-v$NodeVersion-win-x64.zip"
  $zip = Join-Path $PSScriptRoot $zipName
  if (-not (Test-Path $zip)) {
    Info "Downloading $zipName ..."
    try { Invoke-WebRequest "https://nodejs.org/dist/v$NodeVersion/$zipName" -OutFile $zip -UseBasicParsing }
    catch { Remove-Item $zip -ErrorAction SilentlyContinue; Warn "Download failed: $($_.Exception.Message)" }
  }
  if (Test-Path $zip) {
    $tmp = Join-Path $env:TEMP "node-extract"
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip -DestinationPath $tmp -Force
    Remove-Item $runtime -Recurse -Force -ErrorAction SilentlyContinue
    Move-Item (Join-Path $tmp "node-v$NodeVersion-win-x64") $runtime
    Ok "Node $(& $node -v) installed in $runtime (the system Node is not changed)"
  } else {
    $sys = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $sys) { throw "No Node.js found. Copy $zipName from nodejs.org into the setup folder and run again." }
    $node = $sys
    Warn "Using the system Node $(& $node -v). The app is built for Node 22; if it fails, copy $zipName into the setup folder and run again."
  }
} else { Ok "Node $have already present" }
if (-not (Test-Path (Join-Path $AppPath "node_modules\express"))) {
  $npm = Join-Path (Split-Path $node) "npm.cmd"
  Push-Location $AppPath; & $npm install --omit=dev; Pop-Location
}
Ok "Packages present"

# 5 ----------------------------------------------------------------------------
Step "5/8  Settings file (.env) and passwords"
$envFile = Join-Path $AppPath ".env"
$lines = [ordered]@{}
if (Test-Path $envFile) {
  foreach ($l in [IO.File]::ReadAllLines($envFile)) {
    $l = $l.TrimStart([char]0xFEFF)
    if ($l -match '^\s*([A-Z_]+)\s*=(.*)$') { $lines[$Matches[1]] = $Matches[2] }
  }
}
$lines["NODE_ENV"] = "production"; $lines["HOST"] = "127.0.0.1"; $lines["PORT"] = "$NodePort"
if (-not $lines["COOKIE_SECURE"]) { $lines["COOKIE_SECURE"] = "false" }
if (-not $lines["JWT_SECRET"] -or $lines["JWT_SECRET"].Length -lt 32 -or $lines["JWT_SECRET"] -match 'replace') {
  $bytes = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $lines["JWT_SECRET"] = ([BitConverter]::ToString($bytes) -replace '-', '').ToLower()
  Ok "New random JWT_SECRET created"
}
foreach ($acct in @(@{Key="ADMIN_PASSWORD_HASH"; Label="Admin"}, @{Key="EMPLOYEE_PASSWORD_HASH"; Label="Employee (login 00000101)"})) {
  if (-not $lines[$acct.Key] -or $lines[$acct.Key] -notmatch '^\$2[aby]\$') {
    Write-Host ""
    $lines[$acct.Key] = Get-Hash $node (Read-Password $acct.Label)
    Ok "$($acct.Label) password saved (only a bcrypt hash is stored)"
  } else { Ok "$($acct.Key) already set - kept" }
}
$text = ($lines.Keys | ForEach-Object { "$_=$($lines[$_])" }) -join "`r`n"
[IO.File]::WriteAllText($envFile, $text + "`r`n", $utf8)
& icacls $envFile /inheritance:r /grant:r "SYSTEM:F" "BUILTIN\Administrators:F" | Out-Null
Ok ".env written (no BOM), readable only by SYSTEM and Administrators"

# 6 ----------------------------------------------------------------------------
Step "6/8  Node background task '$TaskName'"
$runner = Join-Path $AppPath "run-server-plant.cmd"
$cmd = @"
@echo off
cd /d "$AppPath"
:loop
echo [%date% %time%] starting backend.js>> "$AppPath\logs\server.log"
"$node" backend.js >> "$AppPath\logs\server.log" 2>&1
echo [%date% %time%] backend.js stopped, restarting in 5 s>> "$AppPath\logs\server.log"
ping -n 6 127.0.0.1 >nul
goto loop
"@
[IO.File]::WriteAllText($runner, $cmd, (New-Object System.Text.ASCIIEncoding))
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
$action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runner`"" -WorkingDirectory $AppPath
$trigger   = New-ScheduledTaskTrigger -AtStartup
$tp        = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $tp -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $TaskName
$up = $false
for ($i = 0; $i -lt 20 -and -not $up; $i++) { Start-Sleep 1; $up = [bool](Get-NetTCPConnection -LocalPort $NodePort -State Listen -ErrorAction SilentlyContinue) }
if ($up) { Ok "Node is listening on 127.0.0.1:$NodePort and starts automatically at boot" }
else {
  Bad "Node did not start. Last lines of logs\server.log:"
  Get-Content (Join-Path $AppPath "logs\server.log") -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ }
}

# 7 ----------------------------------------------------------------------------
Step "7/8  IIS site on port $Port"
$site = Find-Site
& icacls $AppPath /grant "IIS_IUSRS:(OI)(CI)RX" | Out-Null
if ($site) {
  Set-ItemProperty "IIS:\Sites\$site" -Name physicalPath -Value $AppPath
  $pool = (Get-Item "IIS:\Sites\$site").applicationPool
  Set-ItemProperty "IIS:\AppPools\$pool" -Name managedRuntimeVersion -Value ""
  Ok "Existing site '$site' now points to $AppPath (binding kept)"
} else {
  $site = "Server-Plant"
  if (-not (Test-Path "IIS:\AppPools\$site")) { New-WebAppPool -Name $site | Out-Null }
  Set-ItemProperty "IIS:\AppPools\$site" -Name managedRuntimeVersion -Value ""
  New-Website -Name $site -PhysicalPath $AppPath -IPAddress $SiteIP -Port $Port -ApplicationPool $site | Out-Null
  Ok "Site '$site' created: http://$($SiteIP):$Port/"
}
Stop-Website -Name $site -ErrorAction SilentlyContinue; Start-Website -Name $site
if (-not (Get-NetFirewallRule -DisplayName "Server-Plant IIS $Port" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName "Server-Plant IIS $Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
}
Ok "Firewall allows TCP $Port (port $NodePort stays closed)"
} # end of install part

# 8 ----------------------------------------------------------------------------
Step "8/8  Checks"
$r = Test-Url "http://127.0.0.1:$NodePort/api/health"
if ($r.Code -eq 200) { Ok "Node health      200  $($r.Body)" } else { Bad "Node health      $($r.Code)  $($r.Body)"; Get-Content "$AppPath\logs\server.log" -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Info $_ } }
$base = "http://$($SiteIP):$Port"
$r = Test-Url "$base/"
if ($r.Code -eq 200 -and $r.Body -match 'MT CNC') { Ok "Home page        200  $base/" } else { Bad "Home page        $($r.Code)  $base/"; Info ($r.Body.Substring(0, [Math]::Min(600, $r.Body.Length))) }
$r = Test-Url "$base/api/health"
if ($r.Code -eq 200) { Ok "IIS -> Node API  200" } else { Bad "IIS -> Node API  $($r.Code)  $($r.Body)" }
$r = Test-Url "$base/socket.io/socket.io.js"
if ($r.Code -eq 200) { Ok "Socket.IO script 200" } else { Bad "Socket.IO script $($r.Code)" }
foreach ($secret in "/.env", "/backend.js", "/api.js", "/package.json", "/run-server-plant.cmd", "/logs/server.log") {
  $r = Test-Url "$base$secret"
  if ($r.Code -eq 404 -or $r.Code -eq 403) { Ok "Blocked          $($r.Code)  $secret" } else { Bad "NOT blocked      $($r.Code)  $secret" }
}

Write-Host ""
if ($script:failed) { Write-Host "  $($script:failed) check(s) failed - send setup\setup-log.txt" -ForegroundColor Red }
else { Write-Host "  ALL GOOD - open $base/ in a browser" -ForegroundColor Green }
try { Stop-Transcript | Out-Null } catch {}
