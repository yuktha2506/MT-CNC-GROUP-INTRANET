<#
  MT CNC-Group server-plant - apply the Plant Hub update to C:\server-plant
  Started by UPDATE-SERVER-PLANT.bat (Run as administrator).
#>
param(
  [string] $Source  = (Split-Path $PSScriptRoot -Parent),
  [string] $AppPath = "C:\server-plant",
  [string] $SiteIP  = "172.32.2.96",
  [int]    $Port    = 3001
)
$ErrorActionPreference = "Stop"
$log = Join-Path $PSScriptRoot "update-log.txt"
try { Start-Transcript -Path $log -Force | Out-Null } catch {}
function Step($t) { Write-Host ""; Write-Host "==== $t" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Bad($t)  { Write-Host "  [FAIL] $t" -ForegroundColor Red; $script:failed++ }
$script:failed = 0
# bcrypt hash of the Admin password supplied by IT (the password itself is not stored)
$AdminHash = '$2b$12$y.UDhCVL7HpWbinFQG4Sm.rRLoOMh2r3zIx.9MKIamGMH2e3wynBy'

if (-not (Test-Path (Join-Path $AppPath "backend.js"))) { throw "$AppPath\backend.js not found. Run INSTALL-SERVER-PLANT.bat first." }

Step "1/4  Backing up the current files"
$bk = Join-Path $AppPath ("backup\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force -Path $bk | Out-Null
foreach ($f in "api.js", "frontend.html", "web.config", ".env") { if (Test-Path (Join-Path $AppPath $f)) { Copy-Item (Join-Path $AppPath $f) $bk } }
& icacls $bk /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
Ok "Saved in $bk"

Step "2/4  Copying the new files"
if ((Resolve-Path $Source).Path.TrimEnd('\') -ne (Resolve-Path $AppPath).Path.TrimEnd('\')) {
  foreach ($f in "api.js", "frontend.html", "web.config", "README-FIRST.txt", "CHECK-SERVER-PLANT.bat", "RESTART-SERVER-PLANT.bat", "INSTALL-SERVER-PLANT.bat", "UPDATE-SERVER-PLANT.bat", "setup\server-plant-setup.ps1", "setup\hash.js") {
    $from = Join-Path $Source $f
    if (Test-Path $from) { Copy-Item $from (Join-Path $AppPath $f) -Force }
  }
}
Remove-Item (Join-Path $AppPath "execute.txt") -Force -ErrorAction SilentlyContinue
Ok "Plant Hub page and API copied"

Step "3/4  Admin password"
$envFile = Join-Path $AppPath ".env"
$lines = [IO.File]::ReadAllLines($envFile) | ForEach-Object { $_.TrimStart([char]0xFEFF) } | Where-Object { $_ -notmatch '^\s*ADMIN_PASSWORD_HASH\s*=' }
$lines = @($lines) + "ADMIN_PASSWORD_HASH=$AdminHash"
[IO.File]::WriteAllText($envFile, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
Ok "Admin password set (user name: Admin)"

Step "4/4  Restarting Node and checking"
Stop-ScheduledTask -TaskName "Server-Plant" -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -match 'backend\.js' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Start-ScheduledTask -TaskName "Server-Plant"
$up = $false
for ($i = 0; $i -lt 20 -and -not $up; $i++) { Start-Sleep 1; $up = [bool](Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue) }
if ($up) { Ok "Node is running on 127.0.0.1:3000" } else { Bad "Node did not start - last lines of logs\server.log:"; Get-Content (Join-Path $AppPath "logs\server.log") -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "         $_" } }
$base = "http://$($SiteIP):$Port"
foreach ($t in @(@("$base/", "Plant Hub"), @("$base/api/health", "online"))) {
  try { $r = Invoke-WebRequest $t[0] -UseBasicParsing -TimeoutSec 15; if ($r.Content -match $t[1]) { Ok "$($t[0])" } else { Bad "$($t[0]) answered but looks wrong" } }
  catch { Bad "$($t[0])  $($_.Exception.Message)" }
}
try { $r = Invoke-WebRequest "$base/api/auth/guest" -Method Post -ContentType "application/json" -Body "{}" -UseBasicParsing -TimeoutSec 15; if ($r.Content -match '"employee"') { Ok "Employees open the portal without a password" } else { Bad "Employee access check failed" } }
catch { Bad "Employee access: $($_.Exception.Message)" }

Write-Host ""
if ($script:failed) { Write-Host "  $($script:failed) check(s) failed - send setup\update-log.txt" -ForegroundColor Red }
else { Write-Host "  ALL GOOD - open $base/ and press Ctrl+F5" -ForegroundColor Green }
try { Stop-Transcript | Out-Null } catch {}
