@echo off
rem MT CNC browser launcher - one-time setup for this Windows user.
rem Version 2. Lets the intranet open business apps in Edge, Chrome or Firefox and
rem start remote-support tools (Quick Assist, AnyDesk, UltraViewer, TeamViewer QuickSupport).
rem No administrator rights needed. To remove:  Install-MTCNC-Browser-Launcher.bat /uninstall
setlocal
set "SETUPFILE=%~f0"
set "DIR=%LOCALAPPDATA%\MTCNC\BrowserLauncher"
set "KEY=HKCU\Software\Classes\mtcnc-browser"
set "TKEY=HKCU\Software\Classes\mtcnc-tool"

if /i "%~1"=="/uninstall" (
  reg delete "%KEY%" /f >nul 2>&1
  reg delete "%TKEY%" /f >nul 2>&1
  if exist "%DIR%" rmdir /s /q "%DIR%"
  echo MT CNC browser launcher removed.
  pause
  exit /b 0
)

if not exist "%DIR%" mkdir "%DIR%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:SETUPFILE); $m='###'+'PS1###'; $i=$t.LastIndexOf($m); [IO.File]::WriteAllText((Join-Path $env:DIR 'Open-InBrowser.ps1'), $t.Substring($i+$m.Length).TrimStart(), (New-Object Text.UTF8Encoding $true))"
if errorlevel 1 goto failed
if not exist "%DIR%\Open-InBrowser.ps1" goto failed

reg add "%KEY%" /ve /t REG_SZ /d "URL:MT CNC browser launcher" /f >nul || goto failed
reg add "%KEY%" /v "URL Protocol" /t REG_SZ /d "" /f >nul || goto failed
reg add "%KEY%\shell\open\command" /ve /t REG_SZ /d "\"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%DIR%\Open-InBrowser.ps1\" \"%%1\"" /f >nul || goto failed
reg add "%TKEY%" /ve /t REG_SZ /d "URL:MT CNC remote-support tools" /f >nul || goto failed
reg add "%TKEY%" /v "URL Protocol" /t REG_SZ /d "" /f >nul || goto failed
reg add "%TKEY%\shell\open\command" /ve /t REG_SZ /d "\"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%DIR%\Open-InBrowser.ps1\" \"%%1\"" /f >nul || goto failed

echo.
echo  MT CNC launcher version 2 is installed (browsers and remote-support tools).
echo  Go back to the intranet and try again.
echo  If the browser asks "Open MT CNC browser launcher?", tick "Always allow" and choose Open.
echo.
pause
exit /b 0

:failed
echo.
echo  Setup did not finish. Please contact IT.
pause
exit /b 1
###PS1###
# MT CNC browser launcher (version 2). Called by Windows for intranet links like:
#   mtcnc-browser:open?b=chrome&u=https%3A%2F%2Fexample.com%2F   open a link in a browser
#   mtcnc-tool:open?t=anydesk                                        start a remote-support tool
# Tools run from their installed location, or else from a portable copy in the IT
# Utilities folder. A copy is only started if it carries a valid digital signature
# from that tool's publisher. Nothing here needs or asks for an administrator password.
param([string]$Link = '')
$ErrorActionPreference = 'Stop'
$Title = 'MT CNC browser launcher'

$Browsers = [ordered]@{
  chrome  = @{ Name = 'Google Chrome';   Exe = 'chrome.exe';  Download = 'https://www.google.com/chrome/';
               Paths = @('%ProgramFiles%\Google\Chrome\Application\chrome.exe', '%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe', '%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe') }
  edge    = @{ Name = 'Microsoft Edge';  Exe = 'msedge.exe';  Download = 'https://www.microsoft.com/edge/download';
               Paths = @('%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe', '%ProgramFiles%\Microsoft\Edge\Application\msedge.exe') }
  firefox = @{ Name = 'Mozilla Firefox'; Exe = 'firefox.exe'; Download = 'https://www.mozilla.org/firefox/new/';
               Paths = @('%ProgramFiles%\Mozilla Firefox\firefox.exe', '%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe', '%LOCALAPPDATA%\Mozilla Firefox\firefox.exe') }
  brave   = @{ Name = 'Brave';           Exe = 'brave.exe';   Download = 'https://brave.com/download/';
               Paths = @('%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe', '%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe', '%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe') }
  opera   = @{ Name = 'Opera';           Exe = 'opera.exe';   Download = 'https://www.opera.com/download';
               Paths = @('%LOCALAPPDATA%\Programs\Opera\launcher.exe', '%ProgramFiles%\Opera\launcher.exe', '%ProgramFiles(x86)%\Opera\launcher.exe') }
}

$ToolShare = '\\172.32.2.12\Ftp\Utilities'
$ToolCache = Join-Path $env:LOCALAPPDATA 'MTCNC\Tools'
$Tools = [ordered]@{
  quickassist = @{ Name = 'Quick Assist'; Uri = 'ms-quick-assist:'; Store = 'ms-windows-store://pdp/?productid=9P7BP5VNWKX5' }
  anydesk     = @{ Name = 'AnyDesk'; Signer = 'AnyDesk|philandro'; Portable = @('AnyDesk.exe'); Match = '^AnyDesk'; Exe = 'AnyDesk.exe';
                   Installed = @('%ProgramFiles(x86)%\AnyDesk\AnyDesk.exe', '%ProgramFiles%\AnyDesk\AnyDesk.exe') }
  ultraviewer = @{ Name = 'UltraViewer'; Signer = 'DucFabulous|UltraViewer'; Portable = @(); Setup = 'UltraViewer*setup*.exe'; Match = '^UltraViewer'; Exe = 'UltraViewer_Desktop.exe';
                   Installed = @('%ProgramFiles(x86)%\UltraViewer\UltraViewer_Desktop.exe', '%ProgramFiles%\UltraViewer\UltraViewer_Desktop.exe') }
  teamviewer  = @{ Name = 'TeamViewer QuickSupport'; Signer = 'TeamViewer'; Portable = @('TeamViewerQS.exe', 'TeamViewerQS_x64.exe'); Match = '^TeamViewer'; Exe = 'TeamViewer.exe';
                   Installed = @('%ProgramFiles%\TeamViewer\TeamViewer.exe', '%ProgramFiles(x86)%\TeamViewer\TeamViewer.exe') }
}

function Show-Message([string]$Text, [string]$Buttons = 'OK', [string]$Icon = 'Information') {
  Add-Type -AssemblyName System.Windows.Forms
  return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

function Find-Browser($Browser) {
  $keys = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($Browser.Exe)",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($Browser.Exe)",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$($Browser.Exe)"
  )
  foreach ($key in $keys) {
    try {
      $value = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
      if ($value) { $value = $value.Trim().Trim('"'); if (Test-Path -LiteralPath $value) { return $value } }
    } catch { }
  }
  foreach ($path in $Browser.Paths) {
    $full = [Environment]::ExpandEnvironmentVariables($path)
    if (Test-Path -LiteralPath $full) { return $full }
  }
  return $null
}

function Read-Link([string]$Text) {
  $result = @{}
  if ($Text -notmatch '^mtcnc-(browser|tool):(//)?([a-zA-Z]+)') { return $result }
  $result['_action'] = if ($Matches[1].ToLowerInvariant() -eq 'tool') { 'tool' } else { $Matches[3].ToLowerInvariant() }
  $q = $Text.IndexOf('?')
  if ($q -lt 0) { return $result }
  foreach ($pair in $Text.Substring($q + 1).Split('&')) {
    $kv = $pair.Split('=', 2)
    if ($kv.Count -eq 2) { $result[$kv[0].ToLowerInvariant()] = [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
  }
  return $result
}

function Test-Signed([string]$Path, [string]$Signer) {
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match $Signer)
  } catch { return $false }
}

# Finds an installed tool: known folders first, then the Windows "installed apps" list.
function Find-InstalledTool($Tool) {
  foreach ($path in $Tool.Installed) {
    $full = [Environment]::ExpandEnvironmentVariables($path)
    if (Test-Path -LiteralPath $full) { return $full }
  }
  if (-not $Tool.Match) { return $null }
  $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
  foreach ($root in $roots) {
    $apps = @()
    try { $apps = @(Get-ItemProperty -Path $root -ErrorAction Stop | Where-Object { $_.DisplayName -match $Tool.Match }) } catch { }
    foreach ($app in $apps) {
      $candidates = @()
      if ($app.InstallLocation) { $candidates += (Join-Path ([string]$app.InstallLocation).Trim('"') $Tool.Exe) }
      if ($app.DisplayIcon) { $candidates += ([string]$app.DisplayIcon -replace ',\s*-?\d+$', '').Trim().Trim('"') }
      foreach ($c in $candidates) {
        if ($c -and (Split-Path -Leaf $c) -ieq $Tool.Exe -and (Test-Path -LiteralPath $c)) { return $c }
      }
    }
  }
  return $null
}

function Start-Tool([string]$Key) {
  $nl = [Environment]::NewLine
  if (-not $Tools.Contains($Key)) { [void](Show-Message 'This link did not name a tool the launcher knows.' 'OK' 'Warning'); return 1 }
  $tool = $Tools[$Key]
  if ($tool.Uri) {
    try { Start-Process $tool.Uri; return 0 } catch {
      $answer = Show-Message ("$($tool.Name) is not on this PC." + $nl + $nl + 'Open Microsoft Store to get it? No administrator password is needed.') 'YesNo' 'Question'
      if ([string]$answer -eq 'Yes') { Start-Process $tool.Store }
      return 2
    }
  }
  $installed = Find-InstalledTool $tool
  if ($installed) { Start-Process -FilePath $installed; return 0 }
  foreach ($file in $tool.Portable) {
    $local = Join-Path $ToolCache $file
    $source = Join-Path $ToolShare $file
    try {
      if (Test-Path -LiteralPath $source) {
        New-Item -ItemType Directory -Force -Path $ToolCache | Out-Null
        Copy-Item -LiteralPath $source -Destination $local -Force
      }
    } catch { }
    if (Test-Path -LiteralPath $local) {
      if (Test-Signed $local $tool.Signer) { Start-Process -FilePath $local; return 0 }
      Remove-Item -LiteralPath $local -Force -ErrorAction SilentlyContinue
      [void](Show-Message ("The copy of $($tool.Name) in the Utilities folder is not signed by its publisher, so it was not started." + $nl + 'Please tell IT.') 'OK' 'Warning')
      return 3
    }
  }
  if ($tool.Setup) {
    $setup = $null
    try { $setup = Get-ChildItem -LiteralPath $ToolShare -Filter $tool.Setup -File -ErrorAction Stop | Select-Object -First 1 } catch { }
    if ($setup -and (Test-Signed $setup.FullName $tool.Signer)) {
      $answer = Show-Message ("$($tool.Name) is not installed on this PC and has no portable version." + $nl + $nl + 'Run its installer from the Utilities folder now? Windows will ask for an administrator to approve it.') 'YesNo' 'Question'
      if ([string]$answer -eq 'Yes') { Start-Process -FilePath $setup.FullName }
      return 2
    }
  }
  $other = if ($Key -eq 'anydesk') { 'Use Quick Assist instead, or call IT.' } else { 'Use Quick Assist or AnyDesk instead, or call IT.' }
  [void](Show-Message ("$($tool.Name) is not installed on this PC and was not found in $ToolShare." + $nl + $nl + $other) 'OK' 'Information')
  return 2
}

$p = Read-Link $Link
if ($p['_action'] -eq 'tool') { exit (Start-Tool ([string]$p['t']).ToLowerInvariant()) }
$key = ([string]$p['b']).ToLowerInvariant()
if (-not $Browsers.Contains($key)) { [void](Show-Message 'This link did not name a browser the launcher knows.' 'OK' 'Warning'); exit 1 }
$browser = $Browsers[$key]

$uri = $null
if (-not [Uri]::TryCreate([string]$p['u'], [UriKind]::Absolute, [ref]$uri) -or ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https')) {
  [void](Show-Message 'Only web addresses (http or https) can be opened.' 'OK' 'Warning'); exit 1
}

$exe = Find-Browser $browser
if (-not $exe) {
  $nl = [Environment]::NewLine
  $answer = Show-Message ("$($browser.Name) is not installed on this PC." + $nl + $nl + "Open the $($browser.Name) download page now?") 'YesNo' 'Question'
  if ([string]$answer -eq 'Yes') { Start-Process $browser.Download }
  exit 2
}

# AbsoluteUri is fully escaped (no spaces or quotes), so it is passed as one safe argument.
Start-Process -FilePath $exe -ArgumentList ('"' + $uri.AbsoluteUri + '"')
exit 0
