# Email Test Tools installer for Windows (no admin rights needed).
#
#   irm https://raw.githubusercontent.com/nahidacm/email-test-tools/main/scripts/install.ps1 | iex
#
# Installs to %LOCALAPPDATA%\Programs\Email Test Tools, adds it to your user PATH
# and creates a Start Menu shortcut. Set $env:VERSION = "v0.1.0" to pin a version.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'nahidacm/email-test-tools'
$Version = $env:VERSION
if (-not $Version) {
  Write-Host '==> Finding the latest release...'
  $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
}
$Num = $Version.TrimStart('v')
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x86_64' }
$File = "email-test-tools_${Num}_windows_${Arch}.zip"
$Url = "https://github.com/$Repo/releases/download/$Version"

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("ett-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  Write-Host "==> Downloading $File ($Version)..."
  Invoke-WebRequest "$Url/$File" -OutFile "$Tmp\$File"
  Invoke-WebRequest "$Url/checksums.txt" -OutFile "$Tmp\checksums.txt"

  Write-Host '==> Verifying checksum...'
  $line = Select-String -Path "$Tmp\checksums.txt" -Pattern ([regex]::Escape($File) + '$') | Select-Object -First 1
  if (-not $line) { throw "No checksum listed for $File" }
  $expected = ($line.Line -split '\s+')[0]
  $actual = (Get-FileHash "$Tmp\$File" -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw 'Checksum mismatch. The download may be corrupted.' }

  $Dest = Join-Path $env:LOCALAPPDATA 'Programs\Email Test Tools'
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  Expand-Archive "$Tmp\$File" -DestinationPath $Tmp -Force
  Copy-Item "$Tmp\email-test-tools.exe" $Dest -Force
  Write-Host "==> Installed to $Dest"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $Dest) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$Dest".TrimStart(';'), 'User')
    Write-Host '==> Added to your PATH (open a new terminal to use it)'
  }

  $lnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'Email Test Tools.lnk'
  $ws = New-Object -ComObject WScript.Shell
  $sc = $ws.CreateShortcut($lnk)
  $sc.TargetPath = "$Dest\email-test-tools.exe"
  $sc.WorkingDirectory = $Dest
  $sc.Save()

  Write-Host ''
  Write-Host "  Email Test Tools $Version installed." -ForegroundColor Green
  Write-Host '  Start it from the Start Menu, or run: email-test-tools'
  Write-Host ''
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
