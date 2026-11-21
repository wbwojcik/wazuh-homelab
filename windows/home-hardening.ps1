# home-hardening.ps1 - 10 Windows security settings that matter on a home laptop
# (picked from the failed Wazuh SCA checks, CIS Windows 11 Enterprise v3.0.0).
#
# Run in PowerShell as Administrator:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Show    # what is set now
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Apply   # set all 10, then restart
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Undo    # put the old values back, then restart
#
# -Apply saves the old values ONCE to C:\ProgramData\HomeHardening\backup.json (a second -Apply keeps the first backup),
# so -Undo always returns to how the laptop was before the first -Apply.
param([switch]$Apply, [switch]$Undo, [switch]$Show)

$ErrorActionPreference = 'Stop'
$BackupDir  = 'C:\ProgramData\HomeHardening'
$BackupFile = Join-Path $BackupDir 'backup.json'

$asr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
# Defender Attack Surface Reduction rules (all in Block mode = 1)
$AsrRules = [ordered]@{
  'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email and webmail'
  'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office apps from creating child processes'
  '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office apps from creating executable content'
  '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office apps from injecting into other processes'
  'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript/VBScript from launching downloaded executables'
  '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated scripts'
  '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
  '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
  'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted and unsigned processes that run from USB'
  'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
  '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'Block abuse of exploited vulnerable signed drivers'
  '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
  '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication apps from creating child processes'
}

# Registry settings: Path, Name, Value (REG_DWORD unless Type says otherwise), Why
$Settings = @(
  @{ Id='1 LLMNR off';             Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';          Name='EnableMulticast';                  Value=0 }
  @{ Id='2 No guest SMB logons';   Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation';     Name='AllowInsecureGuestAuth';           Value=0 }
  @{ Id='3 SMB signing (client)';  Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature';    Value=1 }
  @{ Id='3 SMB signing (server)';  Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='RequireSecuritySignature';         Value=1 }
  @{ Id='3 SMB signing (server)';  Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='EnableSecuritySignature';          Value=1 }
  @{ Id='4 NTLMv2 only';           Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                      Name='LmCompatibilityLevel';             Value=5 }
  @{ Id='5 No anonymous listing';  Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                      Name='RestrictAnonymous';                Value=1 }
  @{ Id='5 No anonymous listing';  Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                      Name='RestrictAnonymousSAM';             Value=1 }
  @{ Id='7 Print spooler closed';  Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers';           Name='RegisterSpoolerRemoteRpcEndPoint'; Value=2 }
  @{ Id='8 Remote Assistance off'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services';  Name='fAllowToGetHelp';                  Value=0 }
  @{ Id='9 UAC';                   Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin';       Value=2 }
  @{ Id='9 UAC';                   Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser';        Value=0 }
  @{ Id='9 UAC';                   Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken';         Value=1 }
  @{ Id='10 Defender ASR on';      Path=$asr;                                                              Name='ExploitGuard_ASR_Rules';           Value=1 }
)
foreach ($g in $AsrRules.Keys) {
  $Settings += @{ Id="10 ASR: $($AsrRules[$g])"; Path="$asr\Rules"; Name=$g; Value='1'; Type='String' }
}
# 6 Account lockout: 5 wrong passwords -> locked 15 min (Windows Hello PIN has its own limit)
$Lockout = @{ LockoutBadCount = 5; LockoutDuration = 15; ResetLockoutCount = 15 }

function Get-Reg($p, $n) {
  $item = Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue
  if ($null -eq $item) { return $null }
  return $item.$n
}

function Get-Lockout {
  $tmp = Join-Path $env:TEMP 'hh-secpol.cfg'
  secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
  $r = @{ LockoutBadCount = 0; LockoutDuration = $null; ResetLockoutCount = $null }
  foreach ($line in Get-Content $tmp) {
    if ($line -match '^(LockoutBadCount|LockoutDuration|ResetLockoutCount)\s*=\s*(\d+)') { $r[$matches[1]] = [int]$matches[2] }
  }
  Remove-Item $tmp -Force
  return $r
}

function Set-Lockout($l) {
  # threshold first: duration/window can only be set while lockout is on
  net accounts /lockoutthreshold:$($l.LockoutBadCount) | Out-Null
  if ($l.LockoutBadCount -gt 0) {
    if ($null -ne $l.LockoutDuration)   { net accounts /lockoutduration:$($l.LockoutDuration) | Out-Null }
    if ($null -ne $l.ResetLockoutCount) { net accounts /lockoutwindow:$($l.ResetLockoutCount) | Out-Null }
  }
}

function Show-State {
  $lo = Get-Lockout
  $rows = foreach ($s in $Settings) {
    $now = Get-Reg $s.Path $s.Name
    [pscustomobject]@{ Setting = $s.Id; Name = $s.Name; Now = $(if ($null -eq $now) { '(not set)' } else { $now }); Target = $s.Value; OK = ("$now" -eq "$($s.Value)") }
  }
  $rows += [pscustomobject]@{ Setting = '6 Account lockout'; Name = 'threshold/duration/window'; Now = "$($lo.LockoutBadCount)/$($lo.LockoutDuration)/$($lo.ResetLockoutCount)"; Target = '5/15/15'
            OK = ($lo.LockoutBadCount -in 1..5 -and $lo.LockoutDuration -ge 15 -and $lo.ResetLockoutCount -ge 15) }
  $rows | Format-Table -AutoSize
  $ok = @($rows | Where-Object OK).Count
  Write-Host "$ok of $($rows.Count) already set."
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this in PowerShell as Administrator.' -ForegroundColor Red; exit 1 }

if ($Apply) {
  if (-not (Test-Path $BackupFile)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $backup = @{
      Registry = @(foreach ($s in $Settings) { @{ Path = $s.Path; Name = $s.Name; Old = (Get-Reg $s.Path $s.Name); Type = $(if ($s.Type) { $s.Type } else { 'DWord' }) } })
      Lockout  = Get-Lockout
      Saved    = (Get-Date).ToString('s')
    }
    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupFile -Encoding UTF8
    Write-Host "Old values saved to $BackupFile"
  } else {
    Write-Host "Backup already exists ($BackupFile), keeping it."
  }
  foreach ($s in $Settings) {
    if (-not (Test-Path $s.Path)) { New-Item -Path $s.Path -Force | Out-Null }
    $type = if ($s.Type) { $s.Type } else { 'DWord' }
    New-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -PropertyType $type -Force | Out-Null
  }
  Set-Lockout $Lockout
  Show-State
  Write-Host 'Done. Restart the laptop so every setting takes effect.' -ForegroundColor Green
}
elseif ($Undo) {
  if (-not (Test-Path $BackupFile)) { Write-Host "No backup at $BackupFile - nothing to undo." -ForegroundColor Red; exit 1 }
  $b = Get-Content $BackupFile -Raw | ConvertFrom-Json
  foreach ($r in $b.Registry) {
    if ($null -eq $r.Old) {
      Remove-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue
    } else {
      if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
      New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Old -PropertyType $r.Type -Force | Out-Null
    }
  }
  Set-Lockout @{ LockoutBadCount = [int]$b.Lockout.LockoutBadCount; LockoutDuration = $b.Lockout.LockoutDuration; ResetLockoutCount = $b.Lockout.ResetLockoutCount }
  Rename-Item $BackupFile ("backup-undone-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
  Show-State
  Write-Host 'Old values restored. Restart the laptop.' -ForegroundColor Green
}
else {
  Show-State
  if (-not $Show) { Write-Host 'Use -Apply to set them, -Undo to go back.' }
}
