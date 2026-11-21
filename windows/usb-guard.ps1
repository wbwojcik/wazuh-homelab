# usb-guard.ps1 - Windows does not install ANY new USB device (hub, dock, keyboard, mouse, phone, stick)
# until you click Allow. See docs/10-usb-guard-and-sandbox.md.
#
# How: a Windows device-installation policy blocks every USB device (all USB class IDs), except devices
# whose instance ID is on the allow list. All USB devices this laptop already knows are put on that list
# at install. When a new one is plugged in, Windows refuses its driver and this script asks
# "Allow / Block". Allow = added to the list and installed. Block = stays without a driver, so it can't do
# anything (a fake "BadUSB" keyboard can't type). It asks again the next time that device is plugged in.
#
# Runs at logon as a scheduled task with admin rights (it changes HKLM policy). When it isn't running,
# new devices simply stay blocked.
#   Install / update (PowerShell as Administrator, in the repo folder):  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\usb-guard.ps1 -Install
#   Remove everything (policy, task, files):                             powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\usb-guard.ps1 -Uninstall
# Log: C:\ProgramData\usb-guard\usb-guard.log. Allowed devices: C:\ProgramData\usb-guard\allowed.txt
param([switch]$Install, [switch]$Uninstall)

$Dir = Join-Path $env:ProgramData "usb-guard"
$Allowed = Join-Path $Dir "allowed.txt"
$LogFile = Join-Path $Dir "usb-guard.log"
$Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$Task = "USB guard"

function Log($msg) {
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item -Force $LogFile "$LogFile.old" }
        Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    } catch {}
}

function Read-Allowed {
    if (-not (Test-Path $Allowed)) { return @() }
    @(Get-Content $Allowed | ForEach-Object { ($_ -split ' # ')[0].Trim() } | Where-Object { $_ })
}

# Write the allow list into the policy (registry values "1", "2", ... under AllowInstanceIDs).
function Sync-Policy {
    $ids = @(Read-Allowed | Sort-Object -Unique)
    $sub = "$Key\AllowInstanceIDs"
    if (Test-Path $sub) { Remove-Item $sub -Recurse -Force }
    New-Item $sub -Force | Out-Null
    $i = 1
    foreach ($id in $ids) { New-ItemProperty $sub -Name "$i" -Value $id -PropertyType String -Force | Out-Null; $i++ }
    Set-ItemProperty $Key -Name AllowInstanceIDs -Value 1 -Type DWord
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object CommandLine -like '*usb-guard.ps1*' |
        Where-Object ProcessId -ne $PID | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    if (Test-Path $Key) { Remove-Item $Key -Recurse -Force }
    Write-Host "Policy and task removed. Devices that were blocked install the next time they are plugged in."
    Write-Host "Allow list kept in $Dir (delete the folder to remove it too)."
    exit
}

if ($Install) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    # Only admins and SYSTEM may change the script and the allow list; users can read them.
    icacls $Dir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
    Copy-Item $PSCommandPath (Join-Path $Dir "usb-guard.ps1") -Force

    # Every USB device Windows has ever installed here (plugged in now or not) counts as known.
    $now = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object InstanceId -like 'USB\*')
    $old = Read-Allowed
    $add = @($now | Where-Object { $old -notcontains $_.InstanceId })
    foreach ($d in $add) { Add-Content $Allowed "$($d.InstanceId) # $($d.FriendlyName), known at install $(Get-Date -Format yyyy-MM-dd)" }
    Write-Host "$($add.Count) USB devices added to the allow list ($((Read-Allowed).Count) in total)."

    New-Item $Key -Force | Out-Null
    Sync-Policy
    # Block: every USB device and interface reports one of these compatible IDs.
    $deny = @("USB\COMPOSITE") + (0..255 | ForEach-Object { "USB\Class_{0:X2}" -f $_ }) + (0..255 | ForEach-Object { "USB\DevClass_{0:X2}" -f $_ })
    $sub = "$Key\DenyDeviceIDs"
    if (Test-Path $sub) { Remove-Item $sub -Recurse -Force }
    New-Item $sub -Force | Out-Null
    $i = 1; foreach ($id in $deny) { New-ItemProperty $sub -Name "$i" -Value $id -PropertyType String -Force | Out-Null; $i++ }
    Set-ItemProperty $Key -Name DenyDeviceIDs -Value 1 -Type DWord
    Set-ItemProperty $Key -Name DenyDeviceIDsRetroactive -Value 0 -Type DWord   # never remove installed devices
    Set-ItemProperty $Key -Name AllowDenyLayered -Value 1 -Type DWord           # allow list wins over the block

    # Start at every logon of this user, with admin rights, visible popups.
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\usb-guard.ps1`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object CommandLine -like '*usb-guard.ps1*' |
        Where-Object ProcessId -ne $PID | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-ScheduledTask -TaskName $Task
    Log "installed ($($add.Count) devices added)"
    Write-Host "Installed and running. Log: $LogFile"
    exit
}

# --- background watcher ------------------------------------------------------------------------------
$mutex = New-Object System.Threading.Mutex($false, "Global\usb-guard")
if (-not $mutex.WaitOne(0)) { exit }
Add-Type -AssemblyName System.Windows.Forms
Log "started"
try { Sync-Policy } catch { Log "error syncing allow list: $_" }   # picks up hand edits of allowed.txt

function Prop($id, $name) { (Get-PnpDeviceProperty -InstanceId $id -KeyName $name -ErrorAction SilentlyContinue).Data }

# A device whose install was refused stays failed: Windows only retries after it is removed and found again.
function Install-Now($id) {
    pnputil /remove-device "$id" | Out-Null
    pnputil /scan-devices | Out-Null
}

# What the device says it is, from its USB class code (a device can lie about this, see docs).
function Describe($id) {
    $ids = @(Prop $id 'DEVPKEY_Device_CompatibleIds') + @(Prop $id 'DEVPKEY_Device_HardwareIds')
    $text = ($ids -join ' ')
    if ($text -match 'Class_03&SubClass_01&Prot_01') { return "KEYBOARD" }
    if ($text -match 'Class_03&SubClass_01&Prot_02') { return "mouse" }
    if ($text -match 'USB\\COMPOSITE|DevClass_00|DevClass_EF') { return "device with several functions (could include a keyboard)" }
    $names = @{ '01'='audio (speaker / microphone)'; '02'='network or modem'; '03'='input device (keyboard / mouse / game controller)';
        '06'='camera / scanner'; '07'='printer'; '08'='storage (USB stick / disk)'; '09'='USB hub (dock, adapter, monitor)';
        '0A'='network or modem'; '0B'='smart card reader'; '0E'='webcam'; 'E0'='wireless / Bluetooth adapter';
        'EF'='device with several functions'; 'FF'='vendor-specific device' }
    if ($text -match 'Class_([0-9A-F]{2})') { $c = $Matches[1]; if ($names.ContainsKey($c)) { return $names[$c] }; return "USB class $c" }
    return "unknown type"
}

$declined = @{}   # blocked this plug-in: don't ask again until it is unplugged
$recent = @{}     # allowed in the last 2 minutes: its own parts (interfaces) are allowed without asking
while ($true) {
    try {
        $known = Read-Allowed
        $present = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object InstanceId -like 'USB\*')
        $presentIds = @($present | ForEach-Object InstanceId)
        foreach ($k in @($declined.Keys)) { if ($presentIds -notcontains $k) { $declined.Remove($k) } }
        foreach ($k in @($recent.Keys)) { if (((Get-Date) - $recent[$k]).TotalMinutes -gt 2) { $recent.Remove($k) } }

        foreach ($d in $present) {
            $id = $d.InstanceId
            if ($known -contains $id -or $declined.ContainsKey($id)) { continue }
            $vidpid = if ($id -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') { "VID $($Matches[1]) PID $($Matches[2])" } else { "" }
            $parent = Prop $id 'DEVPKEY_Device_Parent'

            # An interface (&MI_xx) of a device you just allowed is part of that same device: allow it too.
            if ($id -match '&MI_[0-9A-F]{2}' -and $recent.ContainsKey($parent)) {
                Add-Content $Allowed "$id # part of $parent, $(Get-Date -Format yyyy-MM-dd)"
                Sync-Policy; Install-Now $id
                Log "auto-allowed interface $id (parent $parent)"
                continue
            }

            $what = Describe $id
            $name = if ($d.FriendlyName) { $d.FriendlyName } else { "(no name yet, it has no driver)" }
            Log "NEW device blocked: $id | $what | $name"
            $warn = if ($what -match 'KEYBOARD|several functions') {
                "`n`nWARNING: a USB stick or cable that pretends to be a keyboard can type commands by itself. If you did not plug in a keyboard, click No and unplug it."
            } else { "" }
            $msg = "A new USB device was plugged in and is BLOCKED (no driver, it can't do anything yet).`n`n" +
                   "It says it is: $what`nName: $name`n$vidpid`n`nAllow it? Yes = install it and remember it. No = keep it blocked.`n`n" +
                   "Only USB drives (sticks, disks, card readers) open in the Sandbox. A phone, camera or any other device gets full access to this laptop after Yes, so click Yes only for your own.$warn"
            $answer = [System.Windows.Forms.MessageBox]::Show($msg, "USB guard", 'YesNo', 'Warning', 'Button2',
                [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly)
            if ($answer -eq 'Yes') {
                Add-Content $Allowed "$id # $what, $name, allowed $(Get-Date -Format yyyy-MM-dd)"
                Sync-Policy
                $recent[$id] = Get-Date
                Install-Now $id
                Log "ALLOWED $id"
            } else {
                $declined[$id] = $true
                Log "kept BLOCKED $id"
            }
        }
    } catch { Log "error: $_" }
    Start-Sleep 2
}
