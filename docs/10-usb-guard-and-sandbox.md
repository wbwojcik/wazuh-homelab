# USB guard and USB sandbox

I didn't like that any USB stick or cable could do whatever it wanted the moment it was plugged in, so
I wrote two scripts that work together on Windows 11 Pro:

1. USB guard: any USB device the laptop has never seen (stick, hub, keyboard, phone...) is blocked
   until you click Allow.
2. USB sandbox: a new USB *drive* you allowed opens read-only in Windows Sandbox first.

The Wazuh new-USB email (rule 100221) fires either way.

## AutoPlay off

AutoPlay should be off on every laptop, for all users (PowerShell as Administrator; `windows/audit-settings.ps1` does the same):

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
```

## Auto-open new USB sticks in Windows Sandbox

[windows/usb-sandbox.ps1](../windows/usb-sandbox.ps1) waits for any USB drive (stick, SD card, external SSD/HDD) and opens it read-only
in Windows Sandbox with networking and clipboard off. Closing the Sandbox window deletes everything in it.

Only new drives go to the Sandbox. When you close the Sandbox, a window asks "Trust this drive?":
- Yes: the drive is remembered and from then on opens normally in Windows, no Sandbox.
- No: nothing is remembered, it goes to the Sandbox again next time.

A stick or SD card is recognised by its hardware serial number plus its volume serial number, so a reformatted stick counts as new
(cheap sticks often share the same fake hardware serial, so that alone isn't enough). An external SSD/HDD with a real hardware
serial is recognised by that serial alone: an external SSD's volume serial can change without any formatting.
Remembered drives are listed in `%LOCALAPPDATA%\usb-sandbox\known-drives.txt`, one line each with label and date;
delete a line to send that drive through the Sandbox again. A cheap stick with no hardware serial is identified by
its volume serial only. A drive with no volume serial (unformatted or unreadable) always goes to the Sandbox and is never remembered.

The script looks at the drive letters every 2 seconds (it does not rely on a Windows plug-in event, which can be missed),
so a drive plugged in while a Sandbox is already open, or before you signed in, still gets its turn.
Every decision goes to `%LOCALAPPDATA%\usb-sandbox\usb-sandbox.log`. If a drive didn't open in the Sandbox, look there first:

```powershell
Get-Content "$env:LOCALAPPDATA\usb-sandbox\usb-sandbox.log" -Tail 20
```

Update to a new version of the script (normal PowerShell, in the repo folder): stop the old copy, copy, start again:

```powershell
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object CommandLine -like '*usb-sandbox*' | ForEach-Object { Stop-Process -Id $_.ProcessId }
Copy-Item .\windows\usb-sandbox.ps1 "$env:LOCALAPPDATA\usb-sandbox\" -Force
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\USB to Sandbox.lnk"
```

Needs Windows 11 Pro with the "Windows Sandbox" feature on (Windows Features; the separate "Hyper-V" box is not needed).

### Install the sandbox

Normal PowerShell, as the laptop user, in the repo folder (`schtasks /sc onlogon` needs Admin, so a Startup-folder shortcut is used):

```powershell
$d = "$env:LOCALAPPDATA\usb-sandbox"; New-Item -ItemType Directory -Force $d | Out-Null
Copy-Item .\windows\usb-sandbox.ps1 $d
$lnk = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\USB to Sandbox.lnk"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = "powershell.exe"
$s.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$d\usb-sandbox.ps1`""
$s.WindowStyle = 7; $s.Save()
Start-Process $lnk
```

After checking: if the files look fine, close the Sandbox, right-click the drive in File Explorer >
"Scan with Microsoft Defender", then use it normally. Nothing is blocked on the laptop itself.

Remove: delete `USB to Sandbox.lnk` from the Startup folder (Win+R, `shell:startup`) and sign out.

Closing the Sandbox may show "The remote environment is shutting down. The connection will be closed." That is normal, click Close.
A stick opens read-only in `C:\USB` inside the Sandbox.

Limits:
- Windows still mounts the stick on the laptop too. Don't open it in File Explorer there.
- A "BadUSB" stick pretending to be a keyboard acts the moment it is plugged in, unless USB guard blocks it
  first (USB guard below). The Wazuh new-USB email (rule 100221) fires either way.
- A trusted drive is trusted for good, even if someone later puts a bad file on it. Only say Yes for your own drives;
  for a borrowed stick say No. The Wazuh new-USB email (rule 100221) still fires for every drive.
- `$SkipLabels` at the top of the script skips drives by volume label without asking (older option, usually not needed now).
- Need more than a quick look (run tools, keep state)? Use a VirtualBox VM with a USB filter and a snapshot, no Wazuh agent inside.

## USB guard

Any USB device this laptop has not seen before is blocked until you allow it.
That covers hubs, docks, keyboards, mice, phones, adapters and sticks, not only drives.

Script: [windows/usb-guard.ps1](../windows/usb-guard.ps1). It works alongside the USB Sandbox
(above): a new stick first asks Allow/Block here, and after Allow it
opens in the Sandbox as before.

### How it works

- A Windows device-installation policy (`HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`)
  blocks every USB device: `DenyDeviceIDs` lists `USB\COMPOSITE` and every `USB\Class_xx` / `USB\DevClass_xx`,
  which every USB device and interface reports.
- `AllowInstanceIDs` lists the devices you allowed, and `AllowDenyLayered=1` makes that list win over the block.
  `DenyDeviceIDsRetroactive=0`: nothing already installed is removed.
- At install, every USB device Windows has ever installed on the laptop goes on the allow list, so your
  mouse, keyboard and dock keep working.
- A blocked device gets no driver, so it can't do anything: a fake "BadUSB" keyboard can't type.
- The script (scheduled task "USB guard", at logon, admin rights) checks every 2 seconds for a USB device
  that is plugged in but not on the list and shows a popup: what the device says it is, its name and
  VID/PID. Yes adds it to the list and installs it. No (the default button) keeps it blocked; it asks
  again next time that device is plugged in.
  After Yes the script removes the blocked device and lets Windows find it again (`pnputil /remove-device`,
  `/scan-devices`): a device whose install was refused is never retried otherwise (setupapi.dev.log
  shows only the first, blocked attempt).
- After you allow a device with several functions, its parts (`&MI_xx` interfaces) are allowed without
  asking for 2 minutes. Devices plugged into an allowed hub still ask one by one.
- When the script isn't running (before logon, or it crashed), new devices stay blocked. That's the safe side.

Files in `C:\ProgramData\usb-guard\` (only admins can change them):
- `allowed.txt`: one allowed device per line with a note. Delete a line and restart the task (`Stop-ScheduledTask "USB guard"; Start-ScheduledTask "USB guard"`) to make that device ask again; it takes effect when Windows installs it again (another port, or after uninstalling it in Device Manager).
- `usb-guard.log`: every new device, Allow and Block.

### Install / update (PowerShell as Administrator, in the repo folder)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\usb-guard.ps1 -Install
```

Running it again updates the script and adds any newly installed USB devices to the list.

### Remove

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\usb-guard.ps1 -Uninstall
```

Removes the policy and the task. Blocked devices install the next time they are plugged in.
If something USB stops working and you can't reach the popup: the same command, or delete the registry key above.

### Limits

- "It says it is" comes from the device itself. A BadUSB stick can claim to be a storage stick and then
  be a keyboard as well (several functions). Only allow devices you are holding and expect.
- A device without a serial number (many cheap mice, keyboards, sticks) gets a new ID per USB port,
  so it asks once for each port you use it in.
- The laptop's built-in keyboard and touchpad are not USB and are never affected.
- Phones and cameras connect as media devices (MTP), not drives, so they never open in the Sandbox: Yes gives
  them full access. The popup says so. Click Yes only for your own phone.
- VirtualBox USB passthrough of a new device needs Allow first, which also lets Windows install it on the laptop.
