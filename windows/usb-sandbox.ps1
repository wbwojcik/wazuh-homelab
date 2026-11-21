# usb-sandbox.ps1 - when a NEW USB drive is plugged in, open it READ-ONLY in Windows Sandbox
# (no network, no clipboard). Runs in the background from a Startup shortcut, see docs/10-usb-guard-and-sandbox.md.
# After you close the Sandbox it asks "Trust this drive?". Yes = the drive is remembered and next time
# it opens normally in Windows, without the Sandbox. Remembered drives: %LOCALAPPDATA%\usb-sandbox\known-drives.txt
# (delete a line to make that drive go through the Sandbox again).
# What it did and why is written to %LOCALAPPDATA%\usb-sandbox\usb-sandbox.log.
# Limits: Windows still mounts the stick on the laptop itself (just don't open it there),
# and a "BadUSB" fake keyboard acts before any of this can run.
# Drives you trust and use every day (volume label as shown in File Explorer), never sent to the Sandbox:
$SkipLabels = @()            # e.g. @("BACKUP")
$dir = Join-Path $env:LOCALAPPDATA "usb-sandbox"
New-Item -ItemType Directory -Force $dir | Out-Null
$known = Join-Path $dir "known-drives.txt"
if (-not (Test-Path $known)) { New-Item -ItemType File $known | Out-Null }
$log = Join-Path $dir "usb-sandbox.log"
function Log($msg) {
    try {
        if ((Test-Path $log) -and (Get-Item $log).Length -gt 1MB) { Move-Item -Force $log "$log.old" }
        Add-Content $log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    } catch {}
}
# Only one copy runs; starting it again (e.g. from the shortcut) is harmless.
$mutex = New-Object System.Threading.Mutex($false, "Local\usb-sandbox")
if (-not $mutex.WaitOne(0)) { exit }
Log "started"

$win = { Get-Process WindowsSandbox* -ErrorAction SilentlyContinue | Where-Object MainWindowHandle -ne 0 }

# Returns $true when the drive is dealt with, $false to try again later (a Sandbox is already open,
# or Windows has not finished mounting the drive). $age = seconds since the drive letter appeared.
function Open-InSandbox($drive, $age) {
    # Any USB drive: sticks, SD cards and external SSDs/HDDs (BusType USB), not internal disks.
    $disk = try { Get-Partition -DriveLetter $drive.TrimEnd(':') -ErrorAction Stop | Get-Disk } catch { $null }
    $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'"
    if ("$($disk.BusType)" -ne "USB" -and $ld.DriveType -ne 2) { return $true }   # DriveType 2 = removable
    if (-not $ld.Size) { return $false }   # card reader with no card in it: look again later
    $label = (Get-Volume -DriveLetter $drive.TrimEnd(':') -ErrorAction SilentlyContinue).FileSystemLabel
    if ($SkipLabels -contains $label) { Log "$drive ($label) skipped: label in SkipLabels"; return $true }
    # Drive identity: external SSDs/HDDs (DriveType 3) with a real hardware serial are known by that serial
    # alone, because their volume serial can change without you formatting anything (seen 2026-10-16 on an
    # external SSD). Sticks and SD cards (DriveType 2) often share fake serials between units, so for them,
    # and for disks without a serial, it is hardware + volume serial (a reformatted stick counts as new).
    # Saved as "hardware|volume" either way.
    # Right after plug-in the volume serial can still be empty; wait up to 20 s for it.
    $hw = "$($disk.SerialNumber)".Trim()
    $realHw = $ld.DriveType -eq 3 -and $hw -match '^[0-9A-Za-z]{6,}$' -and $hw -notmatch '^0+$'
    $volSerial = "$($ld.VolumeSerialNumber)".Trim()
    if (-not $volSerial -and $age -lt 20) { return $false }
    $id = "$hw|$volSerial"
    # Exact match on the part before " #". Lines with an empty volume serial (written by the 2026-10-12
    # version when it read a drive too early) only count through a real hardware serial: before that
    # they matched every drive it couldn't read.
    $trusted = Get-Content $known | Where-Object {
        $line = ($_ -split ' #')[0].Trim()
        ($realHw -and ($line -split '\|')[0] -eq $hw) -or ($volSerial -and $line -eq $id)
    }
    if ($trusted) { Log "$drive ($label) trusted, opens normally"; return $true }
    if (& $win) { return $false }   # one sandbox at a time (only the window counts, see below)
    $wsb = Join-Path $dir "usb.wsb"
    @"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$drive\</HostFolder>
      <SandboxFolder>C:\USB</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>explorer.exe C:\USB</Command></LogonCommand>
</Configuration>
"@ | Set-Content -Encoding UTF8 $wsb
    Log "$drive ($label) new drive $id (type $($ld.DriveType)), opening Sandbox"
    Start-Process $wsb
    # Wait for the Sandbox window to open, then for you to close it. Only the window counts:
    # background Sandbox processes keep running for a while after the window is gone.
    for ($i = 0; $i -lt 120 -and -not (& $win); $i++) { Start-Sleep 1 }
    $opened = Get-Date
    # Closed = no Sandbox window for 3 s in a row (the window can blink away while the Sandbox boots).
    $gone = 0
    while ($gone -lt 6) { if (& $win) { $gone = 0 } else { $gone++ }; Start-Sleep -Milliseconds 500 }
    # A Sandbox that never showed up or was gone within 15 s failed to start (seen 2026-10-21: window
    # flashed, then the trust question came and got a Yes). Then the drive was NOT checked: say so, don't ask.
    $secs = [int]((Get-Date) - $opened).TotalSeconds - 3
    if ($i -ge 120 -or $secs -lt 15) {
        Log "$drive Sandbox failed to start or closed by itself after $secs s, drive NOT checked"
        $null = (New-Object -ComObject WScript.Shell).Popup(
            "The Sandbox did not start properly (closed after $secs s), so drive $drive ($label) was NOT checked.`n`nDon't open it on this laptop. Unplug it and plug it in again to retry.",
            0, "USB to Sandbox", 0 + 48 + 4096)   # 0 = OK only, 48 = warning icon, 4096 = always on top
        return $true
    }
    if (-not $realHw -and -not $volSerial) { Log "$drive has no serial at all, can't be remembered"; return $true }
    # 4 = Yes/No, 32 = question icon, 4096 = always on top. 6 = Yes.
    $answer = (New-Object -ComObject WScript.Shell).Popup(
        "Drive $drive ($label) was checked in the Sandbox.`n`nTrust this drive? Yes = next time it opens normally, without the Sandbox.",
        0, "USB to Sandbox", 4 + 32 + 4096)
    if ($answer -eq 6) { Add-Content $known "$id # $label, trusted $(Get-Date -Format yyyy-MM-dd)"; Log "$drive trusted" }
    else { Log "$drive not trusted" }
    return $true
}

# Look at the drive letters every 2 seconds instead of waiting for a Windows event: an event can be
# missed (sleep, hibernate, a busy moment), a look cannot. Drives already plugged in when this starts
# are checked too. A drive is handled once per plug-in; unplug and plug in again to repeat.
$done = @{}; $seen = @{}
while ($true) {
    try {
        $letters = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3" | ForEach-Object DeviceID)
        foreach ($l in @($seen.Keys)) { if ($letters -notcontains $l) { $seen.Remove($l); $done.Remove($l) } }
        foreach ($l in $letters) {
            if (-not $seen.ContainsKey($l)) { $seen[$l] = Get-Date }
            if ($done.ContainsKey($l)) { continue }
            $age = ((Get-Date) - $seen[$l]).TotalSeconds
            if (Open-InSandbox $l $age) { $done[$l] = $true }
        }
    } catch { Log "error: $_" }
    Start-Sleep 2
}
