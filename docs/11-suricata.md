# Suricata on a Windows laptop (network IDS)

Suricata runs on one laptop, watches its own network traffic, and its alerts go into Wazuh. It only sees
that laptop (not phones, cameras or other computers), and only while the laptop is on. Watching the whole
home network needs a separate box on a mirrored switch port.

## What runs where

| Where | What |
|---|---|
| Laptop | [Npcap](https://npcap.com) (packet capture driver; Wireshark installs it too) |
| Laptop | Suricata 8.0.x (Windows MSI from suricata.io), `C:\Program Files\Suricata`, Windows service `Suricata` (Automatic) |
| Laptop | Rules: Emerging Threats Open, merged into `rules\suricata.rules` (about 51,600 rules) |
| Laptop | Output: only alerts, to `log\alerts.json` |
| Server | `agent.conf` block for that laptop only, reads `alerts.json` as JSON ([server/agent.conf.d/suricata.xml](../server/agent.conf.d/suricata.xml)) |
| Server | Rules 100240 / 100241 in `noise_tuning.xml`: which Suricata alerts email |

## Alerts and emails

- Every Suricata alert: Wazuh rule 86601, level 3, dashboard only (search `rule.groups: suricata`).
- Suricata severity 1 (malware, exploits, C2): rule 100240, level 12, email
  ("Suricata: dangerous network traffic", names the signature, connection and website).
- Severity 1 but `ET INFO` / `ET POLICY` / `ET HUNTING` / `GPL INFO`: rule 100241, level 3, no email.
  Add your own harmless signatures there ([05](05-noise-tuning.md#example-quiet-a-suricata-signature)).
- Rate limit: the same signature on the same laptop emails at most once per 30 minutes.

## Install steps (PowerShell as Administrator)

1. Install the Windows MSI from https://suricata.io/download/ with default settings.
2. Suricata can't find Npcap's `wpcap.dll` (exit code -1073741515 = DLL not found), because Npcap
   was installed without "WinPcap API-compatible mode". Add Npcap's folder to the system Path
   (save a copy of the old Path first):
   ```powershell
   $k='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
   $r=(Get-Item $k).GetValue('Path',$null,'DoNotExpandEnvironmentNames')
   if ($r -notlike '*System32\Npcap*') { Set-ItemProperty $k -Name Path -Value "$r;C:\Windows\System32\Npcap" -Type ExpandString }
   ```
3. Rules (the Windows build has no `suricata-update`):
   ```powershell
   cd "C:\Program Files\Suricata\rules"
   Invoke-WebRequest https://rules.emergingthreats.net/open/suricata-8.0.8/emerging.rules.tar.gz -OutFile et.tar.gz
   tar -xzf et.tar.gz
   Get-Content .\rules\emerging-*.rules | Where-Object { $_ -notmatch 'file\.magic|filemagic' } | Set-Content .\suricata.rules
   ```
   Rules with `file.magic` are dropped: the Windows build has no libmagic and refuses to start with them.
4. `suricata.yaml` (make a backup copy first):
   - `rule-files:` lists only `- suricata.rules`.
   - A new `eve-log` output first in `outputs:` with `filename: alerts.json` and `types: [alert]`;
     the original `eve-log` (eve.json, every connection and DNS lookup) is `enabled: no`.
     Windows never trims these files, so the full eve.json would fill the disk.
   - The `stats` and `fast` outputs are `enabled: no`: stats.log grows by hundreds of KB within
     minutes, and fast.log only repeats alerts.json.
   - Check: `.\suricata.exe -T -c suricata.yaml` ends with "successfully loaded".
5. Service on the Wi-Fi adapter, then restart the laptop so the service sees the new Path:
   ```powershell
   .\suricata.exe --service-install -c "C:\Program Files\Suricata\suricata.yaml" -i "\Device\NPF_{<ADAPTER_GUID>}"
   Get-Service Suricata | Set-Service -StartupType Automatic
   ```
   Find the adapter's GUID with `Get-NetAdapter | ft Name,InterfaceGuid`.

## Server side

Append [server/agent.conf.d/suricata.xml](../server/agent.conf.d/suricata.xml) to `/var/ossec/etc/shared/default/agent.conf`
(back it up first), with `LAPTOP-1` replaced by the agent name:

```xml
<agent_config name="LAPTOP-1">
  <localfile>
    <location>C:\Program Files\Suricata\log\alerts.json</location>
    <log_format>json</log_format>
  </localfile>
</agent_config>
```

The agent got the file but didn't reload it by itself; `Restart-Service WazuhSvc` on the laptop fixed it.
Wazuh reads only lines written after it opens the file, so alerts from before that never arrive.

Rules 100240 / 100241 and the email text are in `server/noise_tuning.xml` and
`server/custom-email-alert`; install them as in [03](03-email-alerts.md).

## Test

```powershell
curl.exe -s http://testmyids.com      # "GPL ATTACK_RESPONSE id check returned root" (level 3, no email)
curl.exe -s https://api.ipify.org     # "ET INFO External IP Lookup" (level 3, no email)
Get-Content "C:\Program Files\Suricata\log\alerts.json" -Tail 2
```

On the server: `sudo grep '"suricata"' /var/ossec/logs/alerts/alerts.json | tail -n 2`.
Test the email without real malware: `wazuh-logtest` with a severity-1 line, or
`custom-email-alert --dry-run` with a saved 100240 alert.
(testmynids.org is a parked domain now; testmyids.com still works.)

## Updating rules

Repeat step 3 (download, merge, drop `file.magic`), run the `-T` check, then `Restart-Service Suricata`.

## Known limits

- `alerts.json` itself is never trimmed. It only holds alerts (small), but check its size now and then.
- Only this laptop's traffic.
