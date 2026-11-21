# Windows logging

By default the Wazuh agent only reads the Application, System and Security logs. For anything useful at
home I added Sysmon, a few audit settings, PowerShell script logging, Defender's own log and the USB
plug-in log.

## 1. Sysmon (recommended)

Sysmon logs every process start, network connection, file creation and DNS lookup. Wazuh ships rules for
it, and several rules here need it (credential dumping, browser starting a shell, DNS watch).

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon).
2. Get a config, e.g. [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or
   [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).
3. Administrator PowerShell: `.\Sysmon64.exe -accepteula -i sysmonconfig.xml`
4. Tell the agent to read it: add to the laptop's `C:\Program Files (x86)\ossec-agent\ossec.conf`, or
   better to `agent.conf` on the manager:

   ```xml
   <agent_config os="Windows">
     <localfile>
       <location>Microsoft-Windows-Sysmon/Operational</location>
       <log_format>eventchannel</log_format>
     </localfile>
   </agent_config>
   ```

No Sysmon on a laptop? Step 2 still gives you process creation (event 4688) from Windows itself.

## 2. Audit settings, PowerShell logging, AutoPlay off

[windows/audit-settings.ps1](../windows/audit-settings.ps1) turns on (by GUID, so any Windows language works):
audit policy changes, process creation with full command line, user and group changes, service and
scheduled task creation, PowerShell script block logging (event 4104), and switches AutoPlay off for all
drives and users.

```powershell
# PowerShell as Administrator, in the repo folder
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\audit-settings.ps1
```

## 3. Push collection settings from the manager

[server/agent.conf.d/windows-default.xml](../server/agent.conf.d/windows-default.xml) adds, for every
Windows agent in the `default` group:

- `Microsoft-Windows-Kernel-PnP/Configuration`: new USB device (event 400, rule 100221)
- `Microsoft-Windows-Windows Defender/Operational`: malware found (rule 62123), protection off (100233)
- `Microsoft-Windows-PowerShell/Operational`, event 4104 only: PowerShell script text
- Registry watch on the AutoPlay policy key (rule 100234)
- A bigger agent buffer (25,000 events, 1,000/s). The default overflows on a busy laptop with Sysmon and
  you get "agent overloaded" alerts.

Copy it to the server and append it:

```powershell
scp -i $HOME\.ssh\wazuh server\agent.conf.d\windows-default.xml admin@10.10.0.1:/tmp/
```

```bash
sudo -i
sed -i 's/\r$//' /tmp/windows-default.xml
cp /var/ossec/etc/shared/default/agent.conf /var/ossec/etc/shared/default/agent.conf.bak-$(date +%F)
cat /tmp/windows-default.xml >> /var/ossec/etc/shared/default/agent.conf
/var/ossec/bin/verify-agent-conf
```

Agents pick it up and restart by themselves within a few minutes. If one doesn't:
`/var/ossec/bin/agent_control -R -u 001` (agent id), or `Restart-Service WazuhSvc` on the laptop.

After any agent restart, check the service actually came back:
`Get-Service WazuhSvc` must say Running.

## 4. Check

- New USB: plug in a stick you have never used on that laptop. Windows logs event 400 only the first time
  it sets up a device. To test again with the same stick: Device Manager > View > Show hidden devices >
  Disk drives > the stick > Uninstall device, then plug it in again.
- Audit policy: `auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable`
  (runs the same setting again) fires 100231.
- New user: `net user wazuhtest P@ss-w0rd-123 /add` then `net user wazuhtest /delete` fires 100232.

## Notes on writing Windows rules

- `60000` children are never reached for INFORMATION events, because `60009` claims them first.
  Use `<if_sid>60009, 60010, 60011, 60012</if_sid>` (the severity groups).
- Every `4624` logon (`60106`) is claimed by `92651` first, so hang logon rules off `60106, 92651`.
- `<if_sid>` takes rule ids, not Windows event ids. `<if_sid>4624</if_sid>` never fires.
- For Sysmon event 1 the first matching child of 61603 wins. A custom detection must list every built-in
  process-creation rule below its level as parents (see rule 100250 in `noise_tuning.xml`).
- Test a rule without waiting for the event: `/var/ossec/bin/wazuh-logtest` and paste a JSON event.
