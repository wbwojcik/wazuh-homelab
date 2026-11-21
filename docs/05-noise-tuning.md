# Noise tuning

A fresh Wazuh with Sysmon gives you thousands of alerts a day, and some built-in rules fire at level 12-15
for things Windows and updaters do all the time. Once those hit my inbox I stopped reading it, so this
part mattered more than I expected.

The levels I use: 3 = history only, 7-10 = worth a look in the dashboard, 12+ = email.

## Approach

1. Let it run a week. Then look at the top rules (dashboard > Threat Hunting, or ask Claude
   "summarise alerts of the last 7 days by rule").
2. For each noisy rule, find what makes the harmless cases harmless: **program path, parent, user,
   signer, exact command line**. Never quiet by process id or by a loose name match.
3. Write a child rule at level 3 that matches only that harmless case. Everything else still alerts.
4. Raise rules you care about but Wazuh ships at a low level (log cleared, Defender off, new user) to 12.

## The rules in this repo

[server/noise_tuning.xml](../server/noise_tuning.xml):

| Rule | What |
|---|---|
| 100200-100202 | PowerShell policy test files, `sdbinst` background run, Edge unpacking itself |
| 100203 | Visual Studio Installer background download (template for any updater) |
| 100204 | `explorer.exe` started by Windows as a COM server |
| 100205 | `smss.exe` starting a new session (Sysmon records no parent) |
| 100206, 100210 | Genuine `svchost`, `backgroundTaskHost`, `dllhost` with no parent recorded: only the real System32 path and the command line they always have |
| 100207, 100208 | Brave / Chrome unpacking components, MSBuild writing build scripts to Temp |
| 100235 | Windows' built-in PowerShell wrapper that restricts `Invoke-Command` |
| 100241 | Informational Suricata categories (ET INFO / POLICY / HUNTING) |

[server/local_rules.xml](../server/local_rules.xml) keeps every Sysmon process start at level 3 (100110)
so it is searchable without being noisy, and adds credential dumping (100111).

## Example: quiet an updater

The alert says rule 92213 ("executable dropped in a temp folder") for
`C:\Users\<you>\AppData\Local\SomeApp-updater\pending\SomeApp-Setup.exe`. Add to `noise_tuning.xml`:

```xml
<rule id="100290" level="3">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)^C:\\+Users\\+[^\\]+\\+AppData\\+Local\\+SomeApp-updater\\+pending\\+SomeApp-Setup [0-9.]+\.exe$</field>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\+AppData\\+Local\\+Temp\\+ns[a-z][0-9A-F]+\.tmp\\</field>
  <description>SomeApp updater unpacking its installer in Temp (benign)</description>
</rule>
```

Windows paths arrive with doubled backslashes, so match a backslash as `\\+`.
Anchor with `^` and `$` so a copy of the program somewhere else still alerts.

## Example: quiet a Suricata signature

Add it to the 100241 regex, e.g. Steam's connection check:

```xml
<field name="alert.signature">^ET INFO |^ET POLICY |^ET HUNTING |^GPL INFO |^ET USER_AGENTS Steam HTTP Client</field>
```

## Install and check

```bash
sudo install -o wazuh -g wazuh -m 660 /tmp/noise_tuning.xml /var/ossec/etc/rules/noise_tuning.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

`wazuh-analysisd -t` checks the whole ruleset first, so a typo never stops the manager. Use
`/var/ossec/bin/wazuh-logtest` with a saved event to confirm the new rule matches before you rely on it.
