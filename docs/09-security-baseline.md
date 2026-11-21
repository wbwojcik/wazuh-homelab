# Home security baseline (SCA top 10)

Wazuh's SCA scan checks each laptop against CIS Windows 11 Enterprise v3.0.0 (482 checks).
My laptop passed about a quarter of them. Most of the failures are business and domain settings that
make no sense at home, so I picked the 10 that do protect a personal laptop and put them in one script:
`windows/home-hardening.ps1`.

| # | Setting | Why at home | SCA check |
|---|---------|-------------|-----------|
| 1 | LLMNR off | Stops a device on the same Wi-Fi tricking Windows into sending its password hash | 26193 |
| 2 | No insecure guest SMB logons | Windows won't connect to shares that skip passwords | 26195 |
| 3 | SMB signing required | File-share traffic can't be tampered with in transit | 26031, 26035, 26036 |
| 4 | NTLMv2 only | Refuses old, easily cracked login formats | 26056 |
| 5 | No anonymous account/share listing | Nobody on the network can list users without logging in | 26040 |
| 6 | Account lockout 5 tries / 15 min | Slows password guessing (Windows Hello PIN has its own limit) | 26005-26007 |
| 7 | Print spooler not reachable from the network | Closes the PrintNightmare-style attack path | 26209 |
| 8 | Remote Assistance off | Nobody can be invited in to control the screen | 26288 |
| 9 | UAC prompts on secure desktop, standard users denied | Malware can't click through or fake the elevation prompt | 26064-26066 |
| 10 | Defender Attack Surface Reduction, 13 rules in Block mode | Blocks the classic tricks: Office macros starting programs, LSASS password theft, unsigned programs from USB, obfuscated scripts, vulnerable drivers | 26390, 26391 |

## Use it

PowerShell as Administrator, in the repo folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Show    # what is set now
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Apply   # set all 10, then restart
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\home-hardening.ps1 -Undo    # old values back, then restart
```

`-Apply` saves the old values once to `C:\ProgramData\HomeHardening\backup.json`; `-Undo` restores them and
renames the backup. After a restart, Wazuh re-runs SCA on its own schedule (or restart the agent) and the score goes up
(on the first laptop: 126 -> 143 checks passed).

## If something stops working

- An old NAS or printer share won't open -> settings 3 or 4. Run `-Undo`, or change just that setting back.
- A program from a USB stick is blocked -> ASR rule B2B3F03D (unsigned programs from USB). Defender shows a
  notification; Windows Security > Protection history lists every ASR block.
- An Office add-in or macro is blocked -> one of the Office ASR rules, same place.

## Left out on purpose

- Turning off RDP services: Wazuh already emails on any Remote Desktop login (rule 100162).
- Memory integrity / Credential Guard (VBS): a Windows Security toggle that can clash with old drivers; do it by hand later.
- Everything domain-, BitLocker-policy- and enterprise-only.
