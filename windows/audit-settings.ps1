# audit-settings.ps1 - Windows' own security logging for laptops WITHOUT Sysmon.
# Run in PowerShell as Administrator. Wazuh then picks the events up from the Security / PowerShell logs.
# Subcategories by GUID so it works on any Windows language.
auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Audit Policy Change (4719)
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable                  # Process Creation (4688)
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # User Account Management (4720...)
auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable                  # Security Group Management (4732)
auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable                  # Security System Extension (4697 service installed)
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable                  # Other Object Access (4698 scheduled task)
# Full command line in 4688 events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
# PowerShell script text in Microsoft-Windows-PowerShell/Operational (4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
# AutoPlay off for all users and drives (rule: AutoPlay off on every laptop)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
