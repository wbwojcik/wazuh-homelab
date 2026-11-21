# Troubleshooting

Things that broke while I built this, and what fixed them.

## Server

| Symptom | Cause / fix |
|---|---|
| `ping 10.10.0.1` fails after a server reboot | `wg-quick@wg0` was running but not enabled. Provider web console > log in > `sudo systemctl enable --now wg-quick@wg0`, then Deactivate / Activate the tunnel on the PC |
| SSH times out but ping works | `sudo systemctl status ssh`, `sudo ufw status` (22/tcp must allow the VPN subnet) |
| Dashboard won't load | `systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard`; wait 1-2 minutes after a restart (slow on 4 GB); try a private browser window (old cached JavaScript after an upgrade) |
| Server out of memory | `free -h`. Fewer shards ([06](06-index-retention.md)) and a swap file ([01](01-server-setup.md#7-memory-add-a-swap-file)) |
| Manager API not reachable from the PC | `Test-NetConnection 10.10.0.1 -Port 55000` is False: add `ufw allow from 10.10.0.0/24 to any port 55000 proto tcp` |
| API answers 401 | Tokens live 15 minutes; get a new one |
| Indexer `curl -u admin:...` says Unauthorized | Password changed after install, or shell quoting (`?` / `*` in the password: use `-u "admin:$PASS"`). As root, use the admin certificate instead ([02](02-users-and-credentials.md#rotate-passwords)) |

## Emails

| Symptom | Cause / fix |
|---|---|
| No emails at all, `integrations.log` says "required file not found" | Script copied from a Windows checkout has CRLF line endings. `sed -i 's/\r$//' /var/ossec/integrations/custom-email-alert`, then dry-run it ([03](03-email-alerts.md#3-test)) |
| No email, nothing in `integrations.log` | `<integration>` block missing in `ossec.conf`, or the manager wasn't restarted |
| Mail stuck in `mailq` | `journalctl -u postfix -n 30`. Port 587 blocked, or wrong app password (check `postmap` was run) |
| Gmail rewrote the sender | `From` must be the Gmail account itself; plus-addresses don't survive |
| "Wazuh agent overloaded" emails | Raise the agent buffer ([04](04-windows-logging.md)); a single one after a restart is harmless |

## Agents

| Symptom | Cause / fix |
|---|---|
| Enrollment: `ERROR: Invalid password` | Wrong or missing enrollment password ([01](01-server-setup.md#6-add-a-windows-agent)) |
| `agent.conf` change not picked up | `/var/ossec/bin/verify-agent-conf`, then `agent_control -R -u <id>` or `Restart-Service WazuhSvc` on the laptop |
| Agent shows Disconnected after a restart | `Get-Service WazuhSvc` on the laptop; it can stay Stopped. `Start-Service WazuhSvc` |
| A new log file (e.g. Suricata) never shows up | The agent only reads lines written after it opened the file: restart the agent once after adding a `<localfile>` |
| Registry change never alerts | The first syscheck scan after an agent start only records a baseline. Don't restart the agent while testing; trigger a scan through the API ([12](12-browser-watch.md)) |
| Custom Windows rule never fires | Wrong parent: see the notes at the end of [04](04-windows-logging.md#notes-on-writing-windows-rules) |
| PowerShell script won't run ("not digitally signed") | Run it with `powershell -NoProfile -ExecutionPolicy Bypass -File <script>` |
