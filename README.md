# wazuh-homelab

My notes and scripts for running Wazuh at home: one small cloud VM watching a couple of Windows laptops,
emailing me only when something actually needs a look, plus a small read-only MCP server so I can ask
Claude about alerts instead of clicking through the dashboard.

This is based on the homelab I actually run and use every day. Everything here (rules, scripts, the email
format, the gotchas) comes from that setup. I wrote it down for myself first, then swapped my own names,
addresses and IPs for placeholders so others can build the same thing.

It's a homelab setup, not a product. Read the scripts before you run them and try things on your own
machines first. Not affiliated with Wazuh or Anthropic.

## The setup

- Wazuh 4.14 all-in-one (indexer, manager, dashboard) on an Ubuntu 24.04 VM with 4 GB RAM.
- Dashboard, API and SSH only over WireGuard. The only ports open to the internet are 1514/1515 for the
  agents, and enrollment needs a password.
- Windows 11 laptops with the Wazuh agent and Sysmon.
- Alerts at level 12 and up go out as a readable email through postfix and Gmail. Critical
  vulnerabilities come once a day as a single list.
- Old alerts are deleted after 90 days, which keeps a 4 GB box happy.

```
PC (WireGuard 10.10.0.2) ---- VPN ----> VM (wg0 10.10.0.1)
                                          22     SSH          VPN only
                                          443    dashboard    VPN only
                                          55000  API          VPN only
                                          9200   indexer      localhost only
laptops (agent + Sysmon) -- internet -->  1514   agent data   open, agent keys
                                          1515   enrollment   open, password

alert level >= 12  -> custom-email-alert   -> postfix -> inbox
06:00 cron         -> wazuh-vuln-digest.py -/
```

## Docs

Roughly in the order I'd do them again:

1. [Server setup](docs/01-server-setup.md) - VM, WireGuard, firewall, Wazuh, first agent, swap
2. [Users and credentials](docs/02-users-and-credentials.md)
3. [Email alerts](docs/03-email-alerts.md) - postfix relay, alert emails, daily vulnerability email
4. [Windows logging](docs/04-windows-logging.md) - Sysmon, audit policy, PowerShell, Defender, USB events
5. [Noise tuning](docs/05-noise-tuning.md) - quieting the harmless stuff
6. [Index retention](docs/06-index-retention.md)
7. [Backups](docs/07-backups.md)
8. [Upgrades](docs/08-upgrades.md)
9. [Security baseline](docs/09-security-baseline.md) - 10 CIS settings that make sense on a home laptop
10. [USB guard and sandbox](docs/10-usb-guard-and-sandbox.md) - new USB devices wait for approval, new drives open in Windows Sandbox
11. [Suricata](docs/11-suricata.md) on a Windows laptop
12. [Browser watch](docs/12-browser-watch.md) - browser starting a shell, new extensions
13. [DNS watch](docs/13-dns-watch.md) - lookups of known malware and phishing domains
14. [Claude MCP server](docs/14-claude-mcp.md) - read-only access for Claude
15. [Troubleshooting](docs/15-troubleshooting.md) - things that broke and how I fixed them

## Folders

- `server/` - rules, the email script, vulnerability digest, config backup, bad-domain list updater,
  index policies and `agent.conf` snippets
- `windows/` - PowerShell scripts for the laptops
- `mcp-server/` - the MCP server

## Placeholders

Swap these for your own values:

- `10.10.0.1`, `10.10.0.2`, `10.10.0.0/24` - WireGuard addresses of the server, your PC and the VPN subnet
- `<SERVER_PUBLIC_IP>` - the VM's public IP
- `admin` - your Linux user on the VM
- `$HOME\.ssh\wazuh` - your SSH key on the PC
- `LAPTOP-1`, `LAPTOP-2` - agent names (`/var/ossec/bin/agent_control -l`)
- `you@gmail.com`, `you@example.com` - sending account and the inbox that gets the alerts
- `<USER_SID>` - a Windows user's SID (`(Get-LocalUser $env:USERNAME).SID.Value`)

No passwords or keys live in this repo. The docs only say where each one goes. `.env`, keys and
certificates are in `.gitignore`.

## License

MIT, see [LICENSE](LICENSE).
