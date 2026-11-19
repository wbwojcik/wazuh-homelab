# wazuh-homelab

My notes and scripts for running Wazuh at home: one small cloud VM watching a couple of Windows laptops,
emailing me only when something actually needs a look, plus a small read-only MCP server so I can ask
Claude about alerts instead of clicking through the dashboard.

I'm writing it down for myself first and cleaning out everything personal so others can use it.
It's a homelab setup, not a product. Read the scripts before you run them and try things on your own
machines first. Not affiliated with Wazuh or Anthropic.

Work in progress: I'm adding one part at a time.

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

## What's coming

- [x] [Server setup](docs/01-server-setup.md): VM, WireGuard, firewall, Wazuh, first agent, swap
- [ ] Users and credentials
- [ ] Email alerts: postfix relay, readable alert emails, daily vulnerability email
- [ ] Windows logging: Sysmon, audit policy, PowerShell, Defender, USB events
- [ ] Noise tuning: quieting the harmless stuff
- [ ] Index retention and backups
- [ ] Upgrades and troubleshooting
- [ ] Security baseline: 10 CIS settings that make sense on a home laptop
- [ ] USB guard and USB sandbox
- [ ] Suricata on a Windows laptop
- [ ] Browser watch
- [ ] DNS watch: lookups of known malware and phishing domains
- [ ] Read-only MCP server for Claude

## License

MIT, see [LICENSE](LICENSE).
