# Backups

I use two layers: the provider's daily disk backup, and a tiny nightly backup of just the settings.

| Layer | What it saves | When | Kept | Good for |
|---|---|---|---|---|
| Provider backups (e.g. Hetzner Backups) | the whole server disk (system, Wazuh, all alerts) | once a day | last 7 | server dead, deleted or badly broken |
| Config backup (`wazuh-config-backup.sh`) | settings only, about 0.5 MB | 05:30 every day, before the provider's copy | last 14 days | "I broke a setting", or rebuilding on a new server |

Provider backups are stored apart from the server and usually cost a small share of the server's price
(Hetzner: 20%). Turn them on in the provider's console. Before risky work (upgrades, big config changes)
also take a manual snapshot: it is kept until you delete it.

## Config backup

Script: [server/wazuh-config-backup.sh](../server/wazuh-config-backup.sh), installed as
`/usr/local/bin/wazuh-config-backup.sh`, cron `/etc/cron.d/wazuh-config-backup`.
Archives: `/root/backups/wazuh-config/wazuh-config-YYYY-MM-DD.tgz` (about 0.5 MB), log `backup.log` in the same folder.

What's in it: `/var/ossec/etc` (ossec.conf, rules, agent keys, agent.conf, email-alert.conf, enrollment
password), the email integration script, Wazuh API config, `/etc/wazuh-indexer`, `/etc/wazuh-dashboard`,
`/etc/filebeat` (certificates), postfix (mail relay), WireGuard, UFW, sshd config, the cron files,
the vulnerability digest script and state, sysctl and fstab (swap).

Not in it: alerts and other indexed data (only in the provider backups), and indexer users created through
the API (`claude-idx-ro`): recreate them from [14](14-claude-mcp.md).

The archives hold secrets (agent keys, certificates, mail relay password, WireGuard private key).
Only root can read them. Never put them on GitHub. To keep a copy on the PC, copy one to the PC and
store it in an encrypted place (for example an attachment in the password manager).

### Install / update (server)

Copy the files from the PC (PowerShell, in the repo folder):

```powershell
scp -i $HOME\.ssh\wazuh server\wazuh-config-backup.sh admin@10.10.0.1:/tmp/
```

On the server:

```bash
sudo sed -i 's/\r$//' /tmp/wazuh-config-backup.sh
sudo install -o root -g root -m 700 /tmp/wazuh-config-backup.sh /usr/local/bin/wazuh-config-backup.sh
echo '30 5 * * * root /usr/local/bin/wazuh-config-backup.sh' | sudo tee /etc/cron.d/wazuh-config-backup
sudo /usr/local/bin/wazuh-config-backup.sh && sudo tail -n 1 /root/backups/wazuh-config/backup.log
```

### Check it runs

```bash
sudo ls -lh /root/backups/wazuh-config/
sudo tail -n 3 /root/backups/wazuh-config/backup.log
```

### Restore one file

Example: put back an older `noise_tuning.xml` (pick the date from `ls /root/backups/wazuh-config/`).

```bash
sudo tar xzf /root/backups/wazuh-config/wazuh-config-YYYY-MM-DD.tgz -C /tmp var/ossec/etc/rules/noise_tuning.xml
sudo diff /tmp/var/ossec/etc/rules/noise_tuning.xml /var/ossec/etc/rules/noise_tuning.xml
sudo install -o wazuh -g wazuh -m 660 /tmp/var/ossec/etc/rules/noise_tuning.xml /var/ossec/etc/rules/noise_tuning.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Restore the whole server

Provider console -> server -> Backups -> pick a day -> Restore (overwrites the current disk), or
turn the backup into a snapshot and create a new server from it. Agents keep working because the agent keys come back too.

## Rebuild from scratch

Install the same Wazuh version all-in-one ([01](01-server-setup.md)), then put back the archive's files
(or follow the docs again): WireGuard + UFW, `authd.pass`, rules, email integration + postfix, cron files,
`agent.conf`, index policies ([06](06-index-retention.md)), swap, read-only users.
Agents need new keys after a rebuild unless `client.keys` came back: re-enroll each laptop with the
enrollment password.
