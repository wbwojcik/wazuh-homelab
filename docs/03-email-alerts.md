# Email alerts (urgent events + daily vulnerability email)

I only want an email when I should do something now. Everything else stays in the dashboard for later.
Wazuh's built-in email sends raw alert text, so I replaced it with a small script that writes what happened,
why it matters and what to do, with the raw event at the bottom.

```
alert level >= 12 -> integratord -> custom-email-alert --\
cron 06:00 -> wazuh-vuln-digest.py (indexer) ------------+-> postfix -> Gmail (587) -> inbox
```

| Item | Where |
|---|---|
| Urgent email script | `/var/ossec/integrations/custom-email-alert` ([source](../server/custom-email-alert)) |
| Its settings | `/var/ossec/etc/email-alert.conf` ([example](../server/email-alert.conf.example)) |
| Urgent rules | `/var/ossec/etc/rules/noise_tuning.xml` ([source](../server/noise_tuning.xml)) and `local_rules.xml` ([source](../server/local_rules.xml)) |
| Daily vulnerability email | `/usr/local/bin/wazuh-vuln-digest.py` ([source](../server/wazuh-vuln-digest.py)), `/etc/cron.d/wazuh-vuln-digest` |

Every subject starts with `Wazuh Alert - <agent name> - ...`, so one inbox rule can file them in a folder
(and per-laptop folders are a "subject contains LAPTOP-1" rule).

## 1. Mail relay: postfix -> Gmail

Many cloud providers block outgoing ports 25 and 465; port 587 to Gmail works. Create a Gmail
app password (Google Account > Security > 2-Step Verification > App passwords) and keep it in the
password manager. The `From` address must be the Gmail account itself (plus-addresses get rewritten).

```bash
sudo -i
apt install -y postfix libsasl2-modules mailutils     # choose "Internet Site", name = server hostname
postconf -e 'relayhost = [smtp.gmail.com]:587' \
  'smtp_sasl_auth_enable = yes' 'smtp_sasl_security_options = noanonymous' \
  'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd' \
  'smtp_tls_security_level = encrypt' 'inet_interfaces = loopback-only'

read -rs P; echo ${#P}        # Gmail app password, 16 characters
printf '[smtp.gmail.com]:587 you@gmail.com:%s\n' "$P" > /etc/postfix/sasl_passwd; unset P
postmap /etc/postfix/sasl_passwd && chmod 600 /etc/postfix/sasl_passwd*
chfn -f "Wazuh Alert" root    # otherwise the sender shows as "root"
systemctl restart postfix
echo test | mail -s "Wazuh Alert - test" you@example.com && sleep 5 && mailq    # empty = sent
```

Any other SMTP provider with port 587 works the same way: change `relayhost` and the `sasl_passwd` line.

## 2. Install the scripts and rules

Copy from your checkout to the server (PowerShell, repo folder):

```powershell
scp -i $HOME\.ssh\wazuh server\custom-email-alert server\wazuh-vuln-digest.py server\noise_tuning.xml server\local_rules.xml server\email-alert.conf.example admin@10.10.0.1:/tmp/
```

On the server (as root):

```bash
cd /tmp && sed -i 's/\r$//' custom-email-alert wazuh-vuln-digest.py noise_tuning.xml local_rules.xml email-alert.conf.example
install -o root -g wazuh -m 750 custom-email-alert /var/ossec/integrations/custom-email-alert
install -o root -g root  -m 755 wazuh-vuln-digest.py /usr/local/bin/wazuh-vuln-digest.py
install -o wazuh -g wazuh -m 660 noise_tuning.xml /var/ossec/etc/rules/noise_tuning.xml
install -o wazuh -g wazuh -m 660 local_rules.xml /var/ossec/etc/rules/local_rules.xml
install -o root -g wazuh -m 640 email-alert.conf.example /var/ossec/etc/email-alert.conf
nano /var/ossec/etc/email-alert.conf      # set MAIL_FROM, MAIL_TO, TIMEZONE
```

The `sed` strips Windows line endings. Without it a script copied from a Windows checkout fails with
"cannot execute: required file not found" and no email goes out. (`.gitattributes` forces LF for
`server/`, so a fresh clone is fine, but strip anyway.)

Then in `/var/ossec/etc/ossec.conf`: set `<email_notification>no</email_notification>` in `<global>` (the
script replaces Wazuh's built-in email) and add inside `<ossec_config>`:

```xml
<integration>
  <name>custom-email-alert</name>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```

Daily vulnerability email at 06:00 (server time):

```bash
cat > /etc/cron.d/wazuh-vuln-digest <<'EOF'
0 6 * * * root DIGEST_FROM=you@gmail.com DIGEST_TO=you@example.com DIGEST_TZ=UTC /usr/local/bin/wazuh-vuln-digest.py >> /var/log/wazuh-vuln-digest.log 2>&1
EOF
```

## 3. Test

```bash
# Urgent email from the newest level 12+ alert (prints only, sends nothing):
tail -n 5000 /var/ossec/logs/alerts/alerts.json | grep '"level":1[2-5]' | tail -1 > /tmp/a.json
/var/ossec/integrations/custom-email-alert --dry-run /tmp/a.json
# Vulnerability email (prints only):
/usr/local/bin/wazuh-vuln-digest.py --dry-run
```

Real test: plug a USB stick into a laptop (needs the Windows logging part, coming next). Or download the
[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) and let Defender catch it.

## What sends an email

Any alert at level 12 or higher, except vulnerability alerts (those go in the daily email):

| Event | Rule |
|---|---|
| Malware found by Defender | 62123 (Wazuh) |
| Defender real-time protection turned off | 100233 |
| Event log cleared / audit policy changed | 100230 / 100231 |
| New or re-enabled user account / Administrators group changed | 100232 / 60154 |
| AutoPlay policy changed | 100234 |
| New USB device | 100221 |
| Remote Desktop login | 100162 |
| Windows failed-login burst or lockout / SSH brute force on the server | 100211 / 100212 |
| Credential dumping (Sysmon) | 100111 |
| Browser started cmd / PowerShell / script tool (Sysmon) | 100250 |
| New browser native messaging host | 100252 |
| Suricata high-severity alert | 100240 |
| Known malware / phishing domain looked up (Sysmon) | 100260 |
| Wazuh agent overloaded | 202-205 group `agent_flooding` |
| Any built-in Wazuh rule at level 12-15 | |

Flood protection: at most `MAX_PER_HOUR` emails (10), and the same rule on the same agent at most every
`REPEAT_MINUTES` (30). For Suricata, each signature has its own window.

## Email layout

Urgent: title, a "probably harmless / check this" hint when the program is recognised, then
WHAT HAPPENED (which computer, when, in your time zone), WHY IT MATTERS, YOUR OPTIONS,
DETAILS, and the raw event at the bottom (handy to paste into Claude).

Daily vulnerabilities: per laptop, one line per program to update with the number of critical CVEs and how
to update it, then what is new or fixed since the last email, then the CVE list. Sent only when something
changed (the first run sends the full list). `NVD_MAX_LOOKUPS=150` in the cron line adds "update to
version X" from NVD (slow: about 15 minutes on the first run, no API key).

## Different email settings per laptop

Add `.<agent name>` to a key in `/var/ossec/etc/email-alert.conf`. No restart needed.

| Setting | Effect |
|---|---|
| `SKIP_RULES.LAPTOP-2=100221` | no new-USB emails for LAPTOP-2 |
| `MIN_LEVEL.LAPTOP-2=14` | only that laptop's alerts at level 14+ |
| `MUTE.LAB-VM=yes` | no emails at all for that agent (alerts stay in the dashboard) |
| `MAIL_TO.LAPTOP-2=someone@example.com` | that laptop's emails go to another address |

## Troubleshooting

| Symptom | Check |
|---|---|
| No urgent email | `tail /var/ossec/logs/integrations.log` (sent / skipped / error), `tail /var/ossec/logs/ossec.log`, `mailq`, `journalctl -u postfix -n 30` |
| "required file not found" in the logs | Windows line endings: `sed -i 's/\r$//'` the script and install again |
| "skipped (rate limit)" | Expected during floods; limits in `email-alert.conf` |
| What did the daily run do? | `tail /var/log/wazuh-vuln-digest.log` |
| Start the vulnerability email from scratch | `rm /var/lib/wazuh-vuln-digest/state.json` |
