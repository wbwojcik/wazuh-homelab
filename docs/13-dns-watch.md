# DNS watch: known malware domains

Sysmon already logs every DNS lookup (event 22, about 3,000 a day on my laptop, mostly the browser).
Wazuh gets them but stores none of them (built-in rule 61650 is level 0), so the indexer doesn't fill up
with browsing history. I just wanted an email if one of them is a known bad domain.

Rule 100260 (level 12, email) fires when a looked-up domain is on one of two free lists from
[malware-filter](https://gitlab.com/malware-filter) (no account needed, about 18,000 + 17,000 domains in late 2026):

- urlhaus-filter: sites serving malware right now (built from abuse.ch URLhaus)
- phishing-filter: phishing sites (fake login pages)

abuse.ch's own hostfile downloads (URLhaus/ThreatFox) now need an account key.

`server/wazuh-bad-domains.sh` downloads both lists every day at 05:40, writes the Wazuh CDB list
`/var/ossec/etc/lists/bad-domains` (`domain:source` per line), checks the ruleset with `wazuh-analysisd -t` and
restarts the manager only if the list changed (Wazuh reads CDB lists at start). A failed download (< 500 domains)
keeps yesterday's list.

Limits: exact match only (a lookup of `a.evil.com` doesn't match a listed `evil.com`), and only on laptops with
Sysmon. Suricata ([11](11-suricata.md)) covers the network side.

## Install (server, as root)

```powershell
# on the PC, in the repo folder
scp -i $HOME\.ssh\wazuh server\custom-email-alert server\noise_tuning.xml server\wazuh-bad-domains.sh admin@10.10.0.1:/tmp/
```

```bash
cd /tmp && sed -i 's/\r$//' custom-email-alert noise_tuning.xml wazuh-bad-domains.sh
install -o root -g wazuh -m 750 custom-email-alert /var/ossec/integrations/custom-email-alert
install -o wazuh -g wazuh -m 660 noise_tuning.xml /var/ossec/etc/rules/noise_tuning.xml
install -o root -g root -m 755 wazuh-bad-domains.sh /usr/local/bin/wazuh-bad-domains.sh
grep -q 'etc/lists/bad-domains' /var/ossec/etc/ossec.conf || \
  sed -i '0,/<\/ruleset>/s||  <list>etc/lists/bad-domains</list>\n  </ruleset>|' /var/ossec/etc/ossec.conf
echo '40 5 * * * root /usr/local/bin/wazuh-bad-domains.sh >> /var/log/wazuh-bad-domains.log 2>&1' > /etc/cron.d/wazuh-bad-domains
/usr/local/bin/wazuh-bad-domains.sh
```

The last line prints `bad-domains updated: N domains, manager restarted`.

## Test

The list always contains `wazuh-dns-test.invalid`. On a laptop with Sysmon:

```powershell
Resolve-DnsName wazuh-dns-test.invalid
```

It fails to resolve (that's fine, Sysmon still logs the lookup) and an email "Known malware domain looked up"
arrives within a minute.

## If an email comes

The email names the program and the domain. A browser hitting a listed domain is usually a bad ad or hacked
site (close the tab, don't run what it downloaded). Any other program is more serious: Wi-Fi off, Defender full
scan, forward the email to Claude.
