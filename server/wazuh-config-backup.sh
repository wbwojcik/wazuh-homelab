#!/bin/bash
# wazuh-config-backup.sh - nightly backup of the Wazuh server's settings (not the alerts themselves).
# Saves rules, ossec.conf, agent keys, email setup, certificates, WireGuard, firewall and cron files into
# /root/backups/wazuh-config/wazuh-config-YYYY-MM-DD.tgz and keeps the last 14. See docs/07-backups.md.
#
# The archives hold secrets (agent keys, certificates, mail relay password, WireGuard key): only root can
# read them, and they never go to GitHub.
#   Run by hand:  sudo /usr/local/bin/wazuh-config-backup.sh
#   Cron:         /etc/cron.d/wazuh-config-backup (05:30 every day)
set -euo pipefail

DEST=/root/backups/wazuh-config
KEEP=14
PATHS=(
  /var/ossec/etc                          # ossec.conf, rules, decoders, agent keys, agent.conf, email-alert.conf
  /var/ossec/integrations/custom-email-alert
  /var/ossec/api/configuration
  /etc/wazuh-indexer
  /etc/wazuh-dashboard
  /etc/filebeat
  /etc/postfix
  /etc/aliases
  /etc/wireguard
  /etc/ufw
  /etc/ssh/sshd_config
  /etc/ssh/sshd_config.d
  /etc/cron.d/wazuh-vuln-digest
  /etc/cron.d/wazuh-config-backup
  /etc/cron.d/wazuh-bad-domains
  /usr/local/bin/wazuh-vuln-digest.py
  /usr/local/bin/wazuh-config-backup.sh
  /usr/local/bin/wazuh-bad-domains.sh
  /var/lib/wazuh-vuln-digest
  /etc/sysctl.d
  /etc/fstab
)

umask 077
mkdir -p "$DEST"
chmod 700 "$DEST"

existing=()
for p in "${PATHS[@]}"; do [ -e "$p" ] && existing+=("$p"); done

out="$DEST/wazuh-config-$(date +%F).tgz"
# Exit code 1 only means a file changed while it was read (fine for a nightly copy).
tar czf "$out.tmp" --ignore-failed-read "${existing[@]}" 2>/dev/null || [ $? -eq 1 ]
mv "$out.tmp" "$out"

# Keep only the newest $KEEP archives.
ls -1t "$DEST"/wazuh-config-*.tgz | tail -n +$((KEEP + 1)) | xargs -r rm -f

echo "$(date '+%F %T') backup ok: $out ($(du -h "$out" | cut -f1))" >> "$DEST/backup.log"
