#!/bin/bash
# wazuh-bad-domains.sh - daily list of known malware domains for Wazuh (rule 100260, docs/13-dns-watch.md).
# Downloads two free lists from malware-filter (gitlab.io, no account needed): urlhaus-filter = domains serving
# malware (from abuse.ch URLhaus, whose own download links closed in 2026), phishing-filter = phishing sites.
# Writes them as a Wazuh CDB list /var/ossec/etc/lists/bad-domains ("domain:source" per line) and restarts the
# manager only when the list changed (a CDB list is read when the manager starts).
#   Run by hand:  sudo /usr/local/bin/wazuh-bad-domains.sh
#   Cron:         /etc/cron.d/wazuh-bad-domains (05:40 every day)
set -euo pipefail

LIST=/var/ossec/etc/lists/bad-domains
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Fixed test entry: 'Resolve-DnsName wazuh-dns-test.invalid' on a laptop must send an email.
TEST_DOMAIN=wazuh-dns-test.invalid

fetch() {  # fetch <name> <url>: lines "domain" (or hostfile "127.0.0.1 domain") -> "domain:name"
  curl -fsS --max-time 120 "$2" -o "$TMP/$1.raw" || { echo "WARN: $1 download failed" >&2; return 0; }
  awk -v src="$1" '!/^[#!]/ && NF>=1 { d=tolower($NF); sub(/\.$/, "", d)
       if (d ~ /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/ && d !~ /^[0-9.]+$/ && d != "localhost") print d ":" src }' \
       "$TMP/$1.raw" > "$TMP/$1.list"
}
fetch malware  https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains.txt
fetch phishing https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt

{ cat "$TMP"/*.list 2>/dev/null || true; } | sort -t: -k1,1 -u > "$TMP/new"
count=$(wc -l < "$TMP/new")
# A broken download gives an empty/tiny list: keep yesterday's rather than lose the protection.
if [ "$count" -lt 500 ]; then
  echo "ERROR: only $count domains downloaded, keeping the old list" >&2
  exit 1
fi
echo "$TEST_DOMAIN:test" >> "$TMP/new"

if [ -f "$LIST" ] && cmp -s "$TMP/new" "$LIST"; then
  echo "bad-domains unchanged ($count domains)"
  exit 0
fi
[ -f "$LIST" ] && cp -p "$LIST" "$TMP/old"
install -o wazuh -g wazuh -m 640 "$TMP/new" "$LIST"
# Check the whole ruleset loads before restarting, so a bad list can't stop the manager.
if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>"$TMP/test.err"; then
  systemctl restart wazuh-manager
  echo "bad-domains updated: $count domains, manager restarted"
else
  echo "ERROR: wazuh-analysisd -t failed, old list put back, manager NOT restarted:" >&2
  if [ -f "$TMP/old" ]; then cp -p "$TMP/old" "$LIST"; else rm -f "$LIST"; fi
  cat "$TMP/test.err" >&2
  exit 1
fi
