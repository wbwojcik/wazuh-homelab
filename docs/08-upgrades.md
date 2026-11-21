# Upgrades (all-in-one, APT)

I did this going from 4.14.4 to 4.14.8. The official guide:
<https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html>

Order: indexer -> manager + Filebeat -> dashboard. Run everything as root (`sudo -i`).

## 0. Preparation

1. Snapshot of the VM in your cloud provider's console. Wazuh >= 4.12 cannot be downgraded.
2. Check versions and memory:
   ```bash
   apt list --installed 2>/dev/null | grep -E 'wazuh|filebeat'
   free -h
   ```
3. Back up configs:
   ```bash
   tar czf /root/wazuh-backup-$(date +%F).tgz /var/ossec/etc /etc/wazuh-indexer /etc/wazuh-dashboard /etc/filebeat
   ```
4. Enable the repo / remove holds:
   ```bash
   cat /etc/apt/sources.list.d/wazuh.list        # uncomment the "deb" line if it starts with #
   sed -i 's/^#deb /deb /' /etc/apt/sources.list.d/wazuh.list
   apt-mark showhold                             # unhold wazuh packages if listed
   apt update
   ```

## 1. Indexer

Uses the admin certificate instead of a password:

```bash
C="--cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -k"
curl $C https://127.0.0.1:9200                      # must return JSON

systemctl stop filebeat wazuh-dashboard
curl $C -X PUT https://127.0.0.1:9200/_cluster/settings -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.routing.allocation.enable":"primaries"}}'
curl $C -X POST https://127.0.0.1:9200/_flush

systemctl stop wazuh-indexer
apt install -y wazuh-indexer
systemctl daemon-reload && systemctl enable --now wazuh-indexer
sleep 60                                            # slow on 4 GB

curl $C -X PUT https://127.0.0.1:9200/_cluster/settings -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.routing.allocation.enable":"all"}}'
curl $C "https://127.0.0.1:9200/_cat/health?v"      # green/yellow
dpkg -l wazuh-indexer | tail -1
```

Note: the indexer reports `"number": "7.10.2"` - that's the OpenSearch compatibility version, not Wazuh's.

## 2. Manager + Filebeat

```bash
systemctl stop wazuh-manager
apt install -y wazuh-manager

curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module
curl -so /etc/filebeat/wazuh-template.json \
  https://raw.githubusercontent.com/wazuh/wazuh/v<NEW_VERSION>/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
head -c 200 /etc/filebeat/wazuh-template.json; echo   # must be JSON, not 404

systemctl daemon-reload && systemctl restart wazuh-manager filebeat
filebeat setup --pipelines
filebeat setup --index-management -E output.logstash.enabled=false
filebeat test output                                    # ... OK
/var/ossec/bin/wazuh-control info | grep VERSION
```

## 3. Dashboard

```bash
apt install -y wazuh-dashboard
systemctl daemon-reload && systemctl enable --now wazuh-dashboard
```

The dashboard was stopped in step 1 - it stays down until this step. Wait 1-2 min, open in a private window.

## 4. Verify & finish

```bash
systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard   # 4x active
sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list                 # lock repo again
apt update && apt upgrade -y
reboot
```

After reboot: reconnect VPN, re-check the four services.

## Gotchas

- apt asks about modified config files (`ossec.conf`, `opensearch.yml`, `opensearch_dashboards.yml`) -> answer N (keep mine). `-y` does not answer these.
- Indexer `admin` password may differ from `wazuh-install-files.tar` if it was changed - that's why the certificate method is used.
- WireGuard must be enabled at boot, otherwise the reboot locks you out (see troubleshooting).
- Agents can stay on an older version; the manager accepts older agents. To upgrade them from the
  manager (laptop just needs to be online): `/var/ossec/bin/agent_upgrade -a 001`.
