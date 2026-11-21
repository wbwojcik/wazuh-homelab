# Index retention (auto-delete old data)

Wazuh keeps alerts forever by default, one daily index with 3 shards each. After about half a year I had
157 daily indices plus weekly stats, 545 shards on one 4 GB node, while the data itself was only 2.6 GB.
On a small node the problem is the shard count (indexer heap), not disk space. With the setup below I'm
at about 240 shards.

## What runs

| Name | Type | Applies to | Effect |
|---|---|---|---|
| `wazuh-alerts-retention` | ISM policy | `wazuh-alerts-*` | delete index when older than 90 days |
| `wazuh-stats-retention` | ISM policy | `wazuh-monitoring-*`, `wazuh-statistics-*` | delete index when older than 8 weeks |
| `wazuh-one-shard` | legacy index template, `order: 1` | `wazuh-alerts-4.x-*`, `wazuh-archives-4.x-*` | new daily indices get 1 shard, 0 replicas (overrides Wazuh's `wazuh` template, order 0) |

The policies carry an `ism_template`, so new indices get them automatically. Existing indices were
attached once with `_plugins/_ism/add`. ISM checks roughly every 5 minutes; age = index creation date.

JSON sources: [server/indexer/](../server/indexer/). The `wazuh-one-shard` template is separate from
Wazuh's own template, so a Wazuh upgrade (which reloads `wazuh`) doesn't undo it.

## Commands (on the server, as root)

Copy `server/indexer/*.json` to the server first and `cd` into that folder.

```bash
C="--cacert /etc/wazuh-indexer/certs/root-ca.pem --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem"; U=https://127.0.0.1:9200
# install / update a policy from the repo file
curl -s $C -X PUT "$U/_plugins/_ism/policies/wazuh-alerts-retention" -H 'Content-Type: application/json' -d @ism-wazuh-alerts.json
# (an update of an existing policy needs ?if_seq_no=..&if_primary_term=.. from a GET first)
curl -s $C -X PUT "$U/_plugins/_ism/policies/wazuh-stats-retention" -H 'Content-Type: application/json' -d @ism-wazuh-stats.json
curl -s $C -X PUT "$U/_template/wazuh-one-shard" -H 'Content-Type: application/json' -d @template-wazuh-one-shard.json
# attach to existing indices
curl -s $C -X POST "$U/_plugins/_ism/add/wazuh-alerts-*" -H 'Content-Type: application/json' -d '{"policy_id":"wazuh-alerts-retention"}'
curl -s $C -X POST "$U/_plugins/_ism/add/wazuh-monitoring-*,wazuh-statistics-*" -H 'Content-Type: application/json' -d '{"policy_id":"wazuh-stats-retention"}'
# check
curl -s $C "$U/_plugins/_ism/explain/wazuh-alerts-*?pretty" | grep -E '"index"|"state"|failed' | head
curl -s $C "$U/_cluster/health?pretty" | grep active_shards
curl -s $C "$U/_cat/indices/wazuh-alerts-*?h=index&s=index" | head -1   # oldest kept day
```

To change the retention, edit `min_index_age` in the policy and PUT it again; indices already
managed pick up the change only after `_plugins/_ism/change_policy`.
