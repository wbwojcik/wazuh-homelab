# Claude MCP server

This is the part I use most day to day. The [MCP server](../mcp-server/) lets Claude read Wazuh: agents, inventory, SCA, FIM, rules and
manager logs through the manager API (read-only user `claude-ro`, see [02](02-users-and-credentials.md#create-a-read-only-api-user-for-claude)),
and alerts and vulnerabilities through the indexer (this page). Then I can ask things like
*"anything worrying on LAPTOP-1 this week?"* or paste an alert email and ask what to do.

Setup of the server itself (Python, `.env`, Claude desktop config): [mcp-server/README.md](../mcp-server/README.md).

## Indexer access (alerts + vulnerabilities)

Alerts (`wazuh-alerts-*`) and vulnerabilities (`wazuh-states-vulnerabilities-*`) live in the indexer,
not in the manager API. The indexer only listens on `127.0.0.1:9200` on the server, so the MCP server
reaches it through an SSH tunnel and logs in as a read-only indexer user.

```
wazuh_mcp.py (PC) -> 127.0.0.1:9200 (PC) == SSH tunnel over WireGuard ==> 127.0.0.1:9200 (server)
```

| Item | Value |
|---|---|
| Indexer user | `claude-idx-ro` |
| Indexer role | `claude_ro` - `read` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`, nothing else |
| Password | Password manager + local `mcp-server/.env` on the PC |

### 1. Create the role and user (server, once)

First create a new entry for `claude-idx-ro` in the password manager and let it generate the
password (letters, digits and a symbol, 16+ chars). Then:

```powershell
ssh -i $HOME\.ssh\wazuh admin@10.10.0.1
```

```bash
sudo -i
C="--cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -k -H Content-Type:application/json"
API=https://127.0.0.1:9200/_plugins/_security/api

# Role: read-only on alerts + vulnerabilities
curl -s $C -X PUT $API/roles/claude_ro -d '{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-states-vulnerabilities-*"],
    "allowed_actions": ["read"]
  }]
}'; echo

# User - paste the password from the password manager ONCE (right-click OR Ctrl+V, not both),
# then Enter. Nothing is shown while you type.
read -rs P; export P; echo
echo ${#P}    # must equal the password length in the password manager (e.g. 16); 0 or double = paste again
python3 -c 'import json,os; print(json.dumps({"password": os.environ["P"]}))' \
  | curl -s $C -X PUT $API/internalusers/claude-idx-ro -d @-; echo

# Map the role to the user
curl -s $C -X PUT $API/rolesmapping/claude_ro -d '{"users": ["claude-idx-ro"]}'; echo
```

Each `curl` should answer `"status":"CREATED"` (or `"OK"` when re-run).

### 2. Verify it is read-only (server)

```bash
curl -sk -u "claude-idx-ro:$P" "https://127.0.0.1:9200/wazuh-alerts-*/_count"; echo
#  -> {"count":12345,...}
curl -sk -u "claude-idx-ro:$P" "https://127.0.0.1:9200/wazuh-states-vulnerabilities-*/_count"; echo
#  -> {"count":...}   (0 is fine if vulnerability detection has found nothing yet)
curl -sk -u "claude-idx-ro:$P" -X DELETE "https://127.0.0.1:9200/wazuh-alerts-4.x-2000.01.01"; echo
#  -> 403 "security_exception"  (good: no write/delete)
curl -sk -u "claude-idx-ro:$P" "https://127.0.0.1:9200/_cat/indices"; echo
#  -> 403 (good: can't see other indices)
unset P; exit
```

### 3. SSH tunnel (PC, whenever Claude should see alerts)

```powershell
ssh -i $HOME\.ssh\wazuh -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -L 9200:127.0.0.1:9200 admin@10.10.0.1 "echo TUNNEL READY; sleep infinity"
```

After the key passphrase it prints `TUNNEL READY`. Leave that window open. Test from another window:

```powershell
Test-NetConnection 127.0.0.1 -Port 9200     # TcpTestSucceeded : True
```

Optional - run it hidden without typing the key passphrase each time (Windows OpenSSH agent, admin PowerShell once):

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent
ssh-add $HOME\.ssh\wazuh         # passphrase once
# then, any time:
Start-Process ssh -WindowStyle Hidden -ArgumentList "-i $HOME\.ssh\wazuh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -L 9200:127.0.0.1:9200 admin@10.10.0.1"
```

### 4. Configure the MCP server (PC)

Add to `mcp-server/.env` (see `.env.example`), password from the password manager:

```
INDEXER_URL=https://127.0.0.1:9200
INDEXER_USER=claude-idx-ro
INDEXER_PASSWORD=...
INDEXER_VERIFY_SSL=false
```

```powershell
.\.venv\Scripts\python.exe wazuh_mcp.py --check
#  -> OK - wazuh-alerts-*: ... alerts
#  -> OK - wazuh-states-vulnerabilities-*: ... vulnerabilities
```

Restart the Claude desktop app (tray -> Quit) so it picks up the new tools.

## Maintenance

- The user and role live in the indexer's security index. After `wazuh-passwords-tool.sh` or an upgrade,
  check they still exist: `curl -s $C $API/internalusers/claude-idx-ro` (with `C`/`API` from step 1).
- Change the password: repeat the *User* block of step 1 (same `PUT`), then update `.env`.
- Remove access completely:
  ```bash
  curl -s $C -X DELETE $API/rolesmapping/claude_ro; curl -s $C -X DELETE $API/internalusers/claude-idx-ro; curl -s $C -X DELETE $API/roles/claude_ro
  ```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot reach https://127.0.0.1:9200 - is the SSH tunnel running?` | Start the tunnel (step 3); WireGuard must be on |
| Tunnel: `bind ... Address already in use` | Something else uses 9200 on the PC - use `-L 9201:127.0.0.1:9200` and `INDEXER_URL=https://127.0.0.1:9201` |
| `Indexer login failed (HTTP 401)` | Password in `.env` ≠ password on the server. Common cause: pasted twice (32 chars instead of 16). Check `.env`: `.\.venv\Scripts\python.exe -c "import wazuh_mcp as w; print(len(w.INDEXER_PASSWORD))"`; reset the server side with the *User* block of step 1. Also check the user exists (see Maintenance) |
| `HTTP 403` on a tool | Role mapping missing - re-run the *Map the role* line of step 1 |
| Vulnerability tools return 0 | Vulnerability detection off or not run yet: `<vulnerability-detection>` in `/var/ossec/etc/ossec.conf` |

## Optional: a tunnel-only SSH key

Give the tunnel its own key that can do nothing but forward to the indexer. In
`/home/admin/.ssh/authorized_keys` on the server, prefix that key's line with:

```
restrict,port-forwarding,permitopen="127.0.0.1:9200" ssh-ed25519 AAAA... tunnel-key
```
