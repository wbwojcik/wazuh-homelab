# Users and credentials

My rule: passwords go in the password manager and nowhere else. Not in git, not in docs, not in chats or
screenshots. The docs here only say where each one is kept.

## Accounts in this setup

| Account | Used by | Rights | Keep the password in |
|---|---|---|---|
| `admin` (Linux) | SSH + `sudo` on the VM | sudo | Password manager |
| SSH key | Your PC, login as `admin` | login | Key file on the PC, passphrase in the password manager |
| `admin` (indexer) | Dashboard login, indexer API | full admin | Password manager (original in `/root/wazuh-install-files.tar`) |
| `wazuh-wui` (API) | Dashboard -> manager API | administrator | Password manager + `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` |
| `wazuh` (API) | Built-in API admin | administrator | `/root/wazuh-install-files.tar` |
| `claude-ro` (API) | Claude MCP server | readonly | Password manager + `mcp-server/.env` on the PC |
| `claude-idx-ro` (indexer) | Claude MCP server (alerts, vulnerabilities) | read on two index patterns | Password manager + `mcp-server/.env` on the PC (MCP part, coming later) |
| Enrollment password | New agents on 1515 | can register agents only | Password manager + `/var/ossec/etc/authd.pass` |
| Mail relay app password | Postfix, for alert emails | sends mail as that account | Password manager + `/etc/postfix/sasl_passwd.db` (email part, coming later) |

Once every password is in the password manager, delete the install archive:
`shred -u /root/wazuh-install-files.tar`.

## Typing secrets safely

- Bash: `read -rs P` then `echo ${#P}`. The length must match the password manager. Pasting twice
  (double length) is the most common mistake.
- PowerShell: `Read-Host -AsSecureString`.
- Never put a password directly in a command line (it lands in shell history).

## Create a read-only API user (for Claude)

On the server (VPN on, as root). Get the `wazuh-wui` password into a variable first:

```bash
read -rs WUI; echo ${#WUI}
TOKEN=$(curl -sk -u "wazuh-wui:$WUI" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
read -rs NEWPASS; export NEWPASS; echo ${#NEWPASS}    # the new claude-ro password from the password manager
python3 -c 'import json,os; print(json.dumps({"username":"claude-ro","password":os.environ["NEWPASS"]}))' \
  | curl -sk -X POST "https://127.0.0.1:55000/security/users" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d @-; echo
```

Wazuh API passwords need upper and lower case, a digit and a symbol, 8+ characters.
The answer contains the new user's `id`. Find the `readonly` role id (usually 2) and attach it:

```bash
curl -sk "https://127.0.0.1:55000/security/roles?search=readonly" -H "Authorization: Bearer $TOKEN"; echo
curl -sk -X POST "https://127.0.0.1:55000/security/users/<USER_ID>/roles?role_ids=2" -H "Authorization: Bearer $TOKEN"; echo
unset WUI NEWPASS TOKEN
```

Change an API user's password later:

```bash
python3 -c 'import json,os; print(json.dumps({"password":os.environ["NEWPASS"]}))' \
  | curl -sk -X PUT "https://127.0.0.1:55000/security/users/<USER_ID>" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d @-; echo
```

API tokens expire after 15 minutes. Get a new one if you see HTTP 401.

## Rotate passwords

| Password | How |
|---|---|
| `wazuh-wui` | Change it in the API (above), and in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`, then `systemctl restart wazuh-dashboard` |
| Indexer `admin` | `bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p '<NEW>'` |
| `claude-ro` | API (above), then update `mcp-server/.env` |
| `claude-idx-ro` | Covered in the MCP part (coming later) |

As root, the indexer accepts the admin certificate, so you never need the indexer admin password on the
command line:

```bash
C="--cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -k"
curl $C "https://127.0.0.1:9200/_cat/health?v"
```
