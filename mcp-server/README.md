# Wazuh MCP server (read-only)

A small MCP server that lets Claude (desktop app) query your Wazuh manager API and, for alerts
and vulnerabilities, the Wazuh indexer.
It runs on your PC; the Claude desktop app starts it automatically and talks to it over stdio.

```
Claude -> Claude desktop app (PC) -> wazuh_mcp.py -> WireGuard -> https://10.10.0.1:55000  (manager API)
                                        \-> SSH tunnel -> 127.0.0.1:9200 on server (indexer)
```

Read-only by design: the API client only sends GET requests and logs in as `claude-ro` (role `readonly`);
the indexer client can only run `_search` on `wazuh-alerts-*` / `wazuh-states-vulnerabilities-*` and logs in as
`claude-idx-ro` (read-only role `claude_ro`). Inputs are validated and results are capped at 500 items.

## Tools

| Tool | What it returns |
|---|---|
| `manager_info` | Wazuh version + daemon status |
| `agents_summary` | Agent counts by status |
| `list_agents` | Agents (filter by status / search) |
| `get_agent` | Full detail for one agent |
| `list_groups` | Agent groups |
| `agent_os_hardware` | OS + hardware inventory |
| `agent_packages` | Installed packages (search e.g. `openssl`) |
| `agent_open_ports` | Listening ports + process |
| `agent_processes` | Running processes |
| `agent_fim_files` | File Integrity Monitoring database |
| `agent_sca_policies` | SCA (CIS) policies + score |
| `agent_sca_failed_checks` | Failed SCA checks with remediation |
| `search_rules` / `get_rule` | Detection rules (incl. MITRE mapping) |
| `manager_logs` | Manager `ossec.log` entries |
| `alerts_summary` | Alerts in a time window by level, rule, agent, group, MITRE technique, source IP |
| `search_alerts` | Alerts newest first (filter by time, min level, agent, rule, group, free text) |
| `get_alert` | One full alert document |
| `vulnerabilities_summary` | Vulnerabilities by severity, agent, package, CVE |
| `list_vulnerabilities` | Vulnerabilities, highest CVSS first (filter by agent, severity, CVE or package) |

The last five need the indexer: SSH tunnel running + `INDEXER_*` in `.env`. One-time server setup and the
tunnel command: [docs/14-claude-mcp.md](../docs/14-claude-mcp.md). Without them the other tools still work.

## Setup on Windows

Requirements: Python 3.10+ (after a Python upgrade, rebuild `.venv`), WireGuard connected.

```powershell
# 1. Copy this folder to e.g. $HOME\wazuh-mcp (or clone the repo and use its mcp-server folder)
cd $HOME\wazuh-mcp

# 2. Virtual environment + dependencies
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 3. Config
copy .env.example .env
notepad .env          # set WAZUH_API_URL, WAZUH_API_PASSWORD (claude-ro) and INDEXER_PASSWORD (claude-idx-ro)

# 4. Test
.\.venv\Scripts\python.exe wazuh_mcp.py --check
#  -> OK - Wazuh v4.14.8 ...
#  -> OK - wazuh-alerts-*: ... alerts        (needs the SSH tunnel)
```

## Connect it to the Claude desktop app

Claude desktop -> Settings -> Developer -> Edit Config (opens `claude_desktop_config.json`, usually
`%APPDATA%\Claude\claude_desktop_config.json`). Add the `wazuh` entry inside `mcpServers`
(keep any entries that are already there):

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:\\Users\\<you>\\wazuh-mcp\\.venv\\Scripts\\python.exe",
      "args": ["C:\\Users\\<you>\\wazuh-mcp\\wazuh_mcp.py"]
    }
  }
}
```

Fully quit Claude (tray icon -> Quit) and start it again. Then ask Claude e.g. *"list my Wazuh agents"*.

Logs if it doesn't show up: `%APPDATA%\Claude\logs\mcp-server-wazuh.log`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot reach https://10.10.0.1:55000` | WireGuard off, or UFW rule for 55000 missing |
| `Login failed (HTTP 401)` | Wrong password in `.env` / user changed |
| `HTTP 403` on a tool | `claude-ro` lacks the `readonly` role (role id 2) |
| `Cannot reach https://127.0.0.1:9200 - is the SSH tunnel running?` | Start the tunnel ([docs/14](../docs/14-claude-mcp.md)) |
| `Indexer login failed (HTTP 401)` / 403 on alert tools | See troubleshooting in [docs/14](../docs/14-claude-mcp.md#troubleshooting) |
| Tool missing in Claude | Config JSON typo, wrong path, Claude not fully restarted - check the log above |
