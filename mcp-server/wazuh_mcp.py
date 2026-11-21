"""
Wazuh MCP server (read-only)
============================

Exposes a small, curated set of *read-only* Wazuh calls as MCP tools, so Claude can
look at agents, inventory, FIM, SCA, rules and manager logs (manager API), plus alerts
and vulnerabilities (indexer, reached through an SSH tunnel).

Safety by design:
  * The manager API client only ever sends GET requests (plus the login POST).
  * The indexer client only ever sends GET /<wazuh-alerts-*|wazuh-states-vulnerabilities-*>/_search.
  * Both are meant to run with read-only users (API role `readonly`, indexer role `claude_ro`).
  * Agent IDs and filters are validated, result sizes are capped.

Config comes from a `.env` file next to this script (see `.env.example`).

Usage:
  python wazuh_mcp.py           -> run as an MCP server over stdio (Claude starts it)
  python wazuh_mcp.py --check   -> test the connection and print manager info, then exit
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def load_env(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE per line, # comments). Real env vars win."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env(BASE_DIR / ".env")

API_URL = os.environ.get("WAZUH_API_URL", "https://10.10.0.1:55000").rstrip("/")
API_USER = os.environ.get("WAZUH_API_USER", "")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
TIMEOUT = float(os.environ.get("WAZUH_TIMEOUT", "30"))
TOKEN_TTL = 600  # seconds; Wazuh tokens live 900 s by default, refresh early
MAX_LIMIT = 500


# Indexer (OpenSearch) - optional; alert/vulnerability tools need it.
INDEXER_URL = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
INDEXER_USER = os.environ.get("INDEXER_USER", "")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD", "")
ALERTS_INDEX = "wazuh-alerts-*"
VULNS_INDEX = "wazuh-states-vulnerabilities-*"


def _verify_setting(var: str = "WAZUH_VERIFY_SSL") -> bool | str:
    """'false' (self-signed lab cert), 'true', or a path to a CA/cert file."""
    raw = os.environ.get(var, "false").strip()
    if raw.lower() in ("false", "0", "no", ""):
        return False
    if raw.lower() in ("true", "1", "yes"):
        return True
    return raw


VERIFY = _verify_setting()
INDEXER_VERIFY = _verify_setting("INDEXER_VERIFY_SSL")

# Logs must go to stderr: stdout is the MCP protocol channel.
logging.basicConfig(
    stream=sys.stderr,
    level=os.environ.get("WAZUH_MCP_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s wazuh-mcp: %(message)s",
)
log = logging.getLogger("wazuh-mcp")
logging.getLogger("httpx").setLevel(logging.WARNING)  # don't log every request URL

# ---------------------------------------------------------------------------
# Wazuh API client (GET-only)
# ---------------------------------------------------------------------------


class WazuhAPIError(RuntimeError):
    pass


class WazuhAPI:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(base_url=API_URL, verify=VERIFY, timeout=TIMEOUT)
        self._token: str | None = None
        self._token_at = 0.0
        self._lock = asyncio.Lock()

    async def _login(self) -> None:
        if not API_USER or not API_PASSWORD:
            raise WazuhAPIError("WAZUH_API_USER / WAZUH_API_PASSWORD are not set (check .env).")
        resp = await self._client.post(
            "/security/user/authenticate", params={"raw": "true"}, auth=(API_USER, API_PASSWORD)
        )
        if resp.status_code != 200:
            raise WazuhAPIError(f"Login failed (HTTP {resp.status_code}): {resp.text[:300]}")
        self._token = resp.text.strip()
        self._token_at = time.monotonic()
        log.info("Authenticated to %s as %s", API_URL, API_USER)

    async def _ensure_token(self, force: bool = False) -> None:
        async with self._lock:
            if force or not self._token or time.monotonic() - self._token_at > TOKEN_TTL:
                await self._login()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            await self._ensure_token()
            resp = await self._client.get(path, params=clean, headers=self._headers())
            if resp.status_code == 401:  # token expired/revoked -> one retry
                await self._ensure_token(force=True)
                resp = await self._client.get(path, params=clean, headers=self._headers())
        except httpx.ConnectError as exc:
            raise WazuhAPIError(
                f"Cannot reach {API_URL} - is WireGuard connected? ({exc})"
            ) from exc
        except httpx.TimeoutException as exc:
            raise WazuhAPIError(f"Timeout talking to {API_URL}") from exc
        except httpx.HTTPError as exc:  # any other transport/protocol error
            raise WazuhAPIError(
                f"HTTP error talking to {API_URL}: {type(exc).__name__}: {exc}"
            ) from exc
        if resp.status_code >= 400:
            raise WazuhAPIError(f"GET {path} -> HTTP {resp.status_code}: {resp.text[:400]}")
        return resp.json()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}


api = WazuhAPI()

# ---------------------------------------------------------------------------
# Indexer client (search-only)
# ---------------------------------------------------------------------------


class Indexer:
    """Read-only OpenSearch client. Only `_search` on the two Wazuh index patterns is possible."""

    ALLOWED = (ALERTS_INDEX, VULNS_INDEX)

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=INDEXER_URL,
            verify=INDEXER_VERIFY,
            timeout=TIMEOUT,
            auth=(INDEXER_USER, INDEXER_PASSWORD),
        )

    async def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        if index not in self.ALLOWED:
            raise WazuhAPIError(f"Index {index!r} is not allowed")
        if not INDEXER_USER or not INDEXER_PASSWORD:
            raise WazuhAPIError("INDEXER_USER / INDEXER_PASSWORD are not set (check .env).")
        try:
            # OpenSearch accepts a body on GET _search; keeps this client GET-only.
            resp = await self._client.request(
                "GET", f"/{index}/_search", json=body, params={"ignore_unavailable": "true"}
            )
        except httpx.ConnectError as exc:
            raise WazuhAPIError(
                f"Cannot reach {INDEXER_URL} - is the SSH tunnel running? ({exc})"
            ) from exc
        except httpx.TimeoutException as exc:
            raise WazuhAPIError(f"Timeout talking to {INDEXER_URL}") from exc
        except httpx.HTTPError as exc:
            raise WazuhAPIError(
                f"HTTP error talking to {INDEXER_URL}: {type(exc).__name__}: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise WazuhAPIError("Indexer login failed (HTTP 401) - check INDEXER_USER / INDEXER_PASSWORD")
        if resp.status_code >= 400:
            raise WazuhAPIError(f"Indexer search on {index} -> HTTP {resp.status_code}: {resp.text[:400]}")
        return resp.json()


indexer = Indexer()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGENT_ID_RE = re.compile(r"^\d{1,6}$")


def agent_id_ok(agent_id: str | int) -> str:
    """Normalise '1' -> '001' and reject anything that is not a plain number."""
    s = str(agent_id).strip()
    if not _AGENT_ID_RE.match(s):
        raise WazuhAPIError(f"Invalid agent id: {agent_id!r} (expected digits, e.g. 001)")
    return s.zfill(3)


def clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def items(resp: dict[str, Any]) -> str:
    """Return the useful part of a Wazuh response as compact JSON."""
    data = resp.get("data", resp)
    if isinstance(data, dict) and "affected_items" in data:
        out: dict[str, Any] = {
            "total": data.get("total_affected_items"),
            "returned": len(data.get("affected_items") or []),
            "items": data.get("affected_items"),
        }
        if data.get("failed_items"):
            out["failed_items"] = data["failed_items"]
    else:
        out = data
    return json.dumps(out, indent=1, ensure_ascii=False, default=str)


def safe(fn):
    """Turn validation/API errors into a clean JSON error for Claude instead of a traceback."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except (WazuhAPIError, ValueError) as exc:
            return json.dumps({"error": str(exc)})

    return wrapper


_SINCE_RE = re.compile(r"^\d{1,4}[mhdw]$")
_RULE_GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_CVE_RE = re.compile(r"^(CVE|GHSA)-[\w-]{4,40}$", re.IGNORECASE)
_SEVERITIES = ("critical", "high", "medium", "low")


def since_ok(since: str) -> str:
    """'24h' -> 'now-24h'. Accepts minutes, hours, days, weeks (e.g. 30m, 24h, 7d, 2w)."""
    s = str(since).strip().lower()
    if not _SINCE_RE.match(s):
        raise WazuhAPIError(f"Invalid since: {since!r} (expected e.g. 30m, 24h, 7d, 2w)")
    return f"now-{s}"


def shorten(value: Any, max_text: int) -> Any:
    """Recursively cut long strings (full_log, descriptions ...) so results stay readable."""
    if isinstance(value, str) and len(value) > max_text:
        return value[:max_text] + " ...[truncated]"
    if isinstance(value, dict):
        return {k: shorten(v, max_text) for k, v in value.items()}
    if isinstance(value, list):
        return [shorten(v, max_text) for v in value]
    return value


def hits(resp: dict[str, Any], max_text: int = 1500) -> list[dict[str, Any]]:
    """Return the _source of each hit (plus its _id), with long text fields shortened."""
    return [
        {"_id": h.get("_id"), **shorten(h.get("_source") or {}, max_text)}
        for h in resp.get("hits", {}).get("hits", [])
    ]


def total(resp: dict[str, Any]) -> int | None:
    t = resp.get("hits", {}).get("total")
    return t.get("value") if isinstance(t, dict) else t


def buckets(resp: dict[str, Any], name: str) -> list[list[Any]]:
    """Terms aggregation as compact [key, count] pairs."""
    agg = resp.get("aggregations", {}).get(name, {})
    return [[b.get("key"), b.get("doc_count")] for b in agg.get("buckets", [])]


async def isearch(index: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        return await indexer.search(index, body)
    except WazuhAPIError as exc:
        log.warning("%s", exc)
        raise


async def run(path: str, params: dict[str, Any] | None = None) -> str:
    try:
        return items(await api.get(path, params))
    except WazuhAPIError as exc:
        log.warning("%s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

mcp = MCPServer(
    name="wazuh",
    instructions=(
        "Read-only access to the user's private Wazuh homelab SIEM. "
        "Use these tools to inspect agents, their inventory, FIM, SCA results, rules "
        "and manager logs (manager API), and alerts and vulnerabilities (indexer). "
        "For alerts or vulnerabilities start with alerts_summary / vulnerabilities_summary, "
        "then drill down. Agent IDs are 3-digit strings like '001'; '000' is the manager. "
        "Nothing here can change Wazuh."
    ),
)
RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


@mcp.tool(annotations=RO)
@safe
async def manager_info() -> str:
    """Wazuh manager version, install info and status of its daemons."""
    info = await run("/manager/info")
    status = await run("/manager/status")
    return json.dumps({"info": json.loads(info), "daemons": json.loads(status)}, indent=1)


@mcp.tool(annotations=RO)
@safe
async def agents_summary() -> str:
    """Count of agents by connection status (active, disconnected, never_connected, pending)."""
    return await run("/agents/summary/status")


@mcp.tool(annotations=RO)
@safe
async def list_agents(status: str | None = None, search: str | None = None, limit: int = 100) -> str:
    """List agents with key fields.

    Args:
        status: optional filter - active, disconnected, never_connected or pending.
        search: optional free-text search (name, IP, OS ...).
        limit: max agents to return (1-500).
    """
    return await run(
        "/agents",
        {
            "status": status,
            "search": search,
            "limit": clamp(limit),
            "select": "id,name,ip,status,os.name,os.version,version,group,lastKeepAlive,dateAdd",
        },
    )


@mcp.tool(annotations=RO)
@safe
async def get_agent(agent_id: str) -> str:
    """Full details for one agent (OS, version, groups, last keep-alive, config sync ...)."""
    return await run("/agents", {"agents_list": agent_id_ok(agent_id)})


@mcp.tool(annotations=RO)
@safe
async def list_groups() -> str:
    """Agent groups and how many agents are in each."""
    return await run("/groups")


@mcp.tool(annotations=RO)
@safe
async def agent_os_hardware(agent_id: str) -> str:
    """Operating system and hardware inventory (syscollector) of an agent."""
    aid = agent_id_ok(agent_id)
    os_info = json.loads(await run(f"/syscollector/{aid}/os"))
    hw = json.loads(await run(f"/syscollector/{aid}/hardware"))
    return json.dumps({"os": os_info, "hardware": hw}, indent=1)


@mcp.tool(annotations=RO)
@safe
async def agent_packages(agent_id: str, search: str | None = None, limit: int = 100) -> str:
    """Installed packages on an agent (syscollector). Use `search` to look for a product, e.g. 'openssl'."""
    return await run(
        f"/syscollector/{agent_id_ok(agent_id)}/packages",
        {"search": search, "limit": clamp(limit), "select": "name,version,vendor,architecture,format"},
    )


@mcp.tool(annotations=RO)
@safe
async def agent_open_ports(agent_id: str, limit: int = 200) -> str:
    """Listening / open network ports on an agent, with the owning process when known."""
    return await run(f"/syscollector/{agent_id_ok(agent_id)}/ports", {"limit": clamp(limit)})


@mcp.tool(annotations=RO)
@safe
async def agent_processes(agent_id: str, search: str | None = None, limit: int = 100) -> str:
    """Running processes on an agent (last syscollector scan). `search` filters by name/cmd."""
    return await run(
        f"/syscollector/{agent_id_ok(agent_id)}/processes",
        {"search": search, "limit": clamp(limit), "select": "pid,ppid,name,cmd,euser,state,start_time"},
    )


@mcp.tool(annotations=RO)
@safe
async def agent_fim_files(agent_id: str, search: str | None = None, limit: int = 100) -> str:
    """File Integrity Monitoring (syscheck) database for an agent: monitored files with hashes,
    owner, permissions and last change time. `search` filters by path."""
    return await run(f"/syscheck/{agent_id_ok(agent_id)}", {"search": search, "limit": clamp(limit)})


@mcp.tool(annotations=RO)
@safe
async def agent_sca_policies(agent_id: str) -> str:
    """Security Configuration Assessment (CIS-style) policies for an agent with pass/fail score."""
    return await run(f"/sca/{agent_id_ok(agent_id)}")


@mcp.tool(annotations=RO)
@safe
async def agent_sca_failed_checks(agent_id: str, policy_id: str, limit: int = 50) -> str:
    """Failed SCA checks for one policy (get policy_id from agent_sca_policies), incl. rationale and remediation."""
    if not re.match(r"^[A-Za-z0-9_.-]+$", policy_id):
        return json.dumps({"error": f"Invalid policy id: {policy_id!r}"})
    return await run(
        f"/sca/{agent_id_ok(agent_id)}/checks/{policy_id}",
        {"result": "failed", "limit": clamp(limit)},
    )


@mcp.tool(annotations=RO)
@safe
async def search_rules(
    search: str | None = None, level: str | None = None, group: str | None = None, limit: int = 50
) -> str:
    """Search Wazuh detection rules.

    Args:
        search: free text, e.g. 'ssh', 'brute force', 'sudo'.
        level: a level or range, e.g. '10' or '10-15'.
        group: rule group, e.g. 'authentication_failed', 'syscheck', 'web'.
        limit: max rules (1-500).
    """
    return await run(
        "/rules",
        {
            "search": search,
            "level": level,
            "group": group,
            "limit": clamp(limit),
            "select": "id,level,description,groups,mitre,filename",
        },
    )


@mcp.tool(annotations=RO)
@safe
async def get_rule(rule_id: int) -> str:
    """Full definition of one rule by ID (e.g. 5710), including MITRE mapping and compliance tags."""
    return await run("/rules", {"rule_ids": int(rule_id)})


@mcp.tool(annotations=RO)
@safe
async def manager_logs(level: str | None = None, search: str | None = None, limit: int = 50) -> str:
    """Recent ossec.log entries of the manager. level: error, warning, info or debug."""
    return await run(
        "/manager/logs", {"level": level, "search": search, "limit": clamp(limit), "sort": "-timestamp"}
    )


@mcp.tool(annotations=RO)
@safe
async def search_alerts(
    since: str = "24h",
    min_level: int | None = None,
    agent_id: str | None = None,
    rule_id: str | None = None,
    rule_group: str | None = None,
    query: str | None = None,
    limit: int = 50,
) -> str:
    """Search Wazuh alerts (newest first) in the indexer.

    Args:
        since: time window, e.g. '30m', '24h', '7d', '2w'.
        min_level: only alerts with rule.level >= this (0-15; 7+ is noteworthy, 12+ is high).
        agent_id: only this agent, e.g. '001' ('000' is the manager).
        rule_id: only this rule, e.g. '5710'.
        rule_group: only this rule group, e.g. 'authentication_failed', 'syscheck', 'sca'.
        query: free text over the alert (full_log, rule description, ...), e.g. 'sshd failed'.
        limit: max alerts (1-500).
    """
    filters: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": since_ok(since)}}}]
    if min_level is not None:
        filters.append({"range": {"rule.level": {"gte": max(0, min(int(min_level), 15))}}})
    if agent_id:
        filters.append({"term": {"agent.id": agent_id_ok(agent_id)}})
    if rule_id:
        if not str(rule_id).strip().isdigit():
            raise WazuhAPIError(f"Invalid rule id: {rule_id!r}")
        filters.append({"term": {"rule.id": str(rule_id).strip()}})
    if rule_group:
        if not _RULE_GROUP_RE.match(rule_group):
            raise WazuhAPIError(f"Invalid rule group: {rule_group!r}")
        filters.append({"term": {"rule.groups": rule_group}})
    must: list[dict[str, Any]] = []
    if query:
        must.append({"simple_query_string": {"query": query[:200], "default_operator": "and"}})
    body = {
        "size": clamp(limit),
        "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must": must}},
        "_source": [
            "timestamp", "agent.id", "agent.name", "agent.ip",
            "rule.id", "rule.level", "rule.description", "rule.groups", "rule.firedtimes",
            "rule.mitre.id", "rule.mitre.technique", "location", "decoder.name",
            "data.srcip", "data.srcuser", "data.dstuser", "data.win.system.eventID",
            "syscheck.path", "syscheck.event", "full_log",
        ],
    }
    resp = await isearch(ALERTS_INDEX, body)
    found = hits(resp, max_text=800)
    return json.dumps(
        {"total": total(resp), "returned": len(found), "items": found}, indent=1, ensure_ascii=False
    )


@mcp.tool(annotations=RO)
@safe
async def alerts_summary(since: str = "24h", min_level: int | None = None, agent_id: str | None = None) -> str:
    """Overview of alerts in a time window: counts by level, top rules, agents, groups,
    MITRE techniques and source IPs. Good first call before search_alerts.

    Args:
        since: time window, e.g. '30m', '24h', '7d', '2w'.
        min_level: only alerts with rule.level >= this.
        agent_id: only this agent, e.g. '001'.
    """
    filters: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": since_ok(since)}}}]
    if min_level is not None:
        filters.append({"range": {"rule.level": {"gte": max(0, min(int(min_level), 15))}}})
    if agent_id:
        filters.append({"term": {"agent.id": agent_id_ok(agent_id)}})
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 16, "order": {"_key": "desc"}}},
            "top_rules": {
                "terms": {"field": "rule.id", "size": 15},
                "aggs": {
                    "description": {"terms": {"field": "rule.description", "size": 1}},
                    "level": {"max": {"field": "rule.level"}},
                },
            },
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_group": {"terms": {"field": "rule.groups", "size": 15}},
            "mitre": {"terms": {"field": "rule.mitre.technique", "size": 10}},
            "src_ips": {"terms": {"field": "data.srcip", "size": 10}},
        },
    }
    resp = await isearch(ALERTS_INDEX, body)
    rules = [
        {
            "rule_id": b.get("key"),
            "count": b.get("doc_count"),
            "level": (b.get("level") or {}).get("value"),
            "description": next(iter(b.get("description", {}).get("buckets", [])), {}).get("key"),
        }
        for b in resp.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
    ]
    return json.dumps(
        {
            "window": f"last {since}",
            "total_alerts": total(resp),
            "by_level": buckets(resp, "by_level"),
            "top_rules": rules,
            "by_agent": buckets(resp, "by_agent"),
            "by_group": buckets(resp, "by_group"),
            "mitre_techniques": buckets(resp, "mitre"),
            "top_src_ips": buckets(resp, "src_ips"),
        },
        indent=1,
        ensure_ascii=False,
    )


@mcp.tool(annotations=RO)
@safe
async def get_alert(alert_id: str) -> str:
    """Full alert document by its _id (from search_alerts), including all decoded data fields."""
    if not re.match(r"^[A-Za-z0-9_-]{1,64}$", alert_id):
        raise WazuhAPIError(f"Invalid alert id: {alert_id!r}")
    resp = await isearch(ALERTS_INDEX, {"size": 1, "query": {"ids": {"values": [alert_id]}}})
    found = hits(resp, max_text=5000)
    if not found:
        return json.dumps({"error": f"Alert {alert_id} not found"})
    return json.dumps(found[0], indent=1, ensure_ascii=False)


def _vuln_filters(agent_id: str | None, severity: str | None, search: str | None) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = []
    if agent_id:
        filters.append({"term": {"agent.id": agent_id_ok(agent_id)}})
    if severity:
        sev = severity.strip().lower()
        if sev not in _SEVERITIES:
            raise WazuhAPIError(f"Invalid severity: {severity!r} (critical, high, medium or low)")
        filters.append({"terms": {"vulnerability.severity": [sev.capitalize(), sev.upper(), sev]}})
    if search:
        term = search.strip()
        if _CVE_RE.match(term):
            filters.append({"term": {"vulnerability.id": term.upper()}})
        else:
            if not re.match(r"^[\w .+:@/-]{1,100}$", term):
                raise WazuhAPIError(f"Invalid search: {search!r}")
            filters.append(
                {"wildcard": {"package.name": {"value": f"*{term}*", "case_insensitive": True}}}
            )
    return filters


@mcp.tool(annotations=RO)
@safe
async def list_vulnerabilities(
    agent_id: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    with_description: bool = False,
    limit: int = 50,
) -> str:
    """Current vulnerabilities detected on agents (Wazuh vulnerability detector state), highest
    CVSS score first.

    Args:
        agent_id: only this agent, e.g. '001'.
        severity: critical, high, medium or low.
        search: a CVE id (e.g. 'CVE-2024-3094') or part of a package name (e.g. 'chrome').
        with_description: include the CVE description text.
        limit: max results (1-500).
    """
    source = [
        "agent.id", "agent.name", "package.name", "package.version", "package.type",
        "vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
        "vulnerability.detected_at", "vulnerability.published_at", "vulnerability.reference",
        "vulnerability.under_evaluation",
    ]
    if with_description:
        source.append("vulnerability.description")
    body = {
        "size": clamp(limit),
        "track_total_hits": True,
        "sort": [
            {"vulnerability.score.base": {"order": "desc", "missing": "_last", "unmapped_type": "float"}},
            {"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}},
        ],
        "query": {"bool": {"filter": _vuln_filters(agent_id, severity, search)}},
        "_source": source,
    }
    resp = await isearch(VULNS_INDEX, body)
    found = hits(resp, max_text=600)
    return json.dumps(
        {"total": total(resp), "returned": len(found), "items": found}, indent=1, ensure_ascii=False
    )


@mcp.tool(annotations=RO)
@safe
async def vulnerabilities_summary(agent_id: str | None = None, severity: str | None = None) -> str:
    """Overview of current vulnerabilities: counts by severity, by agent, most affected packages
    and most widespread CVEs. Good first call before list_vulnerabilities.

    Args:
        agent_id: only this agent, e.g. '001'.
        severity: critical, high, medium or low.
    """
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": _vuln_filters(agent_id, severity, None)}},
        "aggs": {
            "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "top_packages": {"terms": {"field": "package.name", "size": 15}},
            "top_cves": {"terms": {"field": "vulnerability.id", "size": 15}},
        },
    }
    resp = await isearch(VULNS_INDEX, body)
    return json.dumps(
        {
            "total_vulnerabilities": total(resp),
            "by_severity": buckets(resp, "by_severity"),
            "by_agent": buckets(resp, "by_agent"),
            "top_packages": buckets(resp, "top_packages"),
            "top_cves": buckets(resp, "top_cves"),
        },
        indent=1,
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def _check() -> int:
    print(f"Connecting to {API_URL} as {API_USER or '(not set)'} (verify SSL: {VERIFY}) ...")
    try:
        info = await api.get("/manager/info")
        aff = info["data"]["affected_items"][0]
        print(f"OK - Wazuh {aff.get('version')} on {aff.get('path')}")
        summary = await api.get("/agents/summary/status")
        print("Agents:", json.dumps(summary.get("data", {}).get("connection", summary.get("data")), default=str))
        rc = 0
    except Exception as exc:  # noqa: BLE001 - CLI diagnostics
        print(f"FAILED - {exc}")
        rc = 1

    if not INDEXER_USER:
        print("Indexer: not configured (INDEXER_USER empty) - alert/vulnerability tools disabled")
        return rc
    print(f"Connecting to indexer {INDEXER_URL} as {INDEXER_USER} (verify SSL: {INDEXER_VERIFY}) ...")
    for name, index in (("alerts", ALERTS_INDEX), ("vulnerabilities", VULNS_INDEX)):
        try:
            resp = await indexer.search(index, {"size": 0, "track_total_hits": True})
            print(f"OK - {index}: {total(resp)} {name}")
        except Exception as exc:  # noqa: BLE001 - CLI diagnostics
            print(f"FAILED - {index}: {exc}")
            rc = 1
    return rc


def main() -> None:
    if "--check" in sys.argv:
        sys.exit(asyncio.run(_check()))
    if not API_USER or not API_PASSWORD:
        log.error("WAZUH_API_USER / WAZUH_API_PASSWORD missing - create .env from .env.example")
    log.info("Starting Wazuh MCP server (stdio) -> %s", API_URL)
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
