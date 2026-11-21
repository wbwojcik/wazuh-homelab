#!/usr/bin/env python3
"""
Daily critical-vulnerability email for a Wazuh homelab.

Runs on the Wazuh server (root cron). Reads the vulnerability state index on the local
indexer with the admin certificate (read-only search), remembers what it already reported,
and emails one short, grouped summary through the local mail relay (e.g. postfix -> Gmail -> your inbox):

  * per laptop, which programs to update, whether a patch exists (fixed version from NVD),
    and how to update;
  * what is new since the last email, and what got fixed.

It only sends when something changed (new or fixed criticals), unless DIGEST_ALWAYS=1.

  wazuh-vuln-digest.py            -> send the email (and save state)
  wazuh-vuln-digest.py --dry-run  -> print it instead (nothing is marked as reported)

Environment: DIGEST_FROM, DIGEST_TO (required to send), DIGEST_ALWAYS=1, DIGEST_TZ
(default UTC), NVD_MAX_LOOKUPS (default 0 = off; e.g. 150 to show fixed versions from
NVD - it allows ~5 requests / 30 s without an API key, so the first run then takes ~15 minutes).
--dry-run keeps the NVD answers it fetched, but does not mark anything as reported.
"""

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr

INDEXER = "https://127.0.0.1:9200/wazuh-states-vulnerabilities-*/_search"
CERT = "/etc/wazuh-indexer/certs/admin.pem"
KEY = "/etc/wazuh-indexer/certs/admin-key.pem"
STATE = os.environ.get("DIGEST_STATE", "/var/lib/wazuh-vuln-digest/state.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
AGENT_CONTROL = "/var/ossec/bin/agent_control"
MAIL_FROM = os.environ.get("DIGEST_FROM", "")
MAIL_TO = os.environ.get("DIGEST_TO", "")
ALWAYS = os.environ.get("DIGEST_ALWAYS") == "1"
TZ = os.environ.get("DIGEST_TZ", "UTC")
NVD_MAX = int(os.environ.get("NVD_MAX_LOOKUPS", "0"))  # 0 = no NVD patch lookup
NVD_RECHECK_DAYS = 7  # re-ask NVD about CVEs that had no fixed version yet


# --- indexer -----------------------------------------------------------------------------

def search(body):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # local self-signed indexer cert
    ctx.load_cert_chain(CERT, KEY)
    req = urllib.request.Request(
        INDEXER, data=json.dumps(body).encode(), method="GET",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        return json.load(resp)


def open_criticals():
    body = {
        "size": 5000,
        "query": {"bool": {"filter": [
            {"terms": {"vulnerability.severity": ["Critical", "CRITICAL", "critical"]}}]}},
        "_source": ["agent.name", "agent.id", "package.name", "package.version",
                    "vulnerability.id", "vulnerability.score.base", "host.os.platform",
                    "host.os.name", "host.os.type"],
    }
    rows = []
    for h in search(body)["hits"]["hits"]:
        s = h["_source"]
        a, p, v = s.get("agent", {}), s.get("package", {}), s.get("vulnerability", {})
        os_ = (s.get("host") or {}).get("os") or {}
        rows.append({
            "agent": a.get("name", "?"), "agent_id": a.get("id", "?"),
            "pkg": p.get("name", "?"), "ver": str(p.get("version", "")),
            "cve": v.get("id", "?"), "score": (v.get("score") or {}).get("base") or 0,
            "os": " ".join(str(os_.get(k, "")) for k in ("platform", "name", "type")).lower(),
        })
    return rows


def key(r):
    return f"{r['agent']}|{r['cve']}|{r['pkg']}|{r['ver']}"


# --- agent status --------------------------------------------------------------------------

def agent_status():
    """{'LAPTOP-2': 'Disconnected', ...} from agent_control; empty if unavailable."""
    try:
        out = subprocess.run([AGENT_CONTROL, "-l"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    status = {}
    for m in re.finditer(r"ID:\s*\d+,\s*Name:\s*([^,]+),.*?,\s*([A-Za-z ]+?)\s*$", out, re.M):
        status[m.group(1).strip()] = m.group(2).strip()
    return status


# --- versions and NVD fix lookup ----------------------------------------------------------

def vkey(v):
    """Comparable version key: '151.0.3' < '151.0.10' < '152'."""
    parts = re.findall(r"\d+|[a-zA-Z]+", str(v))
    return [(0, int(p)) if p.isdigit() else (-1, p.lower()) for p in parts]


def vless(a, b):
    ka, kb = vkey(a), vkey(b)
    n = max(len(ka), len(kb))
    ka += [(0, 0)] * (n - len(ka))
    kb += [(0, 0)] * (n - len(kb))
    return ka < kb


def nvd_ranges(cve):
    """Vulnerable CPE ranges for a CVE from NVD: [{'product','start','start_ex','end','end_in','exact'}]."""
    req = urllib.request.Request(NVD + urllib.parse.quote(cve), headers={"User-Agent": "wazuh-vuln-digest"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    ranges = []
    for item in data.get("vulnerabilities", []):
        for conf in item.get("cve", {}).get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    parts = m.get("criteria", "").split(":")
                    if len(parts) < 6:
                        continue
                    ranges.append({
                        "product": parts[4].replace("_", " ").lower(),
                        "vendor": parts[3].replace("_", " ").lower(),
                        "exact": parts[5] if parts[5] not in ("*", "-") else "",
                        "start": m.get("versionStartIncluding", ""),
                        "start_ex": m.get("versionStartExcluding", ""),
                        "end": m.get("versionEndExcluding", ""),
                        "end_in": m.get("versionEndIncluding", ""),
                    })
    return ranges


def product_matches(product, pkg):
    """NVD product 'firefox' / 'windows_11_23h2' vs Wazuh package 'Mozilla Firefox (x64 pl)'."""
    name = pkg.lower()
    if not product:
        return False
    if product in name:
        return True
    words = [w for w in re.findall(r"[a-z][a-z0-9+.-]*", product) if len(w) > 2 and not re.search(r"\d", w)]
    return bool(words) and all(re.search(r"\b" + re.escape(w) + r"\b", name) for w in words)


def fix_for(ranges, pkg, ver):
    """
    Fixed version for this installed package according to NVD ranges:
      ('fixed', '151.0.4')   patch exists, update to this version or newer
      ('newer', '151.0.3')   all versions up to X are affected; a newer one exists
      ('none', '')           NVD lists it as affected with no fixed version yet
      ('unknown', '')        NVD has no usable data
    """
    mine = [r for r in ranges if product_matches(r["product"], pkg)]
    best = None
    for r in mine:
        if r["exact"]:
            continue
        if r["start"] and vless(ver, r["start"]):
            continue
        if r["start_ex"] and not vless(r["start_ex"], ver):
            continue
        if r["end"]:
            if vless(ver, r["end"]):
                cand = ("fixed", r["end"])
            else:
                continue
        elif r["end_in"]:
            if not vless(r["end_in"], ver):
                cand = ("newer", r["end_in"])
            else:
                continue
        else:
            cand = ("none", "")
        if best is None or cand[0] == "none" or (best[0] != "none" and vless(best[1], cand[1])):
            best = cand
    return best or ("unknown", "")


def lookup_fixes(rows, state):
    """Fill state['nvd'][cve] for as many CVEs as the budget allows, most severe packages first."""
    cache = state.setdefault("nvd", {})
    today = datetime.now(timezone.utc).date()

    def stale(cve):
        c = cache.get(cve)
        if not c:
            return True
        if c.get("ranges"):
            return False
        return (today - datetime.fromisoformat(c["checked"]).date()).days >= NVD_RECHECK_DAYS

    # Round-robin over packages so each one gets its highest-scored CVEs checked first.
    per_pkg = defaultdict(list)
    for r in sorted(rows, key=lambda r: -float(r["score"] or 0)):
        if r["cve"] not in per_pkg[(r["pkg"], r["ver"])]:
            per_pkg[(r["pkg"], r["ver"])].append(r["cve"])
    order, seen = [], set()
    while any(per_pkg.values()):
        for k in list(per_pkg):
            if per_pkg[k]:
                cve = per_pkg[k].pop(0)
                if cve not in seen:
                    seen.add(cve)
                    order.append(cve)
    todo = [c for c in order if stale(c)][:NVD_MAX]
    if todo:
        print(f"Asking NVD about {len(todo)} CVEs (about {len(todo) * 7 // 60 + 1} min)...", file=sys.stderr)
    for i, cve in enumerate(todo):
        if i:
            time.sleep(6.5)
        try:
            cache[cve] = {"ranges": nvd_ranges(cve), "checked": today.isoformat()}
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"NVD lookup failed for {cve}: {e}", file=sys.stderr)
            break
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{len(todo)} done", file=sys.stderr)
            save_state(state)  # keep progress if interrupted ("seen" is untouched)
    return sum(1 for c in order if stale(c))  # still unchecked


def package_fix(cves, pkg, ver, cache):
    """Combine per-CVE results: the highest fixed version wins; any 'none' means no full patch."""
    results = [fix_for(cache[c]["ranges"], pkg, ver) for c in cves if c in cache]
    known = [r for r in results if r[0] != "unknown"]
    if not known:
        return ("unknown", "", len(results), len(cves))
    if any(r[0] == "none" for r in known):
        fixed = [r for r in known if r[0] != "none"]
        return ("partial" if fixed else "none", max((r[1] for r in fixed), key=vkey, default=""),
                len(results), len(cves))
    kind = "fixed" if all(r[0] == "fixed" for r in known) else "newer"
    return (kind, max((r[1] for r in known), key=vkey), len(results), len(cves))


# --- how to update -----------------------------------------------------------------------

HOWTO = [
    (r"firefox", "Firefox menu > Help > About Firefox (updates itself)"),
    (r"thunderbird", "Thunderbird menu > Help > About Thunderbird"),
    (r"google chrome|^chrome", "Chrome menu > Help > About Google Chrome"),
    (r"microsoft edge", "Edge > Settings > About Microsoft Edge"),
    (r"^microsoft windows|^windows 1\d", "Settings > Windows Update > Check for updates"),
    (r"office|microsoft 365|word|excel|outlook", "Open Word > File > Account > Update Options > Update Now"),
    (r"7-zip", "Download the latest 7-Zip from 7-zip.org and install over it"),
    (r"vlc", "VLC > Help > Check for Updates"),
    (r"zoom", "Zoom > profile picture > Check for Updates"),
    (r"python", "Install the latest Python from python.org (or remove old versions you don't use)"),
    (r"java|jre|jdk", "Update Java, or uninstall it if you don't need it"),
]


def howto(pkg, os_):
    name = pkg.lower()
    for pattern, text in HOWTO:
        if re.search(pattern, name):
            return text
    if any(x in os_ for x in ("ubuntu", "debian")):
        return "sudo apt update && sudo apt upgrade"
    if "windows" in os_ or not os_.strip():
        return "PowerShell: winget upgrade --all  (or update it from the program's own menu)"
    return "Install the latest version from the vendor"


def fix_text(fix, ver):
    kind, version, checked, total = fix
    if kind == "fixed":
        return f"Patch available: update to {version} or newer (you have {ver})."
    if kind == "newer":
        return f"Patch available: versions up to {version} are affected, so update to the latest (you have {ver})."
    if kind == "partial":
        return (f"Patch available: {version} or newer fixes most; a few have no fix listed yet "
                f"(you have {ver}).")
    if kind == "none":
        return "No patch listed yet. Update when one comes out, or remove it if you don't need it."
    if checked:
        return f"Patch info not published yet. Update to the latest version (you have {ver})."
    if NVD_MAX == 0:
        return f"Update to the latest version (you have {ver})."
    return f"Patch info: still checking. Update to the latest version (you have {ver})."


# --- the email ---------------------------------------------------------------------------

def local_now():
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(TZ))
    except Exception:
        return datetime.now()


def build(rows, state, status, first_run):
    seen = state.get("seen", {})
    current = {key(r): r for r in rows}
    new_keys = set(current) - set(seen)
    fixed_keys = set(seen) - set(current)
    cache = state.get("nvd", {})

    # agent -> (pkg, ver) -> list of rows
    tree = defaultdict(lambda: defaultdict(list))
    for r in rows:
        tree[r["agent"]][(r["pkg"], r["ver"])].append(r)

    new_by_agent = defaultdict(int)
    for k in new_keys:
        new_by_agent[current[k]["agent"]] += 1
    n_new, n_fixed = len(new_keys), len(fixed_keys)

    if first_run:
        subject = f"Wazuh Alert - Vulnerabilities: {len(rows)} critical to fix on " + ", ".join(sorted(tree))
    elif n_new:
        subject = (f"Wazuh Alert - {n_new} new critical vulnerabilit{'y' if n_new == 1 else 'ies'} on "
                   + ", ".join(sorted(new_by_agent)))
    elif n_fixed:
        subject = f"Wazuh Alert - {n_fixed} critical vulnerabilit{'y' if n_fixed == 1 else 'ies'} fixed"
    else:
        subject = "Wazuh Alert - Vulnerabilities: nothing new"

    now = local_now()
    out = [f"CRITICAL VULNERABILITIES - {now.day} {now:%b %Y}", ""]
    if first_run:
        out += ["This is the starting list. From tomorrow you only get an email when something",
                "new shows up or gets fixed.", ""]
    else:
        out += [f"New since last email: {n_new}    Fixed since last email: {n_fixed}", ""]

    out += ["WHAT TO DO", ""]
    def offline(a):
        return bool(status.get(a)) and status[a].lower() != "active"

    for agent in sorted(tree, key=lambda a: (offline(a), -sum(len(v) for v in tree[a].values()))):
        pkgs = tree[agent]
        total = sum(len(v) for v in pkgs.values())
        st = status.get(agent, "")
        note = ""
        if offline(agent):
            note = f" - {st.upper()}: list is from when it was last on"
        out.append(f"{agent} - {total} critical in {len(pkgs)} program{'s' if len(pkgs) != 1 else ''}{note}")
        ranked = sorted(pkgs.items(), key=lambda kv: (-len(kv[1]), -max(float(r['score'] or 0) for r in kv[1])))
        for i, ((pkg, ver), items) in enumerate(ranked, 1):
            cves = sorted({r["cve"] for r in items})
            new_here = sum(1 for r in items if key(r) in new_keys)
            top = max(float(r["score"] or 0) for r in items)
            fix = package_fix(cves, pkg, ver, cache)
            tag = f", {new_here} new" if new_here and not first_run else ""
            out.append(f"  {i}. Update {pkg} - {len(cves)} critical{tag}, worst CVSS {top:g}")
            out.append(f"     {fix_text(fix, ver)}")
            out.append(f"     How: {howto(pkg, items[0]['os'])}")
        out.append("")

    if fixed_keys:
        out += ["FIXED SINCE LAST EMAIL"]
        gone = defaultdict(set)
        for k in fixed_keys:
            agent, cve, pkg, ver = k.split("|", 3)
            gone[(agent, pkg, ver)].add(cve)
        for (agent, pkg, ver), cves in sorted(gone.items()):
            out.append(f"  {agent}: {pkg} {ver} - {len(cves)} gone")
        out.append("")

    out += ["", "-" * 60, "TECHNICAL DETAILS (CVE list)", "-" * 60]
    for agent in sorted(tree):
        out.append(f"{agent} (agent {next(iter(tree[agent].values()))[0]['agent_id']})")
        for (pkg, ver), items in sorted(tree[agent].items()):
            out.append(f"  {pkg} {ver}")
            for r in sorted(items, key=lambda r: (-float(r['score'] or 0), r['cve'])):
                mark = "  NEW" if key(r) in new_keys and not first_run else ""
                out.append(f"    {r['cve']:<17} CVSS {float(r['score'] or 0):<4g}{mark}".rstrip())
        out.append("")
    out.append("Vulnerability data from Wazuh" + (", patch info from NVD (nvd.nist.gov)." if NVD_MAX else "."))
    changed = first_run or n_new or n_fixed
    return subject, "\n".join(out) + "\n", changed, current


# --- main --------------------------------------------------------------------------------

def load_state():
    try:
        with open(STATE) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {}
    return state, "seen" not in state


def save_state(state):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


def main():
    dry = "--dry-run" in sys.argv
    state, first_run = load_state()
    rows = open_criticals()
    lookup_fixes(rows, state)
    subject, text, changed, current = build(rows, state, agent_status(), first_run)
    if dry:
        save_state(state)  # NVD answers only; "seen" is untouched
        print("Subject:", subject)
        print("(would send)" if changed or ALWAYS else "(nothing changed - would not send)")
        print()
        print(text)
        return
    if changed or ALWAYS:
        if not MAIL_FROM or not MAIL_TO:
            sys.exit("DIGEST_FROM / DIGEST_TO not set")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = formataddr(("Wazuh Alert", MAIL_FROM))
        msg["To"] = MAIL_TO
        msg.set_content(text)
        subprocess.run(["/usr/sbin/sendmail", "-t", "-oi", "-f", MAIL_FROM], input=msg.as_bytes(), check=True)
        print("SENT:", subject)
    else:
        print("Nothing new - no email.")
    today = datetime.now(timezone.utc).date().isoformat()
    state["seen"] = {k: state.get("seen", {}).get(k, today) for k in current}
    save_state(state)


if __name__ == "__main__":
    main()
