#!/usr/bin/env python3
"""
Pull COMPLETE, untruncated info-plugin output from Tenable VM (Tenable.io).

This is the escape hatch for the MCP limitation: the connector's
workbenches_get_vulnerability_outputs returns only the first ~10 grouped blocks,
truncates long ones, and has no host filter. This script talks to the Tenable.io
API directly and returns the full plugin_output for every matching host.

It works in two modes and picks automatically:
  1. pyTenable, if the `pytenable` package is installed (nicer, handles paging).
  2. A dependency-free REST call over urllib (Python stdlib) if pyTenable is
     missing. This matters in locked-down environments where `pip install` can't
     reach PyPI — the direct REST path only needs outbound HTTPS to Tenable.io,
     which is typically already open. (Confirmed working in exactly such a sandbox.)

Usage:
    # Optional, for mode 1: pip install pytenable
    export TIO_ACCESS_KEY=...      # from Tenable VM > Settings > My Account > API Keys
    export TIO_SECRET_KEY=...
    python pull_plugin_output.py --plugin-id 38689                     # whole environment
    python pull_plugin_output.py --plugin-id 70329 --ip 192.168.1.96   # one host
    python pull_plugin_output.py --plugin-id 38689 --format csv --out logons.csv

Auth: reads TIO_ACCESS_KEY / TIO_SECRET_KEY from the environment. NEVER hard-code
keys in this file — anything written here travels with the skill when it's shared.

Output: readable report to stdout by default; --format csv/json writes a structured
file with one row per host (hostname, ip, asset_id, plugin_output).
"""
import argparse
import csv
import json
import os
import re
import sys

TIO_URL = os.environ.get("TIO_URL", "https://cloud.tenable.com")

# Control chars to strip from untrusted output before printing (keep \t \n \r).
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Leading chars that spreadsheet apps treat as the start of a formula.
_CSV_INJECT_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def require_https_url():
    """Fix #2: never send API keys to a non-HTTPS or unexpected endpoint.

    TIO_URL comes from the environment; if it were http:// or pointed at an
    attacker-controlled host, the X-ApiKeys header would leak the credentials.
    Enforce https and warn if the host isn't a Tenable cloud.
    """
    from urllib.parse import urlparse
    u = urlparse(TIO_URL)
    if u.scheme != "https":
        sys.exit(f"ERROR: TIO_URL must use https:// (got {TIO_URL!r}). Refusing to send API keys.")
    if u.hostname and not u.hostname.lower().endswith("tenable.com"):
        sys.stderr.write(f"WARNING: TIO_URL host {u.hostname!r} is not a *.tenable.com endpoint.\n")


def strip_ctrl(s):
    """Fix #3: remove terminal control sequences from untrusted host output."""
    return _CTRL_RE.sub("", s or "")


def csv_safe(v):
    """Fix #1: neutralize CSV/formula injection from scanned-host data.

    Plugin output comes from remote (possibly compromised) hosts. A value like
    '=cmd|...' would execute as a formula when opened in Excel/Sheets, so prefix
    any risky leading character with a single quote.
    """
    s = "" if v is None else str(v)
    if s and s[0] in _CSV_INJECT_PREFIXES:
        s = "'" + s
    return s


def get_keys():
    ak = os.environ.get("TIO_ACCESS_KEY")
    sk = os.environ.get("TIO_SECRET_KEY")
    if not ak or not sk:
        sys.exit("ERROR: set TIO_ACCESS_KEY and TIO_SECRET_KEY environment variables.")
    return ak, sk


def fetch_pytenable(plugin_id, filters):
    """Mode 1: pyTenable. Returns the raw list of output groups, or None if unavailable."""
    try:
        from tenable.io import TenableIO
    except ImportError:
        return None
    ak, sk = get_keys()
    tio = TenableIO(ak, sk, url=TIO_URL)
    if filters:
        return list(tio.workbenches.vuln_outputs(plugin_id, *filters))
    return list(tio.workbenches.vuln_outputs(plugin_id))


def fetch_rest(plugin_id, filters):
    """Mode 2: dependency-free REST call over urllib (Python stdlib)."""
    import ssl
    import urllib.parse
    import urllib.request
    import urllib.error

    ak, sk = get_keys()
    url = f"{TIO_URL}/workbenches/vulnerabilities/{plugin_id}/outputs"
    # Encode workbench filters as filter.N.filter/quality/value query params.
    params = {}
    for i, (fname, quality, value) in enumerate(filters):
        params[f"filter.{i}.filter"] = fname
        params[f"filter.{i}.quality"] = quality
        params[f"filter.{i}.value"] = value
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "X-ApiKeys": f"accessKey={ak}; secretKey={sk}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=90, context=ssl.create_default_context()) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"ERROR: Tenable.io returned HTTP {e.code}: {e.read()[:300].decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: could not reach {TIO_URL}: {e.reason}")
    return data.get("outputs", [])


def rows_from_outputs(outputs):
    """Flatten output groups into (hostname, ip, asset_id, plugin_output) rows.

    The API groups hosts that share identical output text; each group carries one
    plugin_output plus hosts under states[].results[].assets[]. Parse defensively —
    the shape is consistent between the pyTenable and REST paths.
    """
    rows = []
    for grp in outputs:
        text = (grp.get("plugin_output") or "").rstrip()
        hosts = []
        for state in grp.get("states", []):
            for result in state.get("results", []):
                for asset in result.get("assets", []) or []:
                    hosts.append(asset)
        if not hosts:
            rows.append({"hostname": "", "ip": "", "asset_id": "", "plugin_output": text})
        for a in hosts:
            ipv4 = a.get("ipv4")
            rows.append({
                "hostname": a.get("hostname") or a.get("fqdn") or a.get("name") or "",
                "ip": ",".join(ipv4) if isinstance(ipv4, list) else (ipv4 or ""),
                "asset_id": a.get("id") or a.get("uuid") or "",
                "plugin_output": text,
            })
    return rows


def main():
    p = argparse.ArgumentParser(description="Pull full Tenable info-plugin output.")
    p.add_argument("--plugin-id", type=int, required=True, help="Plugin ID, e.g. 38689")
    p.add_argument("--ip", help="Filter to one host by IP (host.target eq)")
    p.add_argument("--hostname", help="Filter to one host by hostname (host.name eq)")
    p.add_argument("--format", choices=["text", "csv", "json"], default="text")
    p.add_argument("--out", help="Output file path (for csv/json)")
    args = p.parse_args()

    require_https_url()

    filters = []
    if args.ip:
        filters.append(("host.target", "eq", args.ip))
    if args.hostname:
        filters.append(("host.name", "eq", args.hostname))

    # Try pyTenable first; fall back to the stdlib REST call if it isn't installed.
    try:
        outputs = fetch_pytenable(args.plugin_id, filters)
        mode = "pyTenable"
        if outputs is None:
            outputs = fetch_rest(args.plugin_id, filters)
            mode = "REST (stdlib)"
    except Exception as e:
        sys.exit(f"ERROR calling Tenable.io: {e}")
    sys.stderr.write(f"[fetched via {mode}]\n")

    rows = rows_from_outputs(outputs)
    if not rows:
        print("No output returned. Info plugins only populate on CREDENTIALED scans — "
              "check that the host(s) were scanned with valid credentials.")
        return

    if args.format == "text":
        for r in rows:
            header = strip_ctrl(f"=== {r['hostname'] or '(unknown host)'}  {r['ip']}  [{r['asset_id']}] ===")
            print("\n" + header)
            print(strip_ctrl(r["plugin_output"]))
        print(f"\n{len(rows)} host record(s), plugin {args.plugin_id}.")
    elif args.format == "csv":
        out = args.out or f"plugin_{args.plugin_id}_output.csv"
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["hostname", "ip", "asset_id", "plugin_output"])
            w.writeheader()
            for r in rows:
                w.writerow({k: csv_safe(v) for k, v in r.items()})
        print(f"Wrote {len(rows)} rows to {out}")
    else:
        out = args.out or f"plugin_{args.plugin_id}_output.json"
        with open(out, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"Wrote {len(rows)} records to {out}")


if __name__ == "__main__":
    main()
