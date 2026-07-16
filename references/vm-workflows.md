# Tenable VM — MCP Workflows

Exact call sequences for discovering and extracting info-plugin data using the
connected Tenable VM (Tenable.io) MCP tools. The relevant tool prefixes are
`plugins_*`, `workbenches_*`, and `scan_*`.

## A. Discover the plugin

```
plugins_search_plugins(query="process information")   # keyword search
plugins_get_plugin_details(plugin_id=70329)           # confirm Info + intended use
plugins_list_plugin_families()                         # breadth by family
```

Filter search results to `Severity: Info`. `plugins_get_plugin_details` returns the
family, type (`local`=credentialed), synopsis, and description.

## B. Extract the plugin output

The **plugin output text is the product** — it is the running-process tree, the
software list, the recycle-bin paths. Everything else (asset IDs, counts, severity)
is just how you locate it. Your job in this step is to get that output text, ideally
complete and untruncated, for the host(s) the user asked about.

### Which tool returns the actual output text

Only one workbench tool returns the rendered plugin output text:

```
workbenches_get_vulnerability_outputs(plugin_id=70329)   # THE output text, grouped by host
```

It returns each affected host (hostname, asset ID, IPv4/6, first/last seen) followed
by that host's plugin output. Optional `age` limits to findings seen within N days —
use it for freshness. This is the workhorse for reading info-plugin output.

The other two are **metadata only — they do NOT contain the output text**, so don't
reach for them expecting the process list or software list:

```
workbenches_get_vulnerability_details(plugin_id=70329)        # synopsis, counts — no output text
workbenches_get_asset_vulnerability_details(asset_id, plugin_id=70329)  # severity, count — no output text
```

(Observed: `get_asset_vulnerability_details` returns `Count: 1` and severity, but no
`pluginText`. Use it to confirm a host *has* the plugin, not to read what it found.)

### ⚠️ The single-host limitation (observed, important)

The MCP tools cannot reliably return **one specific host's** info-plugin output. This
is a hard limitation confirmed in testing, not a tuning issue — plan around it:

- `workbenches_get_vulnerability_outputs` **groups hosts by identical output value**
  and returns only the **first ~10 groups**, with **no host filter and no paging**.
  It also **truncates** each group's output block when the plugin is widespread (you
  see `... (truncated)` and `... and N more outputs`). So a target host is retrievable
  only if it happens to land in the first ~10 groups; otherwise it sits in the
  unreturned `... and N more outputs` and you cannot reach it. An `age` filter changes
  the grouping slightly but does not reliably surface a chosen host.
- `workbenches_get_asset_vulnerabilities` / `..._vulnerability_details` return
  metadata only (severity, `Count`) — **never the output text**.
- The export fallback is also unreliable through the connector: `export_workbenches`
  requires a `chapter` (use `vuln_by_plugin` for CSV; `vuln_by_host` is rejected for
  CSV) and builds fine, but **`download_export` has been observed to return HTTP 406**,
  so you may not get the file back.

Practical rule: use `get_vulnerability_outputs` for a **quick look, environment-wide
mining, or to locate/enumerate hosts** — it is good at "which hosts logged on as X"
or "show me recycle-bin findings across the estate." Do **not** promise a specific
host's full output from the MCP tools alone. If the target host isn't in the returned
groups, say so plainly and switch to the direct-API path below rather than guessing.

### Getting one host's full output — pyTenable / direct API (recommended)

The skill bundles this as a runnable script: **`scripts/pull_plugin_output.py`**.
Prefer offering/running it over pasting ad-hoc code — it handles auth, host filtering,
grouping, and CSV/JSON output. See "Completing a capped pull" in SKILL.md for how to
offer it (run here with user-provided keys, or give them the commands to run locally).

The script tries **pyTenable** first and falls back to a **dependency-free REST call
over `urllib`** when pyTenable isn't installed — so it runs even in locked-down
environments where `pip install` can't reach PyPI (only outbound HTTPS to Tenable.io
is required). This fallback was verified in a sandbox where PyPI was blocked but
`cloud.tenable.com` was reachable.

Under the hood the REST endpoint it calls is
`GET /workbenches/vulnerabilities/{plugin_id}/outputs` (with `X-ApiKeys` auth), which
filters server-side by host and returns the full `plugin_output`. The pyTenable
equivalent:

```python
from tenable.io import TenableIO

tio = TenableIO(access_key='ACCESS_KEY', secret_key='SECRET_KEY')

# Full output of ONE plugin on ONE host (e.g. Last Logged On User = 38689 on 192.168.1.96)
for out in tio.workbenches.vuln_outputs(
        38689,
        filters=[('host.target', 'eq', '192.168.1.96')]):
    for host in out['states'][0]['results']:
        print(host['hostname'])
        print(out['plugin_output'])     # the full, untruncated output text
```

Equivalent REST call (when the user wants curl):

```
GET /workbenches/vulnerabilities/{plugin_id}/outputs?filter.0.filter=host.target&filter.0.quality=eq&filter.0.value=<ip>
Header: X-ApiKeys: accessKey=...; secretKey=...
```

The per-asset variant `GET /workbenches/assets/{asset_uuid}/vulnerabilities/{plugin_id}/outputs`
also returns full `plugin_output` for a single asset. Because you cannot run these
from the MCP session, hand the user the filled-in snippet (plugin ID + their host) and
offer to parse whatever they paste or export back.

### Finding a host / listing what's populated

`workbenches_get_vulnerability_outputs` already lists every affected host with its
IPv4, so it doubles as a lookup: pull the plugin's outputs and read off the asset ID
for the IP or hostname you care about. `workbenches_list_vulnerabilities(severity="info")`
lists which info plugins are populated across the environment (capped at 5,000,
<15 months old). Asset-list filters may not always resolve, so prefer locating the
host from the plugin outputs.

## C. Freshness & credential checks

- Confirm the finding is recent: pass `age` on workbench calls, or check the scan
  date via `scan_list_scans` / `scan_history`. Report the scan date in the output.
- Empty output from a `local` plugin almost always means the host was scanned
  **without credentials**. State that as the likely cause instead of reporting the
  host as clean.

## D. Worked example — "What are the running processes on host 192.168.1.96?"

1. `plugins_search_plugins(query="process information")` → confirm **70329** is `Info`
   (`plugins_get_plugin_details(70329)` states it is for forensic/malware use).
2. `workbenches_get_vulnerability_outputs(plugin_id=70329)` → scan the host blocks for
   IPv4 `192.168.1.96`; read off its hostname + asset ID (e.g. `ex-empire-06`).
3. If the host lands in the first ~10 groups, that response gives its **process
   output** — but note it is likely **truncated** (only the boot-chain processes, cut
   at `... (truncated)`). Present it, but say it is partial. If the host is in
   `... and N more outputs`, you **cannot** reach it from this endpoint — say so.
4. For the **complete** process tree (or when the host wasn't returned), use the
   pyTenable single-host path: `tio.workbenches.vuln_outputs(70329, filters=[('host.target','eq','192.168.1.96')])`
   and parse the full `plugin_output`. Don't rely on `export_workbenches` →
   `download_export` — the download has been observed to 406 through the connector.
5. Parse into (SID, process, PID, parent). Flag processes running from `%TEMP%`,
   user-profile, or unsigned paths. **Note the last-seen/scan date** — the process
   list is a point-in-time snapshot, not live.
6. Deliver the process tree (the plugin output) citing plugin 70329 + host + scan
   date. Offer the fuller host profile (add 20811 software, 58452 startup, 171956
   accounts) only if they ask for more than the processes.
