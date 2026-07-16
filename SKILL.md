---
name: tenable-info-plugins
description: >-
  Discover, extract, and analyze data from Tenable INFO-severity (informational)
  plugins in Tenable Vulnerability Management (Tenable VM / Tenable.io).
  Info plugins are not vulnerabilities — they are rich host-inventory and forensic
  data the scan already collected: running processes, installed software, local/AD
  accounts, services, startup items, network shares, recycle-bin contents,
  AV/firewall status, and patch lists. Use whenever the user wants host inventory,
  an asset profile, a forensic or compliance snapshot, threat-hunting leads from
  scan data, or a report from scan detail — and ANY time they mention info plugins,
  informational plugins, plugin output, a specific info plugin ID (e.g. 70329,
  92429, 20811), recycle bin files, running processes, installed software
  enumeration, enumerate accounts, or "what did the scan find on host X". Trigger
  even without the word "plugin": "profile this server from Tenable", "what
  software is on that box", or "pull forensic data from the last scan" all qualify.
---

# Tenable Info Plugins

## What this skill is for

Tenable scans emit findings at five severities: Critical, High, Medium, Low, and
**Info**. The Critical–Low findings are vulnerabilities. The **Info** findings
(severity id `0`, labeled `Info`) are something different and frequently ignored:
they are the **detailed host telemetry** the scanner gathered along the way.

A credentialed scan of a single Windows host routinely produces dozens of info
plugins covering the machine's entire posture — every running process, every
installed application and hotfix, every local and cached domain account, network
interfaces, shares and their permissions, services and their configs, physical
hardware (CPU, memory, BIOS/model/serial via DMI), AV/EDR and firewall status, and
forensic artifacts like recycle-bin contents. On Linux/Unix and macOS the
equivalents come through SSH and DMI enumeration plugins.

This is a large, mostly-untapped inventory and forensics dataset that is already
sitting in the customer's Tenable deployment. This skill teaches how to **find the
right info plugins for a question, pull their output, parse it, and turn it into an
inventory profile, a forensic snapshot, threat-hunting leads, or a report** — the
same data a responder would otherwise collect by logging into the box.

Info plugins are described by Tenable itself as useful "for forensic
investigation, malware detection, and to confirm that your system processes
conform to your system policies." Lean into exactly those uses.

## The core loop

Every task follows the same four moves. Do them in order.

1. **Discover** — figure out which info plugin(s) hold the answer. Don't rely on
   memory of plugin IDs; discover them dynamically (see below).
2. **Locate** — find the host(s) / finding(s) that carry the plugin, using the
   Tenable VM MCP tools. See `references/vm-workflows.md` for the exact calls.
3. **Extract** — pull the plugin output. This is per-plugin and often per-host.
4. **Parse & deliver** — info-plugin output is semi-structured text, not clean
   JSON. Parse it into structure, then produce the inventory/forensic/report
   deliverable the user asked for.

## Step 1 — Discover plugins dynamically

Do NOT hard-code a mental list of plugin IDs. Plugins are added and renamed
constantly (some in the customer's environment were modified this year), so
discover them at query time and confirm severity is `Info`.

Primary discovery tool (VM/Tenable.io plugin database):

```
plugins_search_plugins(query="<keywords>")
```

Search by what the user is actually after — the *data*, not a plugin name.
"running processes" → `plugins_search_plugins(query="process information")`;
"who can log into this box" → `query="enumerate accounts"`; "what's installed" →
`query="installed software enumeration"`. Each result shows `Severity`, `Family`,
and a one-line `Synopsis`. **Keep only results with `Severity: Info`** — the same
search returns vulnerability plugins too (e.g. an "installed software" search also
surfaces CVE plugins for that software).

Then confirm a candidate with:

```
plugins_get_plugin_details(plugin_id=<id>)
```

which returns the synopsis, description, family, type (`local` = credentialed,
`remote`, `combined`), and — importantly — the plugin's intended use. Plugin 70329
literally states it is "informative only and could be used for forensic
investigation, malware detection."

`plugins_list_plugin_families()` is useful when the user wants breadth ("everything
Windows collected") rather than a specific datum — the `Windows`, `General`,
`Service detection`, `SNMP`, and OS-specific families hold most info plugins.

`references/info-plugins-catalog.md` is a **seed list** of the highest-value
forensic/inventory info plugins with IDs and what each returns. Use it to jump-start
discovery and to recognize plugins in output — but always treat live discovery as
authoritative over the seed list.

## Step 2 — Locate the host / finding in Tenable VM

Work against Tenable VM (Tenable.io) using the live `workbenches_*`, `plugins_*`, and
`scan_*` MCP tools. `references/vm-workflows.md` has the exact call sequences — read
it before extracting. The short version: `workbenches_get_vulnerability_outputs`
lists every host carrying a plugin (hostname, asset ID, IPv4) alongside its output,
so it doubles as a host lookup and an environment-wide view. Be aware of its limits
(covered in Step 3 and the reference) before you rely on it for a single host.

## Step 3 — Extract the plugin output

**The plugin output text is the whole point of this skill.** It is the running-process
tree, the installed-software list, the enumerated accounts, the recycle-bin paths —
the actual telemetry. Asset IDs, finding counts, and severity are just how you locate
that text; they are not the answer. So the goal of extraction is always: get the
plugin's **output text**, as complete and untruncated as possible, for the host(s) in
scope. Don't stop at metadata and present counts as if they were findings.

The pattern is "identify the host(s) that have plugin N, then read plugin N's output
text." `references/vm-workflows.md` gives the precise call sequences. Four things
that always matter:

- **Only some endpoints return the output text.** In VM, `workbenches_get_vulnerability_outputs`
  returns the rendered output; the `*_details` endpoints return metadata (counts,
  severity) and **not** the output text. Don't mistake a `Count: 1` for the finding.
- **The MCP outputs endpoint can't target one host, and truncates.** In VM,
  `workbenches_get_vulnerability_outputs` groups hosts by output value, returns only
  the first ~10 groups (no host filter, no paging), and truncates long blocks — so a
  specific host, or a complete environment-wide list, may not come back. It's great
  for a quick look and locating hosts. When it caps out, use the **bundled script**
  `scripts/pull_plugin_output.py`, which calls the Tenable.io API directly via
  pyTenable to return full, untruncated output (whole environment or one host). Offer
  to run it — see "Completing a capped pull" below. Don't just present partial data as
  if it were complete; say what's partial and offer the script.
- **Info plugins only populate on credentialed/authenticated scans.** If a plugin
  returns no output, the likely cause is an unauthenticated scan, not an absent
  finding. Say so rather than reporting "clean."
- **Scope tightly.** Pull the specific plugin(s) for the specific host(s) asked about;
  use exports for deliberate multi-host pulls. Don't dump every info plugin for every
  asset.

### Completing a capped pull (the pyTenable option)

When the MCP outputs endpoint truncates or omits hosts, the skill ships a runnable
escape hatch: `scripts/pull_plugin_output.py`. It hits the Tenable.io API, filters
server-side by host, and returns the complete `plugin_output`. It self-selects between
two modes: **pyTenable** if that package is installed, otherwise a **dependency-free
REST call over Python's stdlib (`urllib`)**. The fallback matters because locked-down
environments (this sandbox included) often block `pip install`/PyPI while still
allowing outbound HTTPS to Tenable.io — the stdlib path needs no install and just
works. Confirmed: it pulled the full dataset here after pyTenable couldn't install.

Present it as a real option, not just a snippet. Offer the user two ways to run it:

1. **Here, if they provide API keys.** Ask for a Tenable VM access key + secret key
   (Settings → My Account → API Keys). Set them as `TIO_ACCESS_KEY` / `TIO_SECRET_KEY`
   env vars and run, e.g.
   `python scripts/pull_plugin_output.py --plugin-id 38689 --format csv`.
   Pass keys inline on the command as env vars — never write them into the script or
   any file, and never echo them back. If `pip` is blocked, the script's stdlib REST
   mode runs anyway (no `pip install` needed). Remind the user that keys entered in a
   session should be rotated afterward.
2. **On their machine.** Give them the commands to run locally — optionally
   `pip install pytenable` (skippable; stdlib mode covers it), the two `export`s, and
   the invocation.

Common invocations:

```
python scripts/pull_plugin_output.py --plugin-id 38689                    # whole env
python scripts/pull_plugin_output.py --plugin-id 70329 --ip 192.168.1.96  # one host
python scripts/pull_plugin_output.py --plugin-id 38689 --format csv --out logons.csv
```

## Step 4 — Parse and deliver

Info-plugin output is human-readable text with a per-plugin layout, not a uniform
schema. Parse defensively:

- Read the actual output first, then write the parser to the layout you see. Process
  info (70329) is tabular-ish (name, PID, path); installed software (20811) is one
  entry per line; recycle bin (92429) lists file paths with SIDs. Don't assume a
  format — confirm it.
- Preserve host attribution. When mining across assets, every parsed row needs its
  hostname/IP so findings are traceable.
- Flag, don't fabricate. For forensic/hunting work, surface what's notable
  (processes running from `%TEMP%` or user profile dirs, unexpected admin accounts,
  disabled AV, files in the recycle bin that look like exfil staging) and cite the
  plugin + host it came from. Never invent artifacts the output doesn't show.

### Deliverable shapes

Pick based on the request; `references/reporting.md` has templates. Default to the
simplest thing that answers the question — usually the plugin output itself.

- **The plugin output, parsed and presented** (the default) — when the user asks a
  direct question like "what processes are running on host X" or "what's in the
  recycle bin," just give them that plugin's output, cleaned into a readable
  structure, with the plugin ID, host, and scan date. Don't inflate a one-plugin
  question into a full report.
- **Asset inventory profile** — one host (or a set), all its info-plugin data
  organized into sections (Software, Accounts, Processes, Network, Services,
  Security controls). Good as Markdown or a `.docx`.
- **Forensic / hunting snapshot** — cross-host mining for a specific artifact with a
  findings-and-evidence structure.
- **Structured export** — a `.xlsx`/`.csv` (e.g. software-by-host, accounts-by-host)
  when the user wants to pivot the data themselves. Use the `xlsx` skill.
- **Dashboard / live view** — when the user will re-check over time, offer a Cowork
  artifact backed by the Tenable MCP tools.

Always cite the source plugin ID(s), the asset(s), and the scan recency so the user
can trust and reproduce the finding.

## Guardrails

- Info severity means "informational," **not** "safe" or "no action." Recycle-bin
  contents, cached credentials enumeration, or a rogue process are info-severity but
  can be highly security-relevant. Interpret accordingly.
- Data is a **point-in-time snapshot** from the last scan. Note the scan date; a
  process list from three weeks ago is not live IR data.
- Respect scope. This is the customer's own scan data about their own assets — but
  don't pull environment-wide dumps when the user asked about one host.

## Reference files

- `references/info-plugins-catalog.md` — seed catalog of high-value info plugins by
  category (processes, software, accounts, network, services, security controls,
  forensic artifacts) with IDs and output notes.
- `references/vm-workflows.md` — exact Tenable VM MCP call sequences for discovery,
  location, and extraction, plus the pyTenable single-host path, with real examples.
- `references/reporting.md` — deliverable templates (inventory profile, forensic
  snapshot, structured export).
- `scripts/pull_plugin_output.py` — runnable pyTenable pull for complete, untruncated
  plugin output (whole environment or one host); the option when the MCP endpoint caps.
