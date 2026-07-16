# Tenable Info Plugins — Claude Skill

A [Claude](https://claude.com) skill for mining the **INFO-severity (informational)
plugins** in Tenable Vulnerability Management (Tenable VM / Tenable.io). Info plugins
aren't vulnerabilities — they're the rich host telemetry a credentialed scan already
collected: running processes, installed software, local/AD accounts, last logged-on
user, services, startup items, network shares, recycle-bin contents, AV/firewall
status, and patch levels. This skill teaches Claude to discover the right info plugin
for a question, pull its output, parse it, and turn it into inventory, forensic, or
threat-hunting deliverables.

## What it does

- **Dynamic plugin discovery** — finds the relevant info plugin at query time
  (`plugins_search_plugins`) instead of relying on a hard-coded list, and confirms
  `Severity: Info` before use.
- **Extraction that knows the limits** — uses the Tenable VM MCP tools for quick looks
  and environment-wide mining, and documents where they cap out (see below).
- **A completion path** — bundles `scripts/pull_plugin_output.py` to pull complete,
  untruncated output when the MCP endpoint truncates or omits hosts.
- **Deliverables** — parsed plugin output, single-host inventory profiles, cross-host
  forensic/hunting snapshots, and CSV/XLSX exports.

## Repository structure

```
tenable-info-plugins/
├── SKILL.md                          # skill entry point (frontmatter + workflow)
├── README.md                         # this file
├── references/
│   ├── info-plugins-catalog.md       # seed catalog of high-value info plugins by category
│   ├── vm-workflows.md               # exact Tenable VM MCP call sequences + pyTenable path
│   └── reporting.md                  # deliverable templates
└── scripts/
    └── pull_plugin_output.py         # complete-output pull (pyTenable → stdlib REST fallback)
```

## Prerequisites

- **Claude with the Tenable MCP connector** for plugin discovery and the workbench
  tools (`plugins_*`, `workbenches_*`, `scan_*`).
- **A Tenable VM API key pair** (Settings → My Account → API Keys) only if you run
  `scripts/pull_plugin_output.py` for complete pulls. A read-only key scoped to your
  user is recommended.
- **Python 3.8+** to run the script. `pytenable` is optional — the script falls back
  to a dependency-free REST call if it isn't installed.

## Installing the skill

**Into Claude / Cowork (recommended):** package the folder into a `.skill` file and
open it in the Claude desktop app — click **Save skill** on the file card to install
it into your profile.

**From this repo:** clone it and point your Claude Code / Cowork skills directory at
the `tenable-info-plugins/` folder, or copy the folder into your configured skills
location.

```bash
git clone https://github.com/<your-org>/tenable-info-plugins.git
```

Once installed, the skill triggers automatically on requests like "what processes are
running on host X", "who last logged into these servers", "profile this box from
Tenable", or any mention of info plugins / a plugin ID.

## Using the completion script

The MCP outputs endpoint returns only the first ~10 grouped result blocks, truncates
long output, and has no host filter — so it can't reliably return one specific host's
full output or a complete environment-wide list. `pull_plugin_output.py` closes that
gap by calling the Tenable.io API directly.

```bash
export TIO_ACCESS_KEY=...      # never hard-code these in a file
export TIO_SECRET_KEY=...

# Whole environment
python scripts/pull_plugin_output.py --plugin-id 38689

# One host
python scripts/pull_plugin_output.py --plugin-id 70329 --ip 192.168.1.96

# Structured export
python scripts/pull_plugin_output.py --plugin-id 38689 --format csv --out logons.csv
```

The script **tries pyTenable first and falls back to a stdlib `urllib` REST call** when
pyTenable isn't installed, so it runs in locked-down environments where `pip install`
can't reach PyPI (only outbound HTTPS to `cloud.tenable.com` is required). For FedRAMP
or sovereign clouds, set `TIO_URL` to the appropriate API host.

## Security notes

- API keys are read from environment variables only. **Do not** paste keys into
  `SKILL.md`, the script, or any file — anything committed to the repo or packaged into
  the `.skill` travels with it.
- Rotate any key that has been placed in a file or entered into a shared session.
- Info-plugin data is the customer's own scan data. Scope pulls to what you need;
  avoid environment-wide dumps when a single host was requested.
- "Info" severity means informational, not "safe" — recycle-bin contents, cached
  account enumeration, or a rogue process can be highly security-relevant.

## Notes & caveats

- Info plugins populate only on **credentialed / authenticated** scans. Empty output
  usually means an unauthenticated scan, not a clean host.
- Results are a **point-in-time snapshot** from the last scan — note the scan date.
- Plugin IDs and names change over time; the skill favors live discovery over any
  fixed list.

## License

Released under the [MIT License](LICENSE).
