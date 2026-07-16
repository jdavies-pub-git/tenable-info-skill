# Reporting Templates

Deliverable structures for info-plugin data. Pick by request. Always cite source
plugin ID(s), asset(s), and scan date. For `.docx`/`.pptx`/`.xlsx` output use the
matching skill; if the deliverable represents Tenable, also apply the
`tenable-brand-guidelines` skill.

## 1. Asset Inventory Profile (single host or small set)

Best as Markdown or `.docx`. Organize by category, not by plugin ID — the reader
cares about the host, not the scanner internals.

```
# Asset Profile: <hostname> (<ip>)
Scan date: <date> · Source: Tenable VM · Credentialed: <yes/no>

## Summary
1–2 sentences: OS, role, anything notable.

## Installed Software        (plugins 20811 / 22869 / 83991)
## Patches & Hotfixes        (plugin 13855)
## Local & Domain Accounts   (plugins 171956 / 171957)
## Running Processes         (plugin 70329 / 110483)
## Services & Startup        (plugins 33813 / 58452)
## Hardware & firmware (CPU, memory, BIOS/model/serial)  (35351 / 45432 / 45433)
## Network (interfaces, shares, share permissions)   (24272 / 10395 / 60119)
## Security Controls (AV / firewall)                 (45051 / 45052)
## Forensic Artifacts (recycle bin, mounted devices) (92429 / 63080)

## Notable Observations
Bulleted call-outs, each citing the plugin + evidence line.
```

## 2. Forensic / Threat-Hunting Snapshot (cross-host)

For "find X across the environment." Findings-and-evidence structure; every row
traceable to a host.

```
# Hunt: <what you looked for>
Scope: <asset filter> · Plugin(s): <ids> · Scan window: <dates>

## Method
Which info plugin(s) mined and the criterion for "notable."

## Findings
| Host | IP | Evidence | Plugin | Why notable |
|------|----|----------|--------|-------------|
| ...  |    |          |        |             |

## Not-notable / clean hosts
Count + list, so absence is explicit.

## Caveats
Point-in-time; unauthenticated hosts excluded (list them).
```

Good hunt criteria: processes from `%TEMP%`/profile/unsigned paths (70329);
unexpected local admins or stale cached accounts (171956/171957); disabled or
missing AV (45051); shares with `Everyone: Full Control` (60119); files in
`$Recycle.Bin` that look like staging (92429); unexpected autoruns (58452).

## 3. Structured Export (`.xlsx` / `.csv`)

When the user wants to pivot the data. One row per item, host attribution on every
row. Use the `xlsx` skill.

- Software-by-host: `Host | IP | Software | Version | Source plugin`
- Accounts-by-host: `Host | IP | Account | Type(local/cached) | Source plugin`
- Processes-by-host: `Host | IP | Process | PID | Path | Flagged?`

## 4. Live Dashboard (Cowork artifact)

When the user will re-check over time, offer a Cowork artifact backed by the
Tenable VM MCP tools (e.g. `workbenches_get_vulnerability_outputs`).
Probe the tool response shape once in chat first, then build the artifact to parse
what you actually observed. Good for a recurring "recycle-bin watch" or
"unexpected-process watch" across a tagged asset group.
