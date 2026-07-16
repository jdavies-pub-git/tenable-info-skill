# Info-Plugin Seed Catalog

A starting list of high-value INFO-severity plugins for inventory and forensics.
This is a **seed**, not the source of truth — always confirm IDs and severity with
`plugins_search_plugins` / `plugins_get_plugin_details`, since plugins change and
new ones are added constantly. Use this to jump-start a search and to recognize
plugins when you see them in output.

All plugins below are `Severity: Info`. Most are `Type: local`, meaning they only
populate on **credentialed / authenticated** scans. If output is empty, suspect an
unauthenticated scan first.

## Processes & running state (malware detection, forensics)

| ID | Name | What it returns |
|----|------|-----------------|
| 70329 | Microsoft Windows Process Information | Running processes via WMI (name, PID, path). Tenable flags this as forensic/malware-detection use. |
| 70331 | Microsoft Windows Process Information Failure | Signals WMI process collection failed (scan/creds problem). |
| 110483 | Unix Running Processes Information | Running processes on Linux/Unix hosts. |
| 33813 | Windows Services Enumeration | Installed Windows services, state, start type, binary path. |
| 44401 | Microsoft Windows SMB Service Config Enumeration | Service configuration parameters. |
| 58452 | Microsoft Windows Startup Software Enumeration | Autostart/Run-key programs — classic persistence hunting. |

## Installed software & patches (inventory)

| ID | Name | What it returns |
|----|------|-----------------|
| 20811 | Microsoft Windows Installed Software Enumeration (credentialed) | Full installed-application list, one per line. |
| 22869 | Software Enumeration (SSH) | Installed packages on Linux/Unix over SSH. |
| 83991 | List Installed Mac OS X Software | Managed/packaged software on macOS. |
| 13855 | Microsoft Windows Installed Hotfixes | Applied hotfixes/KBs. |
| 97993 / 97998 | OS Identification and Installed Software Enumeration over SSH | OS + software via authenticated SSH. |
| 9479 / 7215 | Installed Software Detection via SNMP | Software seen via SNMP. |

## Accounts & identity (privilege, forensics)

| ID | Name | What it returns |
|----|------|-----------------|
| 171956 | Windows Enumerate Accounts | Local/enumerated Windows accounts. |
| 171957 | Windows Registry Enumerate Cached Accounts | Cached domain accounts from registry — who logged in. |
| 10860 | SMB Use Host SID to Enumerate Local Users | Local users via SID. |
| 10399 | SMB Use Domain SID to Enumerate Users | Domain users via SID. |
| 92367 | Windows User Enumeration variants | Local user detail. |

## Network configuration

| ID | Name | What it returns |
|----|------|-----------------|
| 24272 | Network Interfaces Enumeration (Windows/WMI) | NICs, IPs, MACs. |
| 10287 | Traceroute Information | Network path to host. |
| 35716 | Ethernet Card Manufacturer Detection | MAC → vendor. |
| 60119 | Microsoft Windows SMB Share Permissions Enumeration | Network shares and their ACLs. |
| 10395 | Microsoft Windows SMB Shares Enumeration | Enumerated shares. |

## Security controls (posture, gaps)

| ID | Name | What it returns |
|----|------|-----------------|
| 45051 | WMI Antivirus Enumeration | Installed AV products (a "Critical" variant, 52668-style, flags AV present-but-broken). |
| 45050 | WMI Anti-spyware Enumeration | Anti-spyware products. |
| 45052 | WMI Firewall Enumeration | Third-party firewall software. |
| 20094 | Detected antivirus / EDR variants | Endpoint protection detail. |

## Forensic artifacts

| ID | Name | What it returns |
|----|------|-----------------|
| 92429 | Recycle Bin Files | Files in `$Recycle.Bin` subdirs, per SID — deleted-file forensics, exfil staging. |
| 63080 | Microsoft Windows Mounted Devices | Mounted/removable device history. |
| 92428 | (family) file/USB artifact plugins | Various on-disk artifacts. |

## Discovery recipes

Map a user question to a search term, then filter to `Severity: Info`:

- "what's running on host X" → `query="process information"` → 70329 / 110483
- "what software / apps" → `query="installed software enumeration"` → 20811 / 22869
- "patch level / hotfixes" → `query="installed hotfixes"` → 13855
- "who can log in / accounts" → `query="enumerate accounts"` → 171956 / 171957
- "network shares / who can reach what" → `query="share permissions enumeration"` → 60119
- "is AV/EDR running" → `query="antivirus enumeration"` → 45051
- "deleted files / recycle bin" → `query="recycle bin"` → 92429
- "autoruns / persistence" → `query="startup software enumeration"` → 58452

When the user wants *everything* a scan gathered on a host, don't guess a list —
pull the asset's full finding set and filter to Info severity (see
`vm-workflows.md`), then group by the categories above.
