---
name: "Tenable Info Plugins"
author: "jdavies-pub-git"
github_url: "https://github.com/jdavies-pub-git/tenable-info-skill"
description: "Discover, extract, and analyze data from Tenable INFO-severity plugins in Tenable VM — running processes, installed software, accounts, last logged-on user, recycle-bin contents, and more — for inventory, forensics, and threat hunting."
license: "MIT"
type: "skill"
tier: "unreviewed"
tags: ["tenable", "vulnerability-management", "info-plugins", "asset-inventory", "forensics", "threat-hunting", "claude-code"]
framework: "Claude Code SKILL"
integrations: ["Tenable"]
date_added: 2026-07-16
---

Discover, extract, and analyze data from Tenable INFO-severity (informational)
plugins in Tenable Vulnerability Management. Info plugins aren't vulnerabilities —
they're the rich host telemetry a credentialed scan already collected: running
processes, installed software, local/AD accounts, last logged-on user, services,
startup items, network shares, recycle-bin contents, AV/firewall status, and patch
levels.

The skill teaches Claude to discover the right info plugin at query time, pull its
output, parse it, and turn it into inventory, forensic, or threat-hunting
deliverables. It uses the Tenable VM MCP tools for discovery and environment-wide
mining, documents where those tools cap out, and bundles a completion script
(`scripts/pull_plugin_output.py`) that pulls complete, untruncated output via the
Tenable.io API — trying pyTenable first and falling back to a dependency-free stdlib
REST call so it runs in locked-down environments.
