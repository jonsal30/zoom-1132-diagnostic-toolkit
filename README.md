# Zoom 1132 Diagnostic Toolkit

A local-first, evidence-driven diagnostic and repair toolkit for Zoom desktop issues, including Error 1132 investigations.

## Purpose

This project is designed to distinguish among:

- Zoom installation problems
- corrupted or stale local Zoom state
- DNS / TCP / TLS / proxy / VPN problems
- endpoint reachability problems
- authentication or access-policy conditions
- unknown conditions that require escalation with a diagnostic bundle

The toolkit does **not** spoof device identifiers, modify MAC addresses, obscure hardware identity, or attempt to bypass service-side restrictions.

## Safety model

Every repair action follows:

`discover -> snapshot -> backup -> change -> verify -> report`

The first milestone is diagnostic-only. Destructive operations must be explicitly invoked and should be reversible where practical.

## Quick start

```bash
swift build
swift run zoom-repair
swift test
```

## Project status

**Milestone 1: Diagnostic engine — in progress**

Planned milestones:

1. Read-only macOS diagnostics
2. Backup / reset / verify / rollback for local Zoom state
3. HTML + JSON diagnostic bundle export
4. Windows adapter
5. Packaged macOS UI

## Disclaimer

This is an independent troubleshooting project and is not affiliated with or endorsed by Zoom Communications, Inc.
