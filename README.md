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

Milestone 1 remains read-only. Destructive operations are intentionally deferred until diagnostics and rollback behavior are tested.

## Implemented macOS checks

- Zoom application presence
- Zoom bundle version
- macOS code-signature verification
- known Zoom local-state locations
- running Zoom/client/updater process inventory
- system HTTP/HTTPS/SOCKS proxy detection
- DNS resolution for `zoom.us`
- timed HTTPS reachability for `zoom.us`
- timed HTTPS reachability for `www3.zoom.us`
- category-based concern/confidence scoring
- JSON report export

## Quick start

```bash
swift build
swift run zoom-repair
swift test
```

Export a structured report:

```bash
swift run zoom-repair --json
```

Or choose a destination:

```bash
swift run zoom-repair --json ~/Desktop/zoom-1132-diagnostic.json
```

## Interpreting results

A healthy network result does not mean Zoom must permit a meeting join. It means the implemented DNS/HTTPS path checks succeeded. If those checks are healthy while Zoom still returns 1132, preserve the report and investigate authentication/access behavior rather than repeatedly resetting the network.

Likewise, the presence of normal Zoom cache or preference files is not classified as corruption by itself.

## Project status

**Milestone 1: Diagnostic engine — active**

Current sequence:

1. Read-only macOS diagnostics — active
2. Regression fixtures and CI verification — active
3. Backup / reset / verify / rollback for local Zoom state — next
4. HTML diagnostic bundle export
5. Windows adapter
6. Packaged macOS UI

## CI

GitHub Actions is configured to run `swift build` and `swift test` on macOS for pushes to `main` and pull requests.

## Privacy

Diagnostic data is local-first. The project does not contain an automatic telemetry or bug-report upload path. Exported reports remain on the user's machine unless the user deliberately shares them.

## Disclaimer

This is an independent troubleshooting project and is not affiliated with or endorsed by Zoom Communications, Inc.
