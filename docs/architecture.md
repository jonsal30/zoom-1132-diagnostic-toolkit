# Architecture

## Objective

Build a troubleshooting utility that can answer a more useful question than "did Error 1132 occur?": **which layer has evidence of failure, and how confident are we?**

## Layers

1. **Installation** — application presence, version, code-signing, executable health.
2. **Local state** — Zoom cache, preferences, logs, saved state, updater state.
3. **Network** — DNS, proxy, VPN, route, TCP/TLS, HTTP reachability.
4. **Authentication/access** — evidence that connectivity is healthy while the requested Zoom operation is still rejected.
5. **Repair** — reversible local changes only after a snapshot and explicit invocation.
6. **Reporting** — local JSON/HTML evidence bundle; no automatic upload.

## Non-goals

The project will not implement:

- MAC address spoofing
- serial/UUID/board-ID hiding
- sandbox profiles intended to conceal device identity
- bypasses for Zoom account/device/service restrictions

## Repair invariant

Every modifying operation must conform to:

`discover -> snapshot -> backup -> change -> verify -> report`

Rollback should be provided whenever the underlying change is reversible.

## Platform strategy

The shared `ZoomRepairCore` owns evidence models, confidence, classification, and reporting. Platform adapters collect evidence and execute approved repair actions. macOS is the first implementation; Windows follows the same model rather than becoming a separate codebase.
