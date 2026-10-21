# macOS 1132 Repair Runbook

This runbook captures the safe, evidence-driven parts of the legacy `Zoom1132fix` workflow and the additional state discovered during a live macOS investigation.

## Legacy workflow audit

The historical script performed five major actions:

1. Changed the active network interface MAC address.
2. Removed an existing `zoomuser1` macOS account.
3. Created a fresh macOS account.
4. Copied `/Users/Shared/ZoomTemplate` into that account when the template existed.
5. Launched Zoom from the fresh account.

### Retained concepts

The toolkit retains the legitimate diagnostic intent behind the fresh-user portion:

- isolate user-scoped Zoom preferences and caches;
- isolate Zoom keychain state;
- isolate user-scoped TCC/privacy state;
- validate Zoom URL-scheme registration;
- detect managed client policy that can affect sign-in or join behavior;
- detect encrypted local-database failures before attributing the problem to the network or service.

A fresh macOS user may be used as an **isolation test** when necessary. It is not a service-restriction workaround and should not be treated as a permanent bypass.

### Excluded behavior

The toolkit does not change or randomize MAC addresses, spoof device identifiers, conceal hardware identity, create alternate Zoom identities, or otherwise attempt to evade a Zoom account/device/service restriction.

`/Users/Shared/ZoomTemplate` is not assumed to exist. A template must never be synthesized from unknown or identity-bearing state. If a known-good template is intentionally used, it must be version-compatible, backed up, and validated before restoration.

## Diagnostic sequence

Run diagnostics before changing state:

```bash
swift run zoom-repair --json ~/Desktop/zoom-1132-diagnostic.json
```

Review these layers in order:

1. **Installation**
   - app bundle exists;
   - version is known;
   - code signature passes;
   - Gatekeeper accepts the app;
   - `zoommtg` and `zoomus` URL schemes are registered.
2. **Local state**
   - normal Zoom state locations are inventoried;
   - both `Zoom Safe Meeting Storage` and `Zoom Safe Storage` keychain items are present once Zoom has initialized;
   - no `.decfail` files exist under `~/Library/Application Support/zoom.us/data`;
   - running Zoom/updater processes are inventoried.
3. **Managed policy**
   - inspect standard Zoom configuration/Managed Preferences locations for sign-in or join policies;
   - pay particular attention to web-domain, SSO, sign-in-to-join, login-domain, account, and device-policy settings.
4. **Network**
   - proxy state;
   - DNS resolution;
   - Zoom HTTPS reachability;
   - meeting-endpoint HTTPS reachability.
5. **Access/authentication**
   - if the preceding layers are healthy and the desktop client still returns 1132, preserve the report and the exact client error instead of repeatedly resetting the network.

## Safe clean-repair sequence

Only proceed after a snapshot and backup.

### 1. Snapshot

Preserve relevant user state before changing it, including:

- `~/Library/Application Support/zoom.us`
- Zoom caches and preferences
- Zoom HTTP storage and group-container state
- Zoom logs
- metadata indicating whether the two `Zoom Safe...` keychain items exist

Do not export or commit keychain secret values.

### 2. Use Zoom's own uninstall path

Prefer Zoom Workplace's built-in **Uninstall Zoom Workplace** command or the supported Zoom uninstaller. Verify that the application, privileged helper, launch daemon, and updater agents are actually gone before calling the uninstall complete.

### 3. Keychain decision

Zoom documents `Zoom Safe...` keychain items as part of its local cryptographic state. Removing them is destructive and can make encrypted Zoom data unreadable.

Only reset these items when:

- a backup/snapshot has already been made;
- the user accepts the encrypted-data consequence;
- the repair goal is a genuinely clean Zoom client state.

Never log or export their password values.

### 4. Remove residual client state

After the vendor uninstall, remove only identified Zoom client remnants that have been backed up. Do not delete unrelated macOS state based only on a fuzzy name match.

### 5. Reinstall a verified official build

Verify the installer signature before installation. After installation, verify both code-signing and Gatekeeper acceptance.

### 6. Initialize key material before rebuilding encrypted databases

A live investigation observed Zoom creating multiple `*.decfail` markers before its two `Zoom Safe...` keychain items existed. After the keychain items appeared, rebuilding `~/Library/Application Support/zoom.us/data` produced clean databases without new `.decfail` markers and restored the full Zoom desktop UI.

Therefore:

1. confirm the two Zoom Safe keychain items exist;
2. snapshot the current `data` directory;
3. only then rebuild local encrypted data if `.decfail` markers are present;
4. relaunch Zoom and verify that `.decfail` markers do not reappear.

Do not restore encrypted databases created under different key material.

### 7. Reset user-scoped permissions only when needed

A fresh macOS user has fresh TCC/privacy state. When isolating a damaged profile, resetting Zoom's own TCC grants can reproduce that condition without changing device identity. The user must re-grant camera, microphone, screen/system-audio, and other requested permissions afterward.

### 8. Verify native client behavior

Verify, in order:

- Zoom home/sign-in UI appears;
- `Sign in` and `Join meeting` actions present a window;
- an official Zoom test meeting reaches the native pre-join flow;
- meeting host processes start as expected;
- no 1132 dialog appears.

If the native client still returns 1132 after all local layers are healthy, preserve the diagnostic bundle and use Zoom's `Report to Zoom` flow. Do not escalate to device-identity changes.

## Interpreting `.decfail`

`*.decfail` files under Zoom's data directory are treated as strong evidence of local encrypted-state failure. Their presence should increase local-state concern substantially. Their absence after a keyed rebuild is evidence that the local cryptographic store is internally consistent; it does **not** prove Zoom will authorize a meeting join.

## Fresh-user isolation

A temporary standard macOS user can be useful when all other local checks are inconclusive because it independently resets:

- user preferences and caches;
- keychain state;
- TCC/privacy grants;
- user-scoped containers and saved state.

Use it only to compare behavior. If both profiles reproduce 1132 while installation and network checks are healthy, treat the result as stronger access/authentication evidence rather than a reason to alter device identity.
