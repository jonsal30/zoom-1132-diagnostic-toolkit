import Foundation
import ZoomRepairCore

struct MacDiagnostics {
    private let fm = FileManager.default
    private let zoomPath = "/Applications/zoom.us.app"

    func run() -> DiagnosticReport {
        var findings: [DiagnosticFinding] = []

        let installed = fm.fileExists(atPath: zoomPath)
        findings.append(.init(
            name: "Zoom Installation",
            category: .installation,
            state: installed ? .healthy : .failed,
            confidence: 0.99,
            evidence: installed ? "Found \(zoomPath)." : "Zoom application bundle was not found at \(zoomPath)."
        ))

        if installed {
            findings.append(codeSignatureFinding())
            findings.append(versionFinding())
            findings.append(urlSchemeFinding())
        }

        findings.append(localStateFinding())
        findings.append(keychainFinding())
        findings.append(decryptionFailureFinding())
        findings.append(managedPolicyFinding())
        findings.append(processInventoryFinding())
        findings.append(proxyFinding())

        findings.append(commandFinding(
            name: "DNS Resolution",
            category: .network,
            executable: "/usr/bin/dig",
            arguments: ["+short", "zoom.us"],
            healthyWhen: { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty },
            successEvidence: { output in
                "zoom.us resolved successfully: \(compact(output))"
            }
        ))

        findings.append(curlTimingFinding(
            name: "Zoom HTTPS Reachability",
            url: "https://zoom.us"
        ))

        findings.append(curlTimingFinding(
            name: "Zoom Meeting Endpoint Reachability",
            url: "https://www3.zoom.us"
        ))

        let assessments = DiagnosticClassifier.assessments(for: findings)
        return DiagnosticReport(findings: findings, assessments: assessments)
    }

    private func localStateFinding() -> DiagnosticFinding {
        let home = fm.homeDirectoryForCurrentUser.path
        let statePaths = [
            "\(home)/Library/Application Support/zoom.us",
            "\(home)/Library/Caches/us.zoom.xos",
            "\(home)/Library/Preferences/us.zoom.xos.plist",
            "\(home)/Library/Saved Application State/us.zoom.xos.savedState",
            "\(home)/Library/Logs/zoom.us"
        ]
        let existing = statePaths.filter { fm.fileExists(atPath: $0) }
        return .init(
            name: "Zoom Local State",
            category: .localState,
            state: .healthy,
            confidence: 0.88,
            evidence: "Detected \(existing.count) of \(statePaths.count) known Zoom local-state locations. Presence is normal and is not treated as corruption without stronger evidence."
        )
    }

    private func keychainFinding() -> DiagnosticFinding {
        let keychain = "\(fm.homeDirectoryForCurrentUser.path)/Library/Keychains/login.keychain-db"
        let services = ["Zoom Safe Meeting Storage", "Zoom Safe Storage"]
        var present: [String] = []
        var missing: [String] = []

        for service in services {
            let result = runCommand(
                executable: "/usr/bin/security",
                arguments: ["find-generic-password", "-s", service, keychain]
            )
            if result.launched && result.status == 0 {
                present.append(service)
            } else {
                missing.append(service)
            }
        }

        if missing.isEmpty {
            return .init(
                name: "Zoom Safe Keychain",
                category: .localState,
                state: .healthy,
                confidence: 0.96,
                evidence: "Both documented Zoom Safe keychain items are present. Secret values were not read."
            )
        }

        return .init(
            name: "Zoom Safe Keychain",
            category: .localState,
            state: .suspect,
            confidence: 0.86,
            evidence: "Missing keychain item(s): \(missing.joined(separator: ", ")). Present: \(present.isEmpty ? "none" : present.joined(separator: ", ")). Secret values were not read."
        )
    }

    private func decryptionFailureFinding() -> DiagnosticFinding {
        let dataPath = "\(fm.homeDirectoryForCurrentUser.path)/Library/Application Support/zoom.us/data"
        guard fm.fileExists(atPath: dataPath) else {
            return .init(
                name: "Zoom Encrypted State",
                category: .localState,
                state: .unknown,
                confidence: 0.70,
                evidence: "Zoom data directory is not present yet."
            )
        }

        let root = URL(fileURLWithPath: dataPath)
        let keys: [URLResourceKey] = [.isRegularFileKey]
        let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])
        var failures: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            if url.lastPathComponent.hasSuffix(".decfail") {
                failures.append(url.lastPathComponent)
            }
        }

        if failures.isEmpty {
            return .init(
                name: "Zoom Encrypted State",
                category: .localState,
                state: .healthy,
                confidence: 0.97,
                evidence: "No Zoom .decfail encrypted-database failure markers were found."
            )
        }

        return .init(
            name: "Zoom Encrypted State",
            category: .localState,
            state: .failed,
            confidence: 0.99,
            evidence: "Detected Zoom decryption-failure marker(s): \(failures.sorted().joined(separator: ", ")). Rebuild local encrypted state only after Zoom Safe key material is present."
        )
    }

    private func managedPolicyFinding() -> DiagnosticFinding {
        let home = fm.homeDirectoryForCurrentUser.path
        let candidates = [
            "\(home)/Library/Preferences/us.zoom.config.plist",
            "\(home)/Library/Managed Preferences/us.zoom.config.plist",
            "/Library/Preferences/us.zoom.config.plist",
            "/Library/Managed Preferences/us.zoom.config.plist"
        ]
        let existing = candidates.filter { fm.fileExists(atPath: $0) }
        guard !existing.isEmpty else {
            return .init(
                name: "Zoom Managed Policy",
                category: .localState,
                state: .healthy,
                confidence: 0.90,
                evidence: "No standard Zoom managed-policy plist was found in user or system preference locations."
            )
        }

        let sensitiveKeys = [
            "SetWebDomain", "EnforceSignInToJoin", "EnforceAppSignInToJoin",
            "ForceSSOURL", "zAutoSSOLogin", "zSSOHost", "Login_Domain",
            "SetDevicePolicyToken", "NoSSO", "DisableLoginWithEmail"
        ]
        var hits: [String] = []
        for path in existing {
            guard let data = fm.contents(atPath: path),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                  let dict = plist as? [String: Any] else { continue }
            let presentKeys = sensitiveKeys.filter { dict[$0] != nil }
            if !presentKeys.isEmpty {
                hits.append("\(URL(fileURLWithPath: path).lastPathComponent): \(presentKeys.joined(separator: ", "))")
            }
        }

        return .init(
            name: "Zoom Managed Policy",
            category: .localState,
            state: hits.isEmpty ? .suspect : .suspect,
            confidence: hits.isEmpty ? 0.70 : 0.95,
            evidence: hits.isEmpty
                ? "Zoom configuration plist(s) exist but no known handshake-affecting keys were detected: \(existing.joined(separator: ", ")). Review manually."
                : "Handshake-affecting managed Zoom policy key(s) detected: \(hits.joined(separator: "; "))."
        )
    }

    private func urlSchemeFinding() -> DiagnosticFinding {
        let plistPath = "\(zoomPath)/Contents/Info.plist"
        guard let data = fm.contents(atPath: plistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = plist as? [String: Any],
              let types = dict["CFBundleURLTypes"] as? [[String: Any]] else {
            return .init(
                name: "Zoom URL Schemes",
                category: .installation,
                state: .unknown,
                confidence: 0.60,
                evidence: "Unable to inspect Zoom URL-scheme registration in Info.plist."
            )
        }

        let schemes = types.flatMap { $0["CFBundleURLSchemes"] as? [String] ?? [] }
        let required = ["zoommtg", "zoomus"]
        let missing = required.filter { !schemes.contains($0) }
        return .init(
            name: "Zoom URL Schemes",
            category: .installation,
            state: missing.isEmpty ? .healthy : .failed,
            confidence: 0.98,
            evidence: missing.isEmpty
                ? "Zoom registers both zoommtg and zoomus URL schemes."
                : "Missing Zoom URL scheme(s): \(missing.joined(separator: ", "))."
        )
    }

    private func codeSignatureFinding() -> DiagnosticFinding {
        let codesign = runCommand(
            executable: "/usr/bin/codesign",
            arguments: ["--verify", "--deep", zoomPath]
        )
        let gatekeeper = runCommand(
            executable: "/usr/sbin/spctl",
            arguments: ["-a", "-vv", zoomPath]
        )

        let codesignHealthy = codesign.launched && codesign.status == 0
        let gatekeeperHealthy = gatekeeper.launched && gatekeeper.status == 0

        if codesignHealthy && gatekeeperHealthy {
            return .init(
                name: "Zoom Code Signature",
                category: .installation,
                state: .healthy,
                confidence: 0.99,
                evidence: "macOS codesign verification passed and Gatekeeper accepted the Zoom app as trusted/notarized."
            )
        }

        let details = [
            codesign.output.trimmingCharacters(in: .whitespacesAndNewlines),
            gatekeeper.output.trimmingCharacters(in: .whitespacesAndNewlines)
        ].filter { !$0.isEmpty }.joined(separator: " | ")

        return .init(
            name: "Zoom Code Signature",
            category: .installation,
            state: .failed,
            confidence: 0.95,
            evidence: details.isEmpty ? "Zoom signature or Gatekeeper verification failed without diagnostic output." : details
        )
    }

    private func versionFinding() -> DiagnosticFinding {
        let plist = "\(zoomPath)/Contents/Info.plist"
        return commandFinding(
            name: "Zoom Version",
            category: .installation,
            executable: "/usr/libexec/PlistBuddy",
            arguments: ["-c", "Print :CFBundleShortVersionString", plist],
            healthyWhen: { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty },
            successEvidence: { output in "Installed Zoom version: \(compact(output))" }
        )
    }

    private func processInventoryFinding() -> DiagnosticFinding {
        let result = runCommand(
            executable: "/bin/ps",
            arguments: ["-axo", "pid=,comm="]
        )

        guard result.launched else {
            return .init(
                name: "Zoom Process Inventory",
                category: .localState,
                state: .unknown,
                confidence: 0.60,
                evidence: result.output
            )
        }

        let zoomLines = result.output
            .split(separator: "\n")
            .map(String.init)
            .filter { line in
                let lower = line.lowercased()
                return lower.contains("zoom.us") || lower.contains("caphost") || lower.contains("cpthost") || lower.contains("zoomupdater") || lower.contains("zautoupdate")
            }

        return .init(
            name: "Zoom Process Inventory",
            category: .localState,
            state: .healthy,
            confidence: 0.94,
            evidence: zoomLines.isEmpty ? "No Zoom client/updater processes are currently running." : "Running Zoom-related processes: \(zoomLines.joined(separator: "; "))"
        )
    }

    private func proxyFinding() -> DiagnosticFinding {
        let result = runCommand(executable: "/usr/sbin/scutil", arguments: ["--proxy"])
        guard result.launched && result.status == 0 else {
            return .init(
                name: "System Proxy",
                category: .network,
                state: .unknown,
                confidence: 0.65,
                evidence: result.output
            )
        }

        let enabled = result.output.contains("HTTPEnable : 1") ||
            result.output.contains("HTTPSEnable : 1") ||
            result.output.contains("SOCKSEnable : 1")

        return .init(
            name: "System Proxy",
            category: .network,
            state: enabled ? .suspect : .healthy,
            confidence: 0.95,
            evidence: enabled ? "A system HTTP/HTTPS/SOCKS proxy appears enabled. Review before attributing 1132 to Zoom itself." : "No enabled system HTTP/HTTPS/SOCKS proxy was detected."
        )
    }

    private func curlTimingFinding(name: String, url: String) -> DiagnosticFinding {
        let format = "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}"
        let result = runCommand(
            executable: "/usr/bin/curl",
            arguments: ["-sS", "-o", "/dev/null", "-w", format, "--max-time", "10", url]
        )

        guard result.launched && result.status == 0 else {
            return .init(
                name: name,
                category: .network,
                state: .failed,
                confidence: 0.92,
                evidence: "curl failed: \(compact(result.output))"
            )
        }

        let parts = result.output.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "|", omittingEmptySubsequences: false)
        guard parts.count == 7 else {
            return .init(
                name: name,
                category: .network,
                state: .unknown,
                confidence: 0.65,
                evidence: "Unexpected curl metrics: \(compact(result.output))"
            )
        }

        let http = String(parts[0])
        let healthy = http.hasPrefix("2") || http.hasPrefix("3")
        let evidence = "HTTP \(http), remote \(parts[1]), DNS \(parts[2])s, TCP \(parts[3])s, TLS \(parts[4])s, first-byte \(parts[5])s, total \(parts[6])s."

        return .init(
            name: name,
            category: .network,
            state: healthy ? .healthy : .failed,
            confidence: healthy ? 0.99 : 0.94,
            evidence: evidence
        )
    }

    private func commandFinding(
        name: String,
        category: DiagnosticCategory,
        executable: String,
        arguments: [String],
        healthyWhen: (String) -> Bool,
        successEvidence: (String) -> String
    ) -> DiagnosticFinding {
        let result = runCommand(executable: executable, arguments: arguments)

        guard result.launched else {
            return .init(name: name, category: category, state: .unknown, confidence: 0.60, evidence: result.output)
        }

        let healthy = result.status == 0 && healthyWhen(result.output)
        return .init(
            name: name,
            category: category,
            state: healthy ? .healthy : .failed,
            confidence: healthy ? 0.98 : 0.90,
            evidence: healthy ? successEvidence(result.output) : "Command failed or returned unexpected output: \(compact(result.output))"
        )
    }

    private func runCommand(executable: String, arguments: [String]) -> (launched: Bool, status: Int32, output: String) {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (true, process.terminationStatus, String(decoding: data, as: UTF8.self))
        } catch {
            return (false, -1, "Unable to execute diagnostic: \(error.localizedDescription)")
        }
    }
}

private func compact(_ value: String) -> String {
    value.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\n", with: "; ")
}
