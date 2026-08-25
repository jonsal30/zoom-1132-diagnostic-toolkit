import Foundation
import ZoomRepairCore

struct MacDiagnostics {
    private let fm = FileManager.default

    func run() -> DiagnosticReport {
        var findings: [DiagnosticFinding] = []

        let zoomPath = "/Applications/zoom.us.app"
        let installed = fm.fileExists(atPath: zoomPath)
        findings.append(.init(
            name: "Zoom Installation",
            state: installed ? .healthy : .failed,
            confidence: 0.99,
            evidence: installed ? "Found \(zoomPath)." : "Zoom application bundle was not found at \(zoomPath)."
        ))

        let home = fm.homeDirectoryForCurrentUser.path
        let statePaths = [
            "\(home)/Library/Application Support/zoom.us",
            "\(home)/Library/Caches/us.zoom.xos",
            "\(home)/Library/Preferences/us.zoom.xos.plist",
            "\(home)/Library/Saved Application State/us.zoom.xos.savedState"
        ]
        let existing = statePaths.filter { fm.fileExists(atPath: $0) }
        findings.append(.init(
            name: "Zoom Local State",
            state: .healthy,
            confidence: 0.90,
            evidence: "Detected \(existing.count) known Zoom local-state paths. Presence alone is not treated as corruption."
        ))

        findings.append(commandFinding(
            name: "DNS Resolution",
            executable: "/usr/bin/dig",
            arguments: ["+short", "zoom.us"],
            healthyWhen: { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty },
            successEvidence: "zoom.us resolved successfully."
        ))

        findings.append(commandFinding(
            name: "Zoom HTTPS Reachability",
            executable: "/usr/bin/curl",
            arguments: ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "https://zoom.us"],
            healthyWhen: { output in
                let status = output.trimmingCharacters(in: .whitespacesAndNewlines)
                return status.hasPrefix("2") || status.hasPrefix("3")
            },
            successEvidence: "Zoom HTTPS endpoint returned a successful or redirect HTTP status."
        ))

        return DiagnosticReport(findings: findings)
    }

    private func commandFinding(
        name: String,
        executable: String,
        arguments: [String],
        healthyWhen: (String) -> Bool,
        successEvidence: String
    ) -> DiagnosticFinding {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(decoding: data, as: UTF8.self)
            let healthy = process.terminationStatus == 0 && healthyWhen(output)
            return .init(
                name: name,
                state: healthy ? .healthy : .failed,
                confidence: healthy ? 0.98 : 0.90,
                evidence: healthy ? successEvidence : "Command failed or returned unexpected output: \(output.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        } catch {
            return .init(name: name, state: .unknown, confidence: 0.60, evidence: "Unable to execute diagnostic: \(error.localizedDescription)")
        }
    }
}
