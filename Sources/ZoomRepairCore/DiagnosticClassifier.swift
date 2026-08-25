import Foundation

public enum DiagnosticClassifier {
    public static func summarize(_ findings: [DiagnosticFinding]) -> String {
        if findings.contains(where: { $0.state == .failed }) {
            return "One or more diagnostic checks failed. Repair or escalation is recommended."
        }
        if findings.contains(where: { $0.state == .suspect }) {
            return "No hard failure was proven, but one or more areas require investigation."
        }
        if findings.allSatisfy({ $0.state == .healthy }) {
            return "All implemented checks are healthy. If Zoom still rejects the operation, collect evidence for access/authentication escalation."
        }
        return "The current evidence is incomplete."
    }
}
