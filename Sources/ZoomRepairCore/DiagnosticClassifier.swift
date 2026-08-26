import Foundation

public enum DiagnosticClassifier {
    public static func assessments(for findings: [DiagnosticFinding]) -> [CategoryAssessment] {
        DiagnosticCategory.allCases.map { category in
            let scoped = findings.filter { $0.category == category }
            guard !scoped.isEmpty else {
                return CategoryAssessment(category: category, concernScore: 0.5, confidence: 0.25)
            }

            let weighted = scoped.map { finding -> (Double, Double) in
                let concern: Double
                switch finding.state {
                case .healthy: concern = 0.0
                case .suspect: concern = 0.55
                case .failed: concern = 1.0
                case .unknown: concern = 0.5
                }
                return (concern * finding.confidence, finding.confidence)
            }

            let totalWeight = weighted.reduce(0) { $0 + $1.1 }
            let score = totalWeight > 0 ? weighted.reduce(0) { $0 + $1.0 } / totalWeight : 0.5
            let confidence = scoped.map(\.confidence).reduce(0, +) / Double(scoped.count)
            return CategoryAssessment(category: category, concernScore: score, confidence: confidence)
        }
    }

    public static func summarize(_ findings: [DiagnosticFinding]) -> String {
        let scores = assessments(for: findings)
        let ranked = scores
            .filter { $0.category != .unknown }
            .sorted { $0.concernScore > $1.concernScore }

        if let top = ranked.first, top.concernScore >= 0.70, top.confidence >= 0.60 {
            return "Highest-evidence concern: \(displayName(top.category)) (score \(format(top.concernScore)), confidence \(format(top.confidence)))."
        }

        let networkHealthy = findings
            .filter { $0.category == .network }
            .filter { $0.state == .healthy }
            .count >= 2
        let accessUnknown = findings.filter { $0.category == .access }.allSatisfy { $0.state != .failed }

        if networkHealthy && accessUnknown {
            return "Implemented network checks are healthy. If Zoom still returns 1132, preserve the report and escalate access/authentication evidence rather than repeatedly resetting the network."
        }

        if findings.contains(where: { $0.state == .failed }) {
            return "One or more diagnostic checks failed. Address the failed category before escalating."
        }
        if findings.contains(where: { $0.state == .suspect }) {
            return "No hard failure was proven, but one or more areas require investigation."
        }
        if findings.allSatisfy({ $0.state == .healthy }) {
            return "All implemented checks are healthy. Preserve evidence and investigate Zoom access/authentication behavior."
        }
        return "The current evidence is incomplete."
    }

    private static func displayName(_ category: DiagnosticCategory) -> String {
        switch category {
        case .installation: return "installation"
        case .localState: return "local Zoom state"
        case .network: return "network path"
        case .access: return "service/access"
        case .unknown: return "unknown"
        }
    }

    private static func format(_ value: Double) -> String {
        String(format: "%.2f", value)
    }
}
