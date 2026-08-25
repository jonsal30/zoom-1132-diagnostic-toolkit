import Foundation

public enum FindingState: String, Codable, Sendable {
    case healthy
    case suspect
    case failed
    case unknown
}

public struct DiagnosticFinding: Codable, Sendable {
    public let name: String
    public let state: FindingState
    public let confidence: Double
    public let evidence: String

    public init(name: String, state: FindingState, confidence: Double, evidence: String) {
        self.name = name
        self.state = state
        self.confidence = min(max(confidence, 0), 1)
        self.evidence = evidence
    }
}

public struct DiagnosticReport: Codable, Sendable {
    public let generatedAt: Date
    public let findings: [DiagnosticFinding]

    public init(generatedAt: Date = Date(), findings: [DiagnosticFinding]) {
        self.generatedAt = generatedAt
        self.findings = findings
    }
}
