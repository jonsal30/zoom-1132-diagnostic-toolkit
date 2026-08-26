import Foundation

public enum FindingState: String, Codable, Sendable {
    case healthy
    case suspect
    case failed
    case unknown
}

public enum DiagnosticCategory: String, Codable, Sendable, CaseIterable {
    case installation
    case localState
    case network
    case access
    case unknown
}

public struct DiagnosticFinding: Codable, Sendable {
    public let name: String
    public let category: DiagnosticCategory
    public let state: FindingState
    public let confidence: Double
    public let evidence: String

    public init(
        name: String,
        category: DiagnosticCategory = .unknown,
        state: FindingState,
        confidence: Double,
        evidence: String
    ) {
        self.name = name
        self.category = category
        self.state = state
        self.confidence = min(max(confidence, 0), 1)
        self.evidence = evidence
    }
}

public struct CategoryAssessment: Codable, Sendable {
    public let category: DiagnosticCategory
    public let concernScore: Double
    public let confidence: Double

    public init(category: DiagnosticCategory, concernScore: Double, confidence: Double) {
        self.category = category
        self.concernScore = min(max(concernScore, 0), 1)
        self.confidence = min(max(confidence, 0), 1)
    }
}

public struct DiagnosticReport: Codable, Sendable {
    public let generatedAt: Date
    public let findings: [DiagnosticFinding]
    public let assessments: [CategoryAssessment]

    public init(
        generatedAt: Date = Date(),
        findings: [DiagnosticFinding],
        assessments: [CategoryAssessment] = []
    ) {
        self.generatedAt = generatedAt
        self.findings = findings
        self.assessments = assessments
    }
}
