import XCTest
@testable import ZoomRepairCore

final class ZoomRepairCoreTests: XCTestCase {
    func testConfidenceIsClamped() {
        let finding = DiagnosticFinding(name: "Test", state: .healthy, confidence: 2.0, evidence: "ok")
        XCTAssertEqual(finding.confidence, 1.0)
    }

    func testClassifierPrefersFailure() {
        let findings = [
            DiagnosticFinding(name: "DNS", category: .network, state: .healthy, confidence: 0.9, evidence: "ok"),
            DiagnosticFinding(name: "Install", category: .installation, state: .failed, confidence: 0.9, evidence: "missing")
        ]
        XCTAssertTrue(DiagnosticClassifier.summarize(findings).contains("installation"))
    }

    func testHealthyNetworkProducesLowConcern() throws {
        let findings = [
            DiagnosticFinding(name: "DNS", category: .network, state: .healthy, confidence: 0.99, evidence: "ok"),
            DiagnosticFinding(name: "HTTPS", category: .network, state: .healthy, confidence: 0.99, evidence: "ok")
        ]
        let network = try XCTUnwrap(DiagnosticClassifier.assessments(for: findings).first { $0.category == .network })
        XCTAssertEqual(network.concernScore, 0.0, accuracy: 0.001)
        XCTAssertGreaterThan(network.confidence, 0.95)
    }

    func testFailedInstallationProducesHighConcern() throws {
        let findings = [
            DiagnosticFinding(name: "Install", category: .installation, state: .failed, confidence: 0.99, evidence: "missing")
        ]
        let install = try XCTUnwrap(DiagnosticClassifier.assessments(for: findings).first { $0.category == .installation })
        XCTAssertEqual(install.concernScore, 1.0, accuracy: 0.001)
    }

    func testJSONReportContainsAssessments() throws {
        let finding = DiagnosticFinding(name: "DNS", category: .network, state: .healthy, confidence: 0.99, evidence: "resolved")
        let assessments = DiagnosticClassifier.assessments(for: [finding])
        let report = DiagnosticReport(findings: [finding], assessments: assessments)
        let data = try JSONReportWriter.data(for: report)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains("assessments"))
        XCTAssertTrue(text.contains("network"))
    }
}
