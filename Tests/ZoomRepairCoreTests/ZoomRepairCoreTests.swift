import XCTest
@testable import ZoomRepairCore

final class ZoomRepairCoreTests: XCTestCase {
    func testConfidenceIsClamped() {
        let finding = DiagnosticFinding(name: "Test", state: .healthy, confidence: 2.0, evidence: "ok")
        XCTAssertEqual(finding.confidence, 1.0)
    }

    func testClassifierPrefersFailure() {
        let findings = [
            DiagnosticFinding(name: "DNS", state: .healthy, confidence: 0.9, evidence: "ok"),
            DiagnosticFinding(name: "Install", state: .failed, confidence: 0.9, evidence: "missing")
        ]
        XCTAssertTrue(DiagnosticClassifier.summarize(findings).contains("failed"))
    }
}
