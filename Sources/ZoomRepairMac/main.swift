import Foundation
import ZoomRepairCore

let report = MacDiagnostics().run()

print("ZOOM 1132 DIAGNOSTIC TOOLKIT")
print(String(repeating: "=", count: 32))
for finding in report.findings {
    let confidence = String(format: "%.2f", finding.confidence)
    print("\(finding.name): \(finding.state.rawValue.uppercased()) [\(confidence)]")
    print("  \(finding.evidence)")
}
print("\nAssessment:")
print(DiagnosticClassifier.summarize(report.findings))
