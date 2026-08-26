import Foundation
import ZoomRepairCore

let arguments = CommandLine.arguments.dropFirst()
let report = MacDiagnostics().run()

print("ZOOM 1132 DIAGNOSTIC TOOLKIT")
print(String(repeating: "=", count: 32))
for finding in report.findings {
    let confidence = String(format: "%.2f", finding.confidence)
    print("\(finding.name): \(finding.state.rawValue.uppercased()) [\(confidence)]")
    print("  category: \(finding.category.rawValue)")
    print("  \(finding.evidence)")
}

print("\nCategory assessments:")
for assessment in report.assessments where assessment.category != .unknown {
    print("  \(assessment.category.rawValue): concern \(String(format: "%.2f", assessment.concernScore)), confidence \(String(format: "%.2f", assessment.confidence))")
}

print("\nAssessment:")
print(DiagnosticClassifier.summarize(report.findings))

if let exportIndex = arguments.firstIndex(of: "--json") {
    let next = arguments.index(after: exportIndex)
    let path: String
    if next < arguments.endIndex && !arguments[next].hasPrefix("--") {
        path = arguments[next]
    } else {
        path = FileManager.default.currentDirectoryPath + "/zoom-1132-diagnostic.json"
    }

    do {
        let url = URL(fileURLWithPath: path)
        try JSONReportWriter.write(report, to: url)
        print("\nJSON report written to \(url.path)")
    } catch {
        fputs("Unable to write JSON report: \(error.localizedDescription)\n", stderr)
        exit(2)
    }
}
