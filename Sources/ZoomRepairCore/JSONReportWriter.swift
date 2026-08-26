import Foundation

public enum JSONReportWriter {
    public static func data(for report: DiagnosticReport, pretty: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys] : []
        return try encoder.encode(report)
    }

    public static func write(_ report: DiagnosticReport, to url: URL) throws {
        let data = try data(for: report)
        try data.write(to: url, options: .atomic)
    }
}
