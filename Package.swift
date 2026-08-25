// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Zoom1132DiagnosticToolkit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ZoomRepairCore", targets: ["ZoomRepairCore"]),
        .executable(name: "zoom-repair", targets: ["ZoomRepairMac"])
    ],
    targets: [
        .target(name: "ZoomRepairCore"),
        .executableTarget(name: "ZoomRepairMac", dependencies: ["ZoomRepairCore"]),
        .testTarget(name: "ZoomRepairCoreTests", dependencies: ["ZoomRepairCore"])
    ]
)
