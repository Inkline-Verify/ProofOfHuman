// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "InklineHelper",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "InklineCore"),
        .executableTarget(
            name: "InklinePresenceHelper",
            dependencies: ["InklineCore"]
        ),
        .testTarget(
            name: "InklineCoreTests",
            dependencies: ["InklineCore"]
        ),
    ]
)
