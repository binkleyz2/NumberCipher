// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NumberCipher",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "NumberCipher",
            path: "Sources/NumberCipher",
            swiftSettings: [.unsafeFlags(["-O", "-wmo"])]
        )
    ]
)
