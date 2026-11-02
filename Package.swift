// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NumberCipher",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        // The cipher engine, shared by the Mac app and the iPhone/iPad app (ios/).
        .library(name: "CipherCore", targets: ["CipherCore"]),
    ],
    targets: [
        .target(
            name: "CipherCore",
            path: "Sources/CipherCore",
            swiftSettings: [.unsafeFlags(["-O", "-wmo"])]
        ),
        .executableTarget(
            name: "NumberCipher",
            dependencies: ["CipherCore"],
            path: "Sources/NumberCipher",
            swiftSettings: [.unsafeFlags(["-O", "-wmo"])]
        ),
    ]
)
