// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "keyfob",
  platforms: [.macOS(.v26)],
  targets: [
    .executableTarget(
      name: "keyfob",
      path: "Sources/keyfob",
      exclude: ["Age/LICENSE-age-plugin-se.txt"],
      swiftSettings: [.swiftLanguageMode(.v5)],
      linkerSettings: [.linkedFramework("LocalAuthentication")]
    )
  ]
)
