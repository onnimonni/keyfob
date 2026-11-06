// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "keyfob",
  platforms: [.macOS(.v26)],
  products: [
    .executable(name: "keyfob", targets: ["keyfob"]),
    // sudo's Touch ID with a sheet naming the command and who asked
    .library(name: "pam_keyfob", type: .dynamic, targets: ["pam_keyfob"]),
  ],
  targets: [
    .executableTarget(
      name: "keyfob",
      path: "Sources/keyfob",
      exclude: ["Age/LICENSE-age-plugin-se.txt"],
      swiftSettings: [.swiftLanguageMode(.v5)],
      linkerSettings: [.linkedFramework("LocalAuthentication")]
    ),
    // Shares Caller.swift and GitRepository.swift with keyfob (symlinks)
    .target(
      name: "pam_keyfob",
      path: "Sources/pam_keyfob",
      swiftSettings: [.swiftLanguageMode(.v5)],
      linkerSettings: [.linkedFramework("LocalAuthentication")]
    ),
  ]
)
