import CryptoKit
import Foundation

/// RFC 4251 encoding used by the SSH agent protocol and SSHSIG.
struct SSHWriter {
  var data = Data()

  mutating func byte(_ value: UInt8) { data.append(value) }

  mutating func uint32(_ value: UInt32) {
    withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
  }

  mutating func string(_ value: Data) {
    uint32(UInt32(value.count))
    data.append(value)
  }

  mutating func string(_ value: String) { string(Data(value.utf8)) }

  /// Unsigned big-endian integer as an SSH mpint.
  mutating func mpint(_ value: Data) {
    var bytes = [UInt8](value.drop(while: { $0 == 0 }))
    if let first = bytes.first, first & 0x80 != 0 {
      bytes.insert(0, at: 0)
    }
    string(Data(bytes))
  }
}

struct SSHReader {
  struct Truncated: Error {}

  private let bytes: [UInt8]
  private var offset = 0

  init(_ data: Data) { bytes = [UInt8](data) }

  var isAtEnd: Bool { offset == bytes.count }

  mutating func byte() throws -> UInt8 {
    guard offset < bytes.count else { throw Truncated() }
    defer { offset += 1 }
    return bytes[offset]
  }

  mutating func uint32() throws -> UInt32 {
    guard bytes.count - offset >= 4 else { throw Truncated() }
    defer { offset += 4 }
    return bytes[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
  }

  mutating func string() throws -> Data {
    let count = Int(try uint32())
    guard bytes.count - offset >= count else { throw Truncated() }
    defer { offset += count }
    return Data(bytes[offset..<offset + count])
  }

  mutating func text() throws -> String {
    String(decoding: try string(), as: UTF8.self)
  }
}

enum SSHKey {
  static let type = "ecdsa-sha2-nistp256"

  static func blob(_ key: P256.Signing.PublicKey) -> Data {
    var writer = SSHWriter()
    writer.string(type)
    writer.string("nistp256")
    writer.string(key.x963Representation)
    return writer.data
  }

  static func authorizedKey(_ key: P256.Signing.PublicKey, comment: String) -> String {
    "\(type) \(blob(key).base64EncodedString()) \(comment)"
  }

  static func signature(_ signature: P256.Signing.ECDSASignature) -> Data {
    let raw = signature.rawRepresentation
    var inner = SSHWriter()
    inner.mpint(raw.prefix(32))
    inner.mpint(raw.suffix(32))
    var writer = SSHWriter()
    writer.string(type)
    writer.string(inner.data)
    return writer.data
  }
}
