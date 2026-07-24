import Darwin
import Foundation

/// Small CIDR algebra used to turn direct-route exceptions into WireGuard
/// allowed-IP complements. It supports IPv4 and IPv6 without expanding hosts.
struct IPPrefix: Equatable, Hashable, CustomStringConvertible, Sendable {
    private let family: Int32
    private var bytes: [UInt8]
    let length: Int

    init(_ value: String) throws {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]) else { throw MobileConfigurationError.invalidCIDR(value) }
        let address = String(parts[0])
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            guard (0...32).contains(length) else { throw MobileConfigurationError.invalidCIDR(value) }
            family = AF_INET
            bytes = withUnsafeBytes(of: v4.s_addr) { Array($0) }
        } else if inet_pton(AF_INET6, address, &v6) == 1 {
            guard (0...128).contains(length) else { throw MobileConfigurationError.invalidCIDR(value) }
            family = AF_INET6
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
        } else {
            throw MobileConfigurationError.invalidCIDR(value)
        }
        self.length = length
        maskHostBits()
    }

    private init(family: Int32, bytes: [UInt8], length: Int) {
        self.family = family
        self.bytes = bytes
        self.length = length
        maskHostBits()
    }

    var description: String {
        var copy = bytes
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rendered = copy.withUnsafeMutableBytes { raw in
            inet_ntop(family, raw.baseAddress, &output, socklen_t(output.count))
        }
        guard rendered != nil else { return "invalid/\(length)" }
        let end = output.firstIndex(of: 0) ?? output.endIndex
        return "\(String(decoding: output[..<end].map(UInt8.init(bitPattern:)), as: UTF8.self))/\(length)"
    }

    func subtracting(_ exclusions: [IPPrefix]) -> [IPPrefix] {
        exclusions.reduce([self]) { current, exclusion in
            current.flatMap { $0.subtracting(exclusion) }
        }
    }

    private func subtracting(_ exclusion: IPPrefix) -> [IPPrefix] {
        guard family == exclusion.family else { return [self] }
        if exclusion.contains(self) { return [] }
        guard contains(exclusion), length < bytes.count * 8 else { return [self] }
        let children = split()
        return children.flatMap { $0.subtracting(exclusion) }
    }

    private func contains(_ other: IPPrefix) -> Bool {
        guard family == other.family, length <= other.length else { return false }
        let wholeBytes = length / 8
        if wholeBytes > 0, bytes[..<wholeBytes] != other.bytes[..<wholeBytes] { return false }
        let remaining = length % 8
        guard remaining > 0 else { return true }
        let mask = UInt8.max << (8 - remaining)
        return bytes[wholeBytes] & mask == other.bytes[wholeBytes] & mask
    }

    private func split() -> [IPPrefix] {
        let childLength = length + 1
        var upper = bytes
        let byteIndex = length / 8
        let bitIndex = 7 - (length % 8)
        upper[byteIndex] |= UInt8(1 << bitIndex)
        return [
            IPPrefix(family: family, bytes: bytes, length: childLength),
            IPPrefix(family: family, bytes: upper, length: childLength)
        ]
    }

    private mutating func maskHostBits() {
        let full = length / 8
        let remaining = length % 8
        if remaining > 0 {
            bytes[full] &= UInt8.max << (8 - remaining)
        }
        let firstHostByte = full + (remaining > 0 ? 1 : 0)
        if firstHostByte < bytes.count {
            for index in firstHostByte..<bytes.count { bytes[index] = 0 }
        }
    }
}
