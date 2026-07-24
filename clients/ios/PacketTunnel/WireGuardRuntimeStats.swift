import Foundation

struct WireGuardPeerStat: Codable, Equatable {
    let publicKey: String
    let latestHandshakeUnix: Int64
    let rxBytes: UInt64
}

enum WireGuardRuntimeStats {
    static func decode(_ uapi: String) -> [WireGuardPeerStat] {
        var result: [WireGuardPeerStat] = []
        var key: String?
        var handshake: Int64 = 0
        var rx: UInt64 = 0

        func appendCurrent() {
            guard let key else { return }
            result.append(WireGuardPeerStat(publicKey: key, latestHandshakeUnix: handshake, rxBytes: rx))
        }

        for line in uapi.split(separator: "\n") {
            let pair = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2 else { continue }
            switch pair[0] {
            case "public_key":
                appendCurrent()
                key = base64Key(fromHex: String(pair[1]))
                handshake = 0
                rx = 0
            case "last_handshake_time_sec": handshake = Int64(pair[1]) ?? 0
            case "rx_bytes": rx = UInt64(pair[1]) ?? 0
            default: continue
            }
        }
        appendCurrent()
        return result
    }

    private static func base64Key(fromHex hex: String) -> String? {
        guard hex.count == 64 else { return nil }
        var data = Data(capacity: 32)
        var index = hex.startIndex
        for _ in 0..<32 {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data.base64EncodedString()
    }
}

