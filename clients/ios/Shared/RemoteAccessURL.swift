import Darwin
import Foundation

enum RemoteAccessURL {
    static func make(scheme: String, address: String, port: UInt16) -> URL? {
        guard ["ssh", "rdp", "vnc"].contains(scheme),
              port > 0,
              !address.isEmpty,
              !address.contains("%"),
              address.utf8.count <= Int(INET6_ADDRSTRLEN) - 1,
              isNumericAddress(address) else {
            return nil
        }
        let host = address.contains(":") ? "[\(address)]" : address
        return URL(string: "\(scheme)://\(host):\(port)")
    }

    private static func isNumericAddress(_ address: String) -> Bool {
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return true
        }
        var ipv6 = in6_addr()
        return address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
    }
}
