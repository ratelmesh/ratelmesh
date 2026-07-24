import Foundation

struct Peer: Codable, Identifiable {
    let name: String
    let meshIP: String
    let role: String
    let online: Bool
    let pathType: String
    let platform: String?
    let remoteAccessAllowed: Bool?

    var id: String { meshIP + "|" + name }
}

struct SelfNode: Codable {
    let name: String
    let meshIP: String
    let role: String?
}

struct ExitClient: Codable, Identifiable {
    let name: String
    let meshIP: String
    let state: String
    let online: Bool
    let lastSeen: String

    var id: String { meshIP + "|" + name }
}

struct MeshStatus: Codable {
    let state: String
    let enrollmentRequired: Bool
    let selfNode: SelfNode
    let peers: [Peer]
    let activeExit: String
    let selectedExit: String
    let exitTrafficVerified: Bool
    let killSwitch: Bool
    let internetFallback: Bool?
    let exitClients: [ExitClient]

    enum CodingKeys: String, CodingKey {
        case state, enrollmentRequired, peers, activeExit, selectedExit, exitTrafficVerified, killSwitch, internetFallback, exitClients
        case selfNode = "self"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(String.self, forKey: .state)
        enrollmentRequired = try container.decodeIfPresent(Bool.self, forKey: .enrollmentRequired) ?? false
        selfNode = try container.decode(SelfNode.self, forKey: .selfNode)
        peers = try container.decodeIfPresent([Peer].self, forKey: .peers) ?? []
        activeExit = try container.decode(String.self, forKey: .activeExit)
        selectedExit = try container.decodeIfPresent(String.self, forKey: .selectedExit) ?? activeExit
        exitTrafficVerified = try container.decodeIfPresent(Bool.self, forKey: .exitTrafficVerified) ?? false
        killSwitch = try container.decode(Bool.self, forKey: .killSwitch)
        internetFallback = try container.decodeIfPresent(Bool.self, forKey: .internetFallback)
        exitClients = try container.decodeIfPresent([ExitClient].self, forKey: .exitClients) ?? []
    }
}

func shouldShowEnrollment(status: MeshStatus?, locallyEnrolled: Bool) -> Bool {
    if let status {
        return status.enrollmentRequired
    }
    return !locallyEnrolled
}

enum LocalConnectionPhase: Equatable {
    case disconnected
    case enrollment
    case connecting
    case connected
}

func localConnectionPhase(status: MeshStatus?, reachable: Bool, locallyEnrolled: Bool) -> LocalConnectionPhase {
    guard reachable else { return .disconnected }
    if shouldShowEnrollment(status: status, locallyEnrolled: locallyEnrolled) { return .enrollment }
    return status?.state == "Running" ? .connected : .connecting
}
