import Darwin
import Foundation

struct RemoteService: Codable, Equatable, Identifiable {
    let kind: String
    let port: UInt16
    let targetMeshIp: String

    var id: String { "\(kind)|\(port)|\(targetMeshIp)" }
}

enum RemoteAccessURL {
    static func make(_ service: RemoteService) -> URL? {
        guard ["ssh", "rdp", "vnc"].contains(service.kind),
              service.port > 0,
              !service.targetMeshIp.isEmpty,
              !service.targetMeshIp.contains("%"),
              service.targetMeshIp.utf8.count <= Int(INET6_ADDRSTRLEN) - 1,
              isNumericAddress(service.targetMeshIp) else {
            return nil
        }
        let host = service.targetMeshIp.contains(":")
            ? "[\(service.targetMeshIp)]"
            : service.targetMeshIp
        return URL(string: "\(service.kind)://\(host):\(service.port)")
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

struct Peer: Codable, Identifiable {
    let name: String
    let meshIP: String
    let role: String
    let online: Bool
    let pathType: String
    let platform: String?
    let remoteAccessAllowed: Bool?
    let remoteServices: [RemoteService]?

    var id: String { meshIP + "|" + name }

    var authorizedRemoteServices: [RemoteService] {
        guard remoteAccessAllowed == true, !meshIP.isEmpty else { return [] }
        return (remoteServices ?? []).filter {
            ["ssh", "rdp", "vnc"].contains($0.kind) &&
                $0.port > 0 &&
                $0.targetMeshIp == meshIP
        }
    }
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

let networkDoctorReportSchema = "ratelmesh.diagnose.report/v2"
let networkDoctorPlanSchema = "ratelmesh.diagnose.repair-plan/v1"
let networkDoctorExecutionSchema = "ratelmesh.diagnose.repair-execution/v1"
let networkDoctorAPISchema = "ratelmesh.doctor.api/v1"
let networkDoctorAPIExecutionSchema = "ratelmesh.doctor.execution/v1"

struct NetworkDoctorDiagnosis: Codable, Equatable {
    let schema: String
    let report: NetworkDoctorReport
    let plan: NetworkDoctorRepairPlan
    let availableRepairs: [String]
    let planID: String
    let planExpiresAt: String?

    enum CodingKeys: String, CodingKey {
        case schema, report, plan, availableRepairs, planID, planExpiresAt
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        report = try values.decode(NetworkDoctorReport.self, forKey: .report)
        plan = try values.decode(NetworkDoctorRepairPlan.self, forKey: .plan)
        availableRepairs = try values.decodeIfPresent([String].self, forKey: .availableRepairs) ?? []
        planID = try values.decodeIfPresent(String.self, forKey: .planID) ?? ""
        planExpiresAt = try values.decodeIfPresent(String.self, forKey: .planExpiresAt)
    }

    var executableRepairs: [NetworkDoctorRepair] {
        let allowed = Set(availableRepairs)
        return plan.repairs.filter { $0.applicable && allowed.contains($0.action) }
    }
}

struct NetworkDoctorReport: Codable, Equatable {
    let schema: String
    let generatedAt: String
    let summary: NetworkDoctorSummary
    let findings: [NetworkDoctorFinding]
    let probes: [NetworkDoctorProbe]

    enum CodingKeys: String, CodingKey {
        case schema, summary, findings, probes
        case generatedAt = "generated_at"
    }

    func redactedJSON() throws -> Data {
        guard schema == networkDoctorReportSchema else {
            throw NetworkDoctorContractError.unsupportedSchema
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

struct NetworkDoctorSummary: Codable, Equatable {
    let ok: Bool
    let worstSeverity: String
    let totalFindings: Int
    let countsBySeverity: [String: Int]

    enum CodingKeys: String, CodingKey {
        case ok
        case worstSeverity = "worst_severity"
        case totalFindings = "total_findings"
        case countsBySeverity = "counts_by_severity"
    }
}

struct NetworkDoctorFinding: Codable, Equatable, Identifiable {
    let code: String
    let severity: String
    let probe: String
    let summary: String
    let evidence: [String: String]?
    var id: String { "\(probe)|\(code)" }
}

struct NetworkDoctorProbe: Codable, Equatable, Identifiable {
    let probe: String
    let status: String
    let durationMS: Int64
    let findings: Int

    enum CodingKeys: String, CodingKey {
        case probe, status, findings
        case durationMS = "duration_ms"
    }
    var id: String { probe }
}

struct NetworkDoctorRepairPlan: Codable, Equatable {
    let schema: String
    let dryRun: Bool
    let repairs: [NetworkDoctorRepair]

    enum CodingKeys: String, CodingKey {
        case schema, repairs
        case dryRun = "dry_run"
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        dryRun = try values.decode(Bool.self, forKey: .dryRun)
        repairs = try values.decodeIfPresent([NetworkDoctorRepair].self, forKey: .repairs) ?? []
    }
    var applicableRepairs: [NetworkDoctorRepair] { repairs.filter(\.applicable) }
}

struct NetworkDoctorRepair: Codable, Equatable, Identifiable {
    let action: String
    let title: String
    let addresses: [String]
    let applicable: Bool
    let preconditions: [NetworkDoctorPrecondition]?
    let snapshots: [NetworkDoctorSnapshot]?
    let apply: [NetworkDoctorStep]
    let rollback: [NetworkDoctorStep]?
    let postconditions: [String]?
    var id: String { action }
}

struct NetworkDoctorPrecondition: Codable, Equatable {
    let id: String
    let description: String
    let ok: Bool
    let detail: String?
}

struct NetworkDoctorSnapshot: Codable, Equatable {
    let kind: String
    let description: String?
}

struct NetworkDoctorStep: Codable, Equatable {
    let op: String
    let params: [String: String]?
    let description: String?
}

struct NetworkDoctorExecutionReport: Codable, Equatable {
    let schema: String
    let repairs: [NetworkDoctorRepairExecution]
}

struct NetworkDoctorExecutionEnvelope: Codable, Equatable {
    let schema: String
    let execution: NetworkDoctorExecutionReport
}

struct NetworkDoctorRepairExecution: Codable, Equatable, Identifiable {
    let action: String
    let status: String
    let applied: [NetworkDoctorStepResult]?
    let rolledBack: [NetworkDoctorStepResult]?
    let snapshots: [String]?

    enum CodingKeys: String, CodingKey {
        case action, status, applied, snapshots
        case rolledBack = "rolled_back"
    }
    var id: String { action }
    var needsManualAttention: Bool { status == "uncertain" || status == "rollback_failed" }
}

struct NetworkDoctorStepResult: Codable, Equatable {
    let op: String
    let ok: Bool
}

enum NetworkDoctorContractError: Error, Equatable {
    case unavailable
    case invalidResponse
    case responseTooLarge
    case unsupportedSchema
    case noApplicableRepairs
}

enum NetworkDoctorPhase: Equatable {
    case idle, running, review, confirming, executing, finished, failed
}
