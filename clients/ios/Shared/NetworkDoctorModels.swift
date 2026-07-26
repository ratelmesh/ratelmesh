import Foundation

let networkDoctorReportSchema = "ratelmesh.diagnose.report/v2"
let networkDoctorPlanSchema = "ratelmesh.diagnose.repair-plan/v1"
let networkDoctorExecutionSchema = "ratelmesh.diagnose.repair-execution/v1"
let networkDoctorAPISchema = "ratelmesh.doctor.api/v1"
let networkDoctorAPIExecutionSchema = "ratelmesh.doctor.execution/v1"

struct NetworkDoctorDiagnosis: Codable, Equatable, Sendable {
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

struct NetworkDoctorReport: Codable, Equatable, Sendable {
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

struct NetworkDoctorSummary: Codable, Equatable, Sendable {
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

struct NetworkDoctorFinding: Codable, Equatable, Identifiable, Sendable {
    let code: String
    let severity: String
    let probe: String
    let summary: String
    let evidence: [String: String]?

    var id: String { "\(probe)|\(code)" }
}

struct NetworkDoctorProbe: Codable, Equatable, Identifiable, Sendable {
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

struct NetworkDoctorRepairPlan: Codable, Equatable, Sendable {
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

    var applicableRepairs: [NetworkDoctorRepair] {
        repairs.filter(\.applicable)
    }
}

struct NetworkDoctorRepair: Codable, Equatable, Identifiable, Sendable {
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

struct NetworkDoctorPrecondition: Codable, Equatable, Sendable {
    let id: String
    let description: String
    let ok: Bool
    let detail: String?
}

struct NetworkDoctorSnapshot: Codable, Equatable, Sendable {
    let kind: String
    let description: String?
}

struct NetworkDoctorStep: Codable, Equatable, Sendable {
    let op: String
    let params: [String: String]?
    let description: String?
}

struct NetworkDoctorExecutionReport: Codable, Equatable, Sendable {
    let schema: String
    let repairs: [NetworkDoctorRepairExecution]
}

struct NetworkDoctorExecutionEnvelope: Codable, Equatable, Sendable {
    let schema: String
    let execution: NetworkDoctorExecutionReport
}

struct NetworkDoctorRepairExecution: Codable, Equatable, Identifiable, Sendable {
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
    var needsManualAttention: Bool {
        status == "uncertain" || status == "rollback_failed"
    }
}

struct NetworkDoctorStepResult: Codable, Equatable, Sendable {
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

enum NetworkDoctorPhase: Equatable, Sendable {
    case idle
    case running
    case review
    case confirming
    case executing
    case finished
    case failed
}
