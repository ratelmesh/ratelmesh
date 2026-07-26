import Foundation

@MainActor
protocol NetworkDoctorServicing {
    func diagnose() async throws -> NetworkDoctorDiagnosis
    func execute(planID: String, action: String, confirmed: Bool) async throws -> NetworkDoctorExecutionReport
}

@MainActor
final class NetworkDoctorStore: ObservableObject {
    @Published private(set) var phase: NetworkDoctorPhase = .idle
    @Published private(set) var diagnosis: NetworkDoctorDiagnosis?
    @Published private(set) var execution: NetworkDoctorExecutionReport?
    @Published private(set) var error: NetworkDoctorContractError?

    private let service: NetworkDoctorServicing

    init(service: NetworkDoctorServicing) {
        self.service = service
    }

    var canRepair: Bool {
        phase == .review && diagnosis?.executableRepairs.isEmpty == false
    }

    func run() async {
        guard phase != .running && phase != .executing else { return }
        phase = .running
        diagnosis = nil
        execution = nil
        error = nil
        do {
            let result = try await service.diagnose()
            guard result.schema == networkDoctorAPISchema,
                  result.report.schema == networkDoctorReportSchema,
                  result.plan.schema == networkDoctorPlanSchema,
                  result.plan.dryRun,
                  result.planID.utf8.count <= 256,
                  (result.executableRepairs.isEmpty || !result.planID.isEmpty) else {
                throw NetworkDoctorContractError.unsupportedSchema
            }
            diagnosis = result
            phase = .review
        } catch {
            self.error = Self.contractError(error)
            phase = .failed
        }
    }

    func requestConfirmation() {
        guard canRepair else {
            error = .noApplicableRepairs
            phase = .failed
            return
        }
        phase = .confirming
    }

    func cancelConfirmation() {
        guard diagnosis != nil else { return }
        phase = .review
    }

    func confirmAndRepair() async {
        guard phase == .confirming, let diagnosis,
              let repair = diagnosis.executableRepairs.first else {
            error = .noApplicableRepairs
            phase = .failed
            return
        }
        phase = .executing
        do {
            let result = try await service.execute(
                planID: diagnosis.planID,
                action: repair.action,
                confirmed: true
            )
            guard result.schema == networkDoctorExecutionSchema else {
                throw NetworkDoctorContractError.unsupportedSchema
            }
            execution = result
            phase = .finished
        } catch {
            self.error = Self.contractError(error)
            phase = .failed
        }
    }

    func reset() {
        phase = .idle
        diagnosis = nil
        execution = nil
        error = nil
    }

    private static func contractError(_ error: Error) -> NetworkDoctorContractError {
        error as? NetworkDoctorContractError ?? .unavailable
    }
}

@MainActor
final class TunnelNetworkDoctorService: NetworkDoctorServicing {
    private let tunnel: TunnelController

    init(tunnel: TunnelController) {
        self.tunnel = tunnel
    }

    func diagnose() async throws -> NetworkDoctorDiagnosis {
        let data = try await tunnel.networkDoctorDiagnose()
        return try decode(NetworkDoctorDiagnosis.self, from: data)
    }

    func execute(planID: String, action: String, confirmed: Bool) async throws -> NetworkDoctorExecutionReport {
        guard confirmed else { throw NetworkDoctorContractError.invalidResponse }
        let data = try await tunnel.networkDoctorExecute(
            planID: planID,
            action: action,
            confirmed: true
        )
        let envelope = try decode(NetworkDoctorExecutionEnvelope.self, from: data)
        guard envelope.schema == networkDoctorAPIExecutionSchema else {
            throw NetworkDoctorContractError.unsupportedSchema
        }
        return envelope.execution
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard !data.isEmpty else { throw NetworkDoctorContractError.unavailable }
        guard data.count <= 1_048_576 else { throw NetworkDoctorContractError.responseTooLarge }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw NetworkDoctorContractError.invalidResponse
        }
    }
}
