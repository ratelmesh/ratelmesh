import Darwin
import Foundation
import Security

enum EnrollmentCode {
    static func normalized(_ input: String) -> String {
        input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func valid(_ input: String) -> Bool {
        normalized(input).range(
            of: #"^ratelmesh-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$"#,
            options: .regularExpression
        ) != nil
    }
}

enum EnrollmentFailure: LocalizedError {
    case authorization(OSStatus)
    case unavailable
    case execution(OSStatus)
    case failed(String)

    var errorDescription: String? {
        switch self {
        case let .authorization(status):
            return "Administrator authorization failed (\(status))."
        case .unavailable:
            return "The privileged enrollment service is unavailable on this Mac."
        case let .execution(status):
            return "The enrollment helper could not start (\(status))."
        case let .failed(detail):
            return detail.isEmpty ? "Enrollment did not complete." : detail
        }
    }
}

private typealias ExecuteWithPrivileges = @convention(c) (
    AuthorizationRef?,
    UnsafePointer<CChar>,
    AuthorizationFlags,
    UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    UnsafeMutablePointer<UnsafeMutablePointer<FILE>?>?
) -> OSStatus

enum PrivilegedEnrollment {
    private static let helper = "/usr/local/ratelmesh/bin/ratelmesh-enroll"

    static func run(code input: String) async throws -> String {
        let code = EnrollmentCode.normalized(input)
        guard EnrollmentCode.valid(code) else {
            throw EnrollmentFailure.failed("Invalid code format. Expected ratelmesh-xxxx-xxxx-xxxx.")
        }
        return try await Task.detached(priority: .userInitiated) {
            try execute(code: code)
        }.value
    }

    private static func execute(code: String) throws -> String {
        var authorization: AuthorizationRef?
        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
        let authStatus = AuthorizationCreate(nil, nil, flags, &authorization)
        guard authStatus == errAuthorizationSuccess, let authorization else {
            throw EnrollmentFailure.authorization(authStatus)
        }
        defer { AuthorizationFree(authorization, []) }

        guard let handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY),
              let symbol = dlsym(handle, "AuthorizationExecuteWithPrivileges") else {
            throw EnrollmentFailure.unavailable
        }
        defer { dlclose(handle) }
        let execute = unsafeBitCast(symbol, to: ExecuteWithPrivileges.self)

        var pipe: UnsafeMutablePointer<FILE>?
        let status = helper.withCString { path in
            execute(authorization, path, [], nil, &pipe)
        }
        guard status == errAuthorizationSuccess, let pipe else {
            throw EnrollmentFailure.execution(status)
        }

        let descriptor = fileno(pipe)
        let request = Data((code + "\n").utf8)
        let sent = request.withUnsafeBytes { bytes in
            Darwin.write(descriptor, bytes.baseAddress, bytes.count)
        }
        guard sent == request.count else {
            fclose(pipe)
            throw EnrollmentFailure.failed("The enrollment code could not be delivered to the system helper.")
        }
        shutdown(descriptor, SHUT_WR)

        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count <= 0 { break }
            output.append(buffer, count: count)
        }
        fclose(pipe)

        let text = String(decoding: output, as: UTF8.self)
        guard text.contains("RatelMesh enrollment completed.") else {
            let detail = text
                .split(separator: "\n")
                .suffix(4)
                .joined(separator: "\n")
            throw EnrollmentFailure.failed(detail)
        }
        return text
    }
}
