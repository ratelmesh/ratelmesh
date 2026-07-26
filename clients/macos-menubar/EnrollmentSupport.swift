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

enum EnrollmentFailure: Error {
    case invalidCode
    case authorization
    case unavailable
    case execution
    case delivery
    case rejected
}

enum TrustedPrivilegedHelper {
    static func validate(_ path: String) throws {
        guard path.hasPrefix("/"), !path.contains("/../") else {
            throw EnrollmentFailure.unavailable
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        var current = ""
        for (index, component) in components.enumerated() {
            current += "/\(component)"
            var metadata = stat()
            guard lstat(current, &metadata) == 0,
                  metadata.st_uid == 0,
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
                  access(current, W_OK) != 0 else {
                throw EnrollmentFailure.unavailable
            }
            let kind = metadata.st_mode & S_IFMT
            let expected = index == components.count - 1 ? S_IFREG : S_IFDIR
            guard kind == expected else {
                throw EnrollmentFailure.unavailable
            }
        }
        guard access(path, X_OK) == 0 else {
            throw EnrollmentFailure.unavailable
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
    private static let maximumOutputBytes = 64 * 1024

    static func run(code input: String) async throws {
        let code = EnrollmentCode.normalized(input)
        guard EnrollmentCode.valid(code) else {
            throw EnrollmentFailure.invalidCode
        }
        return try await Task.detached(priority: .userInitiated) {
            try execute(code: code)
        }.value
    }

    private static func execute(code: String) throws {
        try TrustedPrivilegedHelper.validate(helper)
        var authorization: AuthorizationRef?
        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
        let authStatus = AuthorizationCreate(nil, nil, flags, &authorization)
        guard authStatus == errAuthorizationSuccess, let authorization else {
            throw EnrollmentFailure.authorization
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
            throw EnrollmentFailure.execution
        }

        let descriptor = fileno(pipe)
        var request = Data((code + "\n").utf8)
        do {
            try writeAll(request, to: descriptor)
        } catch {
            request.resetBytes(in: request.startIndex..<request.endIndex)
            fclose(pipe)
            throw EnrollmentFailure.delivery
        }
        request.resetBytes(in: request.startIndex..<request.endIndex)
        shutdown(descriptor, SHUT_WR)

        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                fclose(pipe)
                throw EnrollmentFailure.delivery
            }
            guard output.count <= maximumOutputBytes - count else {
                fclose(pipe)
                throw EnrollmentFailure.delivery
            }
            output.append(buffer, count: count)
        }
        fclose(pipe)

        let success = Data("RatelMesh enrollment completed.".utf8)
        guard output.range(of: success) != nil else {
            throw EnrollmentFailure.rejected
        }
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var pointer = rawBuffer.baseAddress else { return }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, pointer, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw EnrollmentFailure.delivery
                }
                guard written > 0 else { throw EnrollmentFailure.delivery }
                remaining -= written
                pointer = pointer.advanced(by: written)
            }
        }
    }
}
