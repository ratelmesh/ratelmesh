import CryptoKit
import Foundation

@main
private struct UpdateSecurityTests {
    static func main() async throws {
        guard CommandLine.arguments.count == 6 else { throw TestFailure.arguments }
        let manifestURL = URL(fileURLWithPath: CommandLine.arguments[1])
        let publicKey = CommandLine.arguments[2]
        let pqPublicKey = CommandLine.arguments[3]
        let verifierURL = URL(fileURLWithPath: CommandLine.arguments[4])
        let packageURL = URL(fileURLWithPath: CommandLine.arguments[5])
        let manifest = try JSONDecoder().decode(UpdateManifest.self, from: Data(contentsOf: manifestURL))
		func verify(_ candidate: UpdateManifest) throws {
			try UpdateSecurity.verify(candidate, publicKeyBase64: publicKey, pqPublicKeyBase64: pqPublicKey, pqVerifierURL: verifierURL)
		}

        try verify(manifest)
        guard try UpdateSecurity.sha256(of: packageURL) == manifest.sha256 else { throw TestFailure.checksum }
        guard UpdateSecurity.compareVersions("0.1.26", "0.1.27") == .orderedAscending else { throw TestFailure.version }
        guard UpdateSecurity.compareVersions("0.1.27", "0.1.27") == .orderedSame else { throw TestFailure.version }
        guard UpdateSecurity.compareVersions("0.2.0", "0.1.99") == .orderedDescending else { throw TestFailure.version }
        guard UpdateSecurity.manifestIsFresh(Date()),
              !UpdateSecurity.manifestIsFresh(Date().addingTimeInterval(-31 * 24 * 60 * 60)),
              !UpdateSecurity.manifestIsFresh(Date().addingTimeInterval(10 * 60))
        else { throw TestFailure.freshness }

        let allowedResponse = HTTPURLResponse(
            url: URL(string: manifest.url)!,
            statusCode: 200,
            httpVersion: nil,
            headerFields: nil
        )!
        let redirectedResponse = HTTPURLResponse(
            url: URL(string: "https://example.com/update.pkg")!,
            statusCode: 200,
            httpVersion: nil,
            headerFields: nil
        )!
        guard UpdateSecurity.responseIsAllowed(allowedResponse),
              !UpdateSecurity.responseIsAllowed(redirectedResponse)
        else { throw TestFailure.responseHost }
        guard UpdateFailure.classify(URLError(.cannotConnectToHost)) == .network,
              UpdateFailure.classify(UpdateSecurityError.invalidPublicKey) == .configuration,
              UpdateFailure.classify(UpdateSecurityError.invalidSignature) == .verification,
              UpdateFailure.classify(UpdateSecurityError.checksumMismatch) == .checksum,
              UpdateFailure.network.message(chinese: false).contains("official update service"),
              UpdateFailure.configuration.message(chinese: true).contains("安全配置缺失")
        else { throw TestFailure.failureClassification }

        let tamperedPackageURL = packageURL.appendingPathExtension("tampered")
        var tamperedPackage = try Data(contentsOf: packageURL)
        tamperedPackage.append(0)
        try tamperedPackage.write(to: tamperedPackageURL, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tamperedPackageURL) }
        guard try UpdateSecurity.sha256(of: tamperedPackageURL) != manifest.sha256 else {
            throw TestFailure.tamperedPackage
        }

        let tampered = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: manifest.url,
            sha256: manifest.sha256,
            size: manifest.size + 1,
            publishedAt: manifest.publishedAt,
            signature: manifest.signature,
            pqSignature: manifest.pqSignature
        )
        do {
            try verify(tampered)
            throw TestFailure.tamperAccepted
        } catch UpdateSecurityError.invalidSignature {
            // Expected.
        }

        let unsafeURL = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: "https://example.com/RatelMesh.pkg",
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: manifest.signature,
            pqSignature: manifest.pqSignature
        )
        do {
            try verify(unsafeURL)
            throw TestFailure.unsafeURLAccepted
        } catch UpdateSecurityError.unsafeURL {
            // Expected.
        }

        let wrongOfficialPath = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: "https://download.ratelmesh.com/download/other.pkg",
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: manifest.signature,
            pqSignature: manifest.pqSignature
        )
        do {
            try verify(wrongOfficialPath)
            throw TestFailure.unsafeURLAccepted
        } catch UpdateSecurityError.unsafeURL {
            // Expected.
        }

        do {
            try UpdateSecurity.verify(manifest, publicKeyBase64: Data(repeating: 0, count: 31).base64EncodedString())
            throw TestFailure.invalidKeyAccepted
        } catch UpdateSecurityError.invalidPublicKey {
            // Expected.
        }

        var badSignatureBytes = Data(base64Encoded: manifest.signature)!
        badSignatureBytes[badSignatureBytes.startIndex] ^= 1
        let badSignature = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: manifest.url,
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: badSignatureBytes.base64EncodedString(),
            pqSignature: manifest.pqSignature
        )
        do {
            try verify(badSignature)
            throw TestFailure.invalidSignatureAccepted
        } catch UpdateSecurityError.invalidSignature {
            // Expected.
        }

        do {
            try UpdateSecurity.verify(
                manifest,
                publicKeyBase64: publicKey,
                pqPublicKeyBase64: "",
                pqVerifierURL: verifierURL
            )
            throw TestFailure.invalidPQKeyAccepted
        } catch UpdateSecurityError.invalidPQSignature {
            // Expected.
        }

        let missingPQSignature = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: manifest.url,
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: manifest.signature,
            pqSignature: nil
        )
        do {
            try verify(missingPQSignature)
            throw TestFailure.invalidPQSignatureAccepted
        } catch UpdateSecurityError.invalidPQSignature {
            // Expected.
        }

        guard let pqSignature = manifest.pqSignature,
              var badPQSignatureBytes = Data(base64Encoded: pqSignature)
        else { throw TestFailure.invalidPQSignatureAccepted }
        badPQSignatureBytes[badPQSignatureBytes.startIndex] ^= 1
        let badPQSignature = UpdateManifest(
            schema: manifest.schema,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: manifest.url,
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: manifest.signature,
            pqSignature: badPQSignatureBytes.base64EncodedString()
        )
        do {
            try verify(badPQSignature)
            throw TestFailure.invalidPQSignatureAccepted
        } catch UpdateSecurityError.invalidPQSignature {
            // Expected.
        }

        let downgradePrivateKey = Curve25519.Signing.PrivateKey()
        let unsignedDowngrade = UpdateManifest(
            schema: 1,
            platform: manifest.platform,
            version: manifest.version,
            minimumSystemVersion: manifest.minimumSystemVersion,
            url: manifest.url,
            sha256: manifest.sha256,
            size: manifest.size,
            publishedAt: manifest.publishedAt,
            signature: "",
            pqSignature: nil
        )
        let downgrade = UpdateManifest(
            schema: unsignedDowngrade.schema,
            platform: unsignedDowngrade.platform,
            version: unsignedDowngrade.version,
            minimumSystemVersion: unsignedDowngrade.minimumSystemVersion,
            url: unsignedDowngrade.url,
            sha256: unsignedDowngrade.sha256,
            size: unsignedDowngrade.size,
            publishedAt: unsignedDowngrade.publishedAt,
            signature: try downgradePrivateKey.signature(
                for: unsignedDowngrade.canonicalData
            ).base64EncodedString(),
            pqSignature: nil
        )
        do {
            try UpdateSecurity.verify(
                downgrade,
                publicKeyBase64: downgradePrivateKey.publicKey.rawRepresentation.base64EncodedString()
            )
            throw TestFailure.schemaDowngradeAccepted
        } catch UpdateSecurityError.malformedManifest {
            // Expected: Ed25519-valid legacy manifests cannot bypass ML-DSA.
        }

        try await testBoundedTransfers()
        try testAtomicCacheReplacementPreservesOldPackage(
            packageURL: packageURL,
            manifest: manifest
        )

        print("macOS updater security tests passed")
    }

    private static func testBoundedTransfers() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StreamingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let request = URLRequest(
            url: URL(string: "https://download.ratelmesh.com/download/test")!
        )

        StreamingURLProtocol.response = .init(
            headers: [:],
            chunks: [Data(repeating: 1, count: 8), Data([2])]
        )
        do {
            _ = try await BoundedHTTPTransfer.data(for: request, using: session, limit: 8)
            throw TestFailure.chunkedOversizeAccepted
        } catch let failure as TestFailure {
            throw failure
        } catch {
            // Expected: an unbounded/chunked body is cancelled at byte 9.
        }

        StreamingURLProtocol.response = .init(
            headers: ["Content-Length": "1"],
            chunks: [Data(repeating: 1, count: 9)]
        )
        do {
            _ = try await BoundedHTTPTransfer.download(for: request, using: session, limit: 8)
            throw TestFailure.lyingLengthAccepted
        } catch let failure as TestFailure {
            throw failure
        } catch {
            // Expected: the signed byte ceiling overrides a lying header.
        }

        StreamingURLProtocol.response = .init(
            headers: ["Content-Length": "9"],
            chunks: []
        )
        do {
            _ = try await BoundedHTTPTransfer.data(for: request, using: session, limit: 8)
            throw TestFailure.declaredOversizeAccepted
        } catch let failure as TestFailure {
            throw failure
        } catch {
            // Expected: oversized declared bodies are rejected before reading.
        }

        StreamingURLProtocol.response = .init(
            headers: ["Content-Length": "8"],
            chunks: [Data(repeating: 1, count: 8)]
        )
        let (data, _) = try await BoundedHTTPTransfer.data(for: request, using: session, limit: 8)
        guard data.count == 8 else { throw TestFailure.boundedTransfer }
    }

    private static func testAtomicCacheReplacementPreservesOldPackage(
        packageURL: URL,
        manifest: UpdateManifest
    ) throws {
        let cacheRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("ratelmesh-cache-replace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: cacheRoot) }
        let fileName = "RatelMesh-macOS-\(manifest.version)-universal.pkg"
        let destination = cacheRoot.appendingPathComponent(fileName)
        let oldBytes = Data("previous verified package".utf8)
        try oldBytes.write(to: destination, options: .atomic)
        let oldHash = try UpdateSecurity.sha256(of: destination)

        do {
            _ = try AtomicPackageCache.install(
                verifiedPackage: packageURL,
                in: cacheRoot,
                fileName: fileName,
                expectedSize: manifest.size,
                expectedSHA256: manifest.sha256,
                replace: { _, _ in throw InjectedFailure.replace }
            )
            throw TestFailure.replaceFailureAccepted
        } catch InjectedFailure.replace {
            // Expected: replacement fails before the atomic rename.
        }

        guard try Data(contentsOf: destination) == oldBytes,
              try UpdateSecurity.sha256(of: destination) == oldHash
        else {
            throw TestFailure.oldPackageChanged
        }
        let remaining = try FileManager.default.contentsOfDirectory(
            at: cacheRoot,
            includingPropertiesForKeys: nil
        )
        guard remaining.map(\.lastPathComponent) == [fileName] else {
            throw TestFailure.cacheCandidateLeaked
        }
    }
}

private final class StreamingURLProtocol: URLProtocol, @unchecked Sendable {
    struct Response {
        let headers: [String: String]
        let chunks: [Data]
    }

    private static let responseStore = ResponseStore()
    static var response: Response {
        get { responseStore.get() }
        set { responseStore.set(newValue) }
    }
    private let stopLock = NSLock()
    private var stopped = false

    override class func canInit(with _: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let configured = Self.response
        guard let url = request.url,
              let response = HTTPURLResponse(
                  url: url,
                  statusCode: 200,
                  httpVersion: "HTTP/1.1",
                  headerFields: configured.headers
              )
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in configured.chunks where !isStopped {
            client?.urlProtocol(self, didLoad: chunk)
        }
        if !isStopped {
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {
        stopLock.lock()
        stopped = true
        stopLock.unlock()
    }

    private var isStopped: Bool {
        stopLock.lock()
        defer { stopLock.unlock() }
        return stopped
    }
}

private final class ResponseStore: @unchecked Sendable {
    private let lock = NSLock()
    private var response = StreamingURLProtocol.Response(headers: [:], chunks: [])

    func get() -> StreamingURLProtocol.Response {
        lock.lock()
        defer { lock.unlock() }
        return response
    }

    func set(_ response: StreamingURLProtocol.Response) {
        lock.lock()
        self.response = response
        lock.unlock()
    }
}

private enum TestFailure: Error {
    case arguments
    case checksum
    case version
    case freshness
    case tamperAccepted
    case responseHost
    case tamperedPackage
    case unsafeURLAccepted
    case invalidKeyAccepted
    case invalidSignatureAccepted
    case invalidPQKeyAccepted
    case invalidPQSignatureAccepted
    case schemaDowngradeAccepted
    case chunkedOversizeAccepted
    case lyingLengthAccepted
    case declaredOversizeAccepted
    case boundedTransfer
    case replaceFailureAccepted
    case oldPackageChanged
    case cacheCandidateLeaked
    case failureClassification
}

private enum InjectedFailure: Error {
    case replace
}
