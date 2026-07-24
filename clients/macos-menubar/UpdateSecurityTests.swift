import Foundation

@main
private struct UpdateSecurityTests {
    static func main() throws {
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

        print("macOS updater security tests passed")
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
    case failureClassification
}
