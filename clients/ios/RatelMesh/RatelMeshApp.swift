import SwiftUI

#if DEBUG
private struct DeviceNetworkTestResult: Codable {
    let name: String
    let status: Int
    let bytes: Int
    let succeeded: Bool
    let errorCode: Int?
}

private func runDeviceNetworkTests() async {
    let checks: [(String, String)] = [
        ("control", "https://control.ratelmesh.com/v1/healthz"),
        ("dns-tls", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("large-transfer", "https://speed.cloudflare.com/__down?bytes=2097152"),
        ("youtube", "https://www.youtube.com/generate_204"),
        ("video-cdn", "https://redirector.googlevideo.com/report_mapping"),
    ]
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 20
    configuration.timeoutIntervalForResource = 30
    configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    let session = URLSession(configuration: configuration)
    var results: [DeviceNetworkTestResult] = []
    for (name, rawURL) in checks {
        guard let url = URL(string: rawURL) else { continue }
        do {
            let (data, response) = try await session.data(from: url)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            results.append(DeviceNetworkTestResult(
                name: name,
                status: status,
                bytes: data.count,
                succeeded: (200..<400).contains(status),
                errorCode: nil
            ))
        } catch {
            let code = (error as? URLError)?.errorCode ?? (error as NSError).code
            results.append(DeviceNetworkTestResult(
                name: name,
                status: 0,
                bytes: 0,
                succeeded: false,
                errorCode: code
            ))
        }
    }
    if let data = try? JSONEncoder().encode(results),
       let json = String(data: data, encoding: .utf8) {
        AppConstants.sharedDefaults?.set(json, forKey: "device-test-network-results")
    }
}
#endif

@main
struct RatelMeshApp: App {
    @StateObject private var model = AppViewModel()
    @AppStorage("ratelmesh.language") private var language = ProductLanguage.system.rawValue

    var body: some Scene {
        WindowGroup {
            ContentView(
                model: model,
                language: Binding(
                    get: { ProductLanguage(rawValue: language) ?? .system },
                    set: { language = $0.rawValue }
                )
            )
                .task {
#if DEBUG
                    let runDeviceConnectTest =
                        ProcessInfo.processInfo.environment["RATELMESH_DEVICE_TEST_CONNECT"] == "1"
                        || CommandLine.arguments.contains("--ratelmesh-device-test-connect")
                    let runDeviceDisconnectTest =
                        CommandLine.arguments.contains("--ratelmesh-device-test-disconnect")
                    let deviceTestExit = CommandLine.arguments.first {
                        $0.hasPrefix("--ratelmesh-device-test-exit=")
                    }?.split(separator: "=", maxSplits: 1).last.map(String.init)
                    let runDeviceDirectTest =
                        CommandLine.arguments.contains("--ratelmesh-device-test-direct")
                    let runDeviceNetworkTest =
                        CommandLine.arguments.contains("--ratelmesh-device-test-network")
                    if runDeviceConnectTest {
                        AppConstants.sharedDefaults?.set(
                            "prepare-start",
                            forKey: "device-test-stage"
                        )
                    }
#endif
                    await model.prepare()
#if DEBUG
                    if runDeviceDisconnectTest {
                        model.disconnect()
                        AppConstants.sharedDefaults?.set(
                            "disconnect-returned",
                            forKey: "device-test-stage"
                        )
                    }
                    if runDeviceConnectTest {
                        AppConstants.sharedDefaults?.set(
                            "prepare-finished",
                            forKey: "device-test-stage"
                        )
                        await model.connect()
                        AppConstants.sharedDefaults?.set(
                            "connect-returned",
                            forKey: "device-test-stage"
                        )
                    }
                    if let deviceTestExit, !deviceTestExit.isEmpty {
                        await model.selectExit(deviceTestExit)
                        _ = try? await URLSession.shared.data(
                            from: URL(string: "https://control.ratelmesh.com/v1/healthz")!
                        )
                        AppConstants.sharedDefaults?.set(
                            "exit-requested",
                            forKey: "device-test-stage"
                        )
                    }
                    if runDeviceDirectTest {
                        await model.selectExit("")
                        _ = try? await URLSession.shared.data(
                            from: URL(string: "https://control.ratelmesh.com/v1/healthz")!
                        )
                        AppConstants.sharedDefaults?.set(
                            "direct-requested",
                            forKey: "device-test-stage"
                        )
                    }
                    if runDeviceNetworkTest {
                        await runDeviceNetworkTests()
                        AppConstants.sharedDefaults?.set(
                            "network-tests-finished",
                            forKey: "device-test-stage"
                        )
                    }
#endif
                }
        }
    }
}
