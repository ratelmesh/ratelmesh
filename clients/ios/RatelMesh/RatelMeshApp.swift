import SwiftUI

enum ProductLanguage: String, CaseIterable, Identifiable {
    case system, chinese, english
    var id: String { rawValue }
}

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
                .task { await model.prepare() }
        }
    }
}
