import SwiftUI

enum ProductLanguage: String, CaseIterable, Identifiable {
    case system
    case english
    case spanish = "es"
    case german = "de"
    case french = "fr"
    case japanese = "ja"
    case korean = "ko"
    case italian = "it"
    case dutch = "nl"
    case polish = "pl"
    case swedish = "sv"
    case portugueseBrazil = "pt-BR"
    case chinese = "chinese"
    case traditionalChinese = "zh-Hant"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .system: return localized("System", chineseFallback: "跟随系统")
        case .english: return "English"
        case .spanish: return "Español"
        case .german: return "Deutsch"
        case .french: return "Français"
        case .japanese: return "日本語"
        case .korean: return "한국어"
        case .italian: return "Italiano"
        case .dutch: return "Nederlands"
        case .polish: return "Polski"
        case .swedish: return "Svenska"
        case .portugueseBrazil: return "Português (Brasil)"
        case .chinese: return "简体中文"
        case .traditionalChinese: return "繁體中文"
        }
    }

    func localized(_ english: String, chineseFallback: String) -> String {
        let systemChinese = Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
        let fallback = self == .chinese || self == .traditionalChinese || (self == .system && systemChinese) ? chineseFallback : english
        if self == .english { return english }
        if self == .system {
            return Bundle.main.localizedString(forKey: english, value: fallback, table: nil)
        }
        let tag = self == .chinese ? "zh-Hans" : rawValue
        guard let path = Bundle.main.path(forResource: tag, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return fallback }
        return bundle.localizedString(forKey: english, value: fallback, table: nil)
    }
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
