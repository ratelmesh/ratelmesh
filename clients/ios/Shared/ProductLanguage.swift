import Foundation

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
        if self == .system {
            return Self.systemLanguage(for: Locale.preferredLanguages.first)
                .localized(english, chineseFallback: chineseFallback)
        }
        let fallback = self == .chinese || self == .traditionalChinese ? chineseFallback : english
        if self == .english { return english }
        let tag = self == .chinese ? "zh-Hans" : rawValue
        guard let path = Bundle.main.path(forResource: tag, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return fallback }
        for table in [nil, "NetworkDoctor", "MacApp"] {
            let localized = bundle.localizedString(forKey: english, value: english, table: table)
            if localized != english { return localized }
        }
        return fallback
    }

    static func systemLanguage(for identifier: String?) -> ProductLanguage {
        let tag = (identifier ?? "en").lowercased()
        if tag.hasPrefix("zh-hant") || tag.hasPrefix("zh-tw")
            || tag.hasPrefix("zh-hk") || tag.hasPrefix("zh-mo") {
            return .traditionalChinese
        }
        if tag.hasPrefix("zh") { return .chinese }
        if tag.hasPrefix("es") { return .spanish }
        if tag.hasPrefix("de") { return .german }
        if tag.hasPrefix("fr") { return .french }
        if tag.hasPrefix("ja") { return .japanese }
        if tag.hasPrefix("ko") { return .korean }
        if tag.hasPrefix("it") { return .italian }
        if tag.hasPrefix("nl") { return .dutch }
        if tag.hasPrefix("pl") { return .polish }
        if tag.hasPrefix("sv") { return .swedish }
        if tag.hasPrefix("pt") { return .portugueseBrazil }
        return .english
    }
}
