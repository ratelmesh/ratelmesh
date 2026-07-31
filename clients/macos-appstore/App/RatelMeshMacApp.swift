import AppKit
import SwiftUI

@main
struct RatelMeshMacApp: App {
    @StateObject private var model = AppViewModel()
    @AppStorage("ratelmesh.language") private var language = ProductLanguage.system.rawValue

    var body: some Scene {
        WindowGroup {
            MacContentView(
                model: model,
                language: Binding(
                    get: { ProductLanguage(rawValue: language) ?? .system },
                    set: { language = $0.rawValue }
                )
            )
            .frame(minWidth: 880, minHeight: 620)
#if DEBUG
            .background {
                if let path = ProcessInfo.processInfo.environment[
                    "RATELMESH_APP_STORE_SCREENSHOT_PATH"
                ], !path.isEmpty {
                    MacAppStoreScreenshotCapture(path: path)
                }
            }
#endif
            .task {
                if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
                    await model.prepare()
                }
            }
        }
        .defaultSize(width: 980, height: 720)
        .windowStyle(.titleBar)
    }
}

#if DEBUG
private struct MacAppStoreScreenshotCapture: NSViewRepresentable {
    let path: String

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            guard let window = view.window,
                  let contentView = window.contentView else {
                return
            }
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.setFrame(
                NSRect(origin: window.frame.origin, size: NSSize(width: 1440, height: 900)),
                display: true
            )
            window.displayIfNeeded()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                contentView.layoutSubtreeIfNeeded()
                contentView.displayIfNeeded()
                if let captured = CGWindowListCreateImage(
                    .null,
                    .optionIncludingWindow,
                    CGWindowID(window.windowNumber),
                    [.boundsIgnoreFraming, .bestResolution]
                ), let png = NSBitmapImageRep(cgImage: captured).representation(
                    using: .png,
                    properties: [:]
                ) {
                    try? png.write(to: URL(fileURLWithPath: path), options: .atomic)
                    return
                }
                guard let image = contentView.bitmapImageRepForCachingDisplay(
                    in: contentView.bounds
                ) else {
                    return
                }
                contentView.cacheDisplay(in: contentView.bounds, to: image)
                guard let png = image.representation(using: .png, properties: [:]) else {
                    return
                }
                try? png.write(to: URL(fileURLWithPath: path), options: .atomic)
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}
#endif
