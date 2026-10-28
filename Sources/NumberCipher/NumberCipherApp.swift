import SwiftUI
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct NumberCipherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    private let model = CipherModel()

    var body: some Scene {
        WindowGroup("Number Cipher") {
            ContentView(model: model)
        }
        .windowResizability(.contentMinSize)
    }
}
