import SwiftUI

@main
struct CipherwordsApp: App {
    @State private var model = CipherModel()

    init() {
        // Used by the build pipeline: `simctl launch ... -selftest` checks the engine and exits.
        if CommandLine.arguments.contains("-selftest") { SelfTest.runAndExit() }
    }

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
