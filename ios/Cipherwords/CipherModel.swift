import SwiftUI
import UIKit
import Observation
import UniformTypeIdentifiers

enum Mode: String, CaseIterable, Identifiable {
    case encrypt = "Encrypt", decrypt = "Decrypt"
    var id: Self { self }
}

@MainActor
@Observable
final class CipherModel {
    var mode: Mode = .encrypt {
        didSet { if oldValue != mode { clearAll() } }
    }
    var input = ""
    var passphrase = ""
    var confirm = ""
    var output = ""
    var errorText: String?
    var busy = false
    var copied = false
    var startedAt: Date?
    var estimate: Double = 0
    /// True while the screen is being recorded, mirrored or shared; the UI hides its contents.
    var screenCaptured = false

    private var copyGeneration = 0
    private let background = BackgroundWork()

    var canRun: Bool {
        !busy
        && !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !passphrase.isEmpty
        && (mode == .decrypt || passphrase == confirm)
    }

    func run() {
        guard canRun else { return }
        let m = mode, text = input, pw = passphrase
        busy = true; errorText = nil; output = ""; copied = false
        // If the user switches apps mid-way, ask iOS for time to finish. If iOS pauses the app
        // anyway, the work resumes on return; the round count is fixed up front, so a pause can
        // only make it slower, never weaker.
        background.begin()
        Task { @MainActor in
            let secs = await Task.detached(priority: .userInitiated) { () -> Double in
                m == .encrypt ? CipherEngine.targetSeconds : (CipherEngine.estimatedSeconds(forCode: text) ?? 0)
            }.value
            self.estimate = secs
            self.startedAt = Date()
            let result = await Task.detached(priority: .userInitiated) { () -> Result<String, Error> in
                Result {
                    m == .encrypt
                        ? try CipherEngine.encrypt(text, passphrase: pw)
                        : try CipherEngine.decrypt(text, passphrase: pw)
                }
            }.value
            self.busy = false
            self.startedAt = nil
            self.background.end()
            switch result {
            case .success(let s): self.output = s
            case .failure(let e): self.errorText = e.localizedDescription
            }
        }
    }

    /// Copies to this device only (no Universal Clipboard), and the system erases it after 60 seconds.
    func copy() {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: output]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
        copied = true
        copyGeneration += 1
        let gen = copyGeneration
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(60))
            if self.copyGeneration == gen { self.copied = false }
        }
    }

    func clearAll() {
        input = ""; passphrase = ""; confirm = ""; output = ""; errorText = nil; copied = false
    }

    func refreshCaptureState() {
        screenCaptured = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { $0.traitCollection.sceneCaptureState == .active }
    }
}

/// Wraps UIKit's background-task API so a running encryption can finish after the user switches away.
@MainActor
final class BackgroundWork {
    private var id: UIBackgroundTaskIdentifier = .invalid

    func begin() {
        end()
        id = UIApplication.shared.beginBackgroundTask(withName: "Cipherwords key stretching") { [weak self] in
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}
