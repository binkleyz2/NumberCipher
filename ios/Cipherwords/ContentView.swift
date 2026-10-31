import SwiftUI
import UIKit

struct ContentView: View {
    @Bindable var model: CipherModel
    @Environment(\.scenePhase) private var scenePhase
    @FocusState private var focused: Field?

    private enum Field { case input, passphrase, confirm }

    private var encrypt: Bool { model.mode == .encrypt }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Picker("Mode", selection: $model.mode) {
                        ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .disabled(model.busy)

                    inputSection
                    passphraseSection
                    runButton

                    if model.busy { progress }

                    if let errorText = model.errorText {
                        Label(errorText, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }

                    if !model.output.isEmpty { outputCard }

                    Text("AES-256-GCM · PBKDF2-SHA256 tuned to ~10 s on this device · every encryption is unique")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding()
                .frame(maxWidth: 640)
                .frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Cipherwords")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Clear All", action: model.clearAll).disabled(model.busy)
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { focused = nil }
                }
            }
        }
        .overlay {
            if scenePhase != .active || model.screenCaptured {
                PrivacyCover(captured: model.screenCaptured)
            }
        }
        .onAppear(perform: model.refreshCaptureState)
        .onChange(of: scenePhase) { model.refreshCaptureState() }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            model.refreshCaptureState()
        }
    }

    // MARK: Sections

    private var inputSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(encrypt ? "Text to encrypt" : "Code to decrypt").font(.headline)
                Spacer()
                if !encrypt && !model.busy {
                    // PasteButton reads the clipboard without iOS's "Allow Paste?" prompt.
                    PasteButton(payloadType: String.self) { strings in
                        let text = strings.first ?? ""
                        Task { @MainActor in model.input = text }
                    }
                    .labelStyle(.titleAndIcon)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
                }
            }
            TextEditor(text: $model.input)
                .font(encrypt ? .body : .system(.body, design: .monospaced))
                // Keeps secrets out of the keyboard's learned words and stops "fixes" to code words.
                .autocorrectionDisabled()
                .textInputAutocapitalization(encrypt ? .sentences : .characters)
                .focused($focused, equals: .input)
                .scrollContentBackground(.hidden)
                .padding(8)
                .frame(minHeight: 130)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))
                .disabled(model.busy)
            if !encrypt {
                Text("Words, or an older letter code. Capitalization, line breaks and numbering don't matter.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var passphraseSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SecureField("Passphrase", text: $model.passphrase)
                .textFieldStyle(.roundedBorder)
                .focused($focused, equals: .passphrase)
                .submitLabel(encrypt ? .next : .go)
                .onSubmit { if encrypt { focused = .confirm } else { focused = nil; model.run() } }
                .disabled(model.busy)

            if encrypt {
                SecureField("Confirm passphrase", text: $model.confirm)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .confirm)
                    .submitLabel(.go)
                    .onSubmit { focused = nil; model.run() }
                    .disabled(model.busy)
                StrengthMeter(passphrase: model.passphrase)
                if !model.confirm.isEmpty && model.confirm != model.passphrase {
                    Text("Passphrases don't match").font(.caption).foregroundStyle(.red)
                }
            }
        }
    }

    private var runButton: some View {
        Button {
            focused = nil
            model.run()
        } label: {
            HStack(spacing: 8) {
                if model.busy { ProgressView().tint(.white) }
                Text(model.mode.rawValue)
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .keyboardShortcut(.return, modifiers: .command)
        .disabled(!model.canRun)
    }

    @ViewBuilder private var progress: some View {
        if let start = model.startedAt, model.estimate > 0 {
            TimelineView(.periodic(from: start, by: 0.2)) { context in
                let elapsed = context.date.timeIntervalSince(start)
                let remaining = max(0, Int((model.estimate - elapsed).rounded(.up)))
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: min(elapsed / model.estimate, 1))
                    Text(remaining > 0 ? "Strengthening key — about \(remaining) s left" : "Finishing…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } else {
            Text("Measuring this device's speed…").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var outputCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(encrypt ? "Word code" : "Text").font(.headline)
            Text(model.output)
                .font(encrypt ? .system(.body, design: .monospaced) : .body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack {
                Button(model.copied ? "Copied — clears in 60s" : "Copy", systemImage: "doc.on.doc", action: model.copy)
                    .buttonStyle(.bordered)
                if encrypt {
                    // Only the code is offered for sharing, never decrypted text.
                    ShareLink(item: model.output) { Label("Share", systemImage: "square.and.arrow.up") }
                        .buttonStyle(.bordered)
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.secondarySystemBackground)))
    }
}

/// Covers the app in the app switcher, and while the screen is recorded, mirrored or shared.
private struct PrivacyCover: View {
    let captured: Bool

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.tint)
                Text("Cipherwords").font(.title2.bold())
                if captured {
                    Text("Hidden while the screen is being recorded, mirrored or shared.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 32)
                }
            }
        }
    }
}

struct StrengthMeter: View {
    let passphrase: String

    private var bits: Double {
        guard !passphrase.isEmpty else { return 0 }
        var pool = 0
        if passphrase.contains(where: \.isLowercase) { pool += 26 }
        if passphrase.contains(where: \.isUppercase) { pool += 26 }
        if passphrase.contains(where: \.isNumber) { pool += 10 }
        if passphrase.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 33 }
        return Double(passphrase.count) * log2(Double(max(pool, 2)))
    }

    private var label: (String, Color) {
        switch bits {
        case ..<40: return ("Weak — use a longer passphrase", .red)
        case ..<60: return ("Fair", .orange)
        case ..<80: return ("Strong", .green)
        default:    return ("Very strong", .green)
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            ProgressView(value: min(bits, 100), total: 100)
                .tint(label.1)
                .frame(width: 120)
            Text(passphrase.isEmpty ? "Passphrase strength" : label.0)
                .font(.caption)
                .foregroundStyle(passphrase.isEmpty ? .secondary : label.1)
        }
    }
}
