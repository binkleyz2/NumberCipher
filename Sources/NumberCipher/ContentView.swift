import SwiftUI
import AppKit
import Observation

// App state lives in an Observation model instead of SwiftUI @State, so the app
// builds with the Command Line Tools alone (which don't include SwiftUI's macro plugin).

enum Mode: String, CaseIterable, Identifiable, Sendable {
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

    private var copyGeneration = 0

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
        Task { @MainActor in
            let result = await Task.detached(priority: .userInitiated) { () -> Result<String, Error> in
                Result {
                    m == .encrypt
                        ? try CipherEngine.encrypt(text, passphrase: pw)
                        : try CipherEngine.decrypt(text, passphrase: pw)
                }
            }.value
            self.busy = false
            switch result {
            case .success(let s): self.output = s
            case .failure(let e): self.errorText = e.localizedDescription
            }
        }
    }

    func copy() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(output, forType: .string)
        // Convention honored by most clipboard managers: don't record this item.
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let stamp = pb.changeCount
        copied = true
        copyGeneration += 1
        let gen = copyGeneration
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(60))
            if pb.changeCount == stamp { pb.clearContents() }
            if self.copyGeneration == gen { self.copied = false }
        }
    }

    func clearAll() {
        input = ""; passphrase = ""; confirm = ""; output = ""; errorText = nil; copied = false
    }
}

struct ContentView: View {
    let model: CipherModel

    private func bind<T>(_ keyPath: ReferenceWritableKeyPath<CipherModel, T>) -> Binding<T> {
        Binding(get: { model[keyPath: keyPath] }, set: { model[keyPath: keyPath] = $0 })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("Mode", selection: bind(\.mode)) {
                ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            Text(model.mode == .encrypt ? "Numbers to encrypt" : "Letter code to decrypt")
                .font(.headline)

            TextEditor(text: bind(\.input))
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(6)
                .frame(minHeight: 90)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary))

            SecureField("Passphrase", text: bind(\.passphrase))
                .textFieldStyle(.roundedBorder)

            if model.mode == .encrypt {
                SecureField("Confirm passphrase", text: bind(\.confirm))
                    .textFieldStyle(.roundedBorder)
                HStack {
                    StrengthMeter(passphrase: model.passphrase)
                    if !model.confirm.isEmpty && model.confirm != model.passphrase {
                        Spacer()
                        Text("Passphrases don't match").font(.caption).foregroundStyle(.red)
                    }
                }
            }

            HStack {
                Button(action: model.run) {
                    HStack(spacing: 6) {
                        if model.busy { ProgressView().controlSize(.small) }
                        Text(model.mode.rawValue)
                    }
                    .frame(minWidth: 90)
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(!model.canRun)

                Spacer()
                Button("Clear All", action: model.clearAll)
            }

            if let errorText = model.errorText {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }

            if !model.output.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(model.mode == .encrypt ? "Letter code" : "Numbers").font(.headline)
                        Spacer()
                        Button(model.copied ? "Copied — clears in 60s" : "Copy", action: model.copy)
                    }
                    ScrollView {
                        Text(model.output)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(minHeight: 70, maxHeight: 180)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
                }
            }

            Spacer(minLength: 0)

            Text("AES-256-GCM · PBKDF2-SHA256, 2,000,000 rounds · every encryption is unique")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(minWidth: 540, minHeight: 540)
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
