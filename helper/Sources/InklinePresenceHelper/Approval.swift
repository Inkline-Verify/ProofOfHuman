// The what-you-see-is-what-you-sign confirmation window.
//
// The helper renders the CANONICAL content — the exact bytes that will be
// hashed and signed. It never signs anything it did not display.
//
// There is no approve button. The moment the window is on screen the system
// Touch ID prompt is raised (its reason string carries the recipient and
// subject), so one touch of the sensor both approves and signs. Cancelling
// the Touch ID sheet, pressing Cancel in the window, or pressing Escape
// declines: the LAContext is invalidated, which makes the blocked signing
// call fail with a cancel error instead of ever producing a signature.

import AppKit
import InklineCore
import LocalAuthentication

enum Approval {
    /// Shows the canonical email and immediately runs `sign` on a background
    /// thread with a fresh LAContext. `sign` is expected to block on the
    /// Touch ID prompt. Returns whatever `sign` returns; throws
    /// `PresenceKeyError.cancelled` when the user declines.
    static func requestApproval<T>(
        canonical email: Canonical.Email,
        sign: @escaping (LAContext) throws -> T
    ) throws -> T {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 480),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.title = "Inkline: confirm send"
        window.isReleasedWhenClosed = false
        window.center()
        window.level = .floating

        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 10
        content.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 16, right: 20)
        content.translatesAutoresizingMaskIntoConstraints = false

        let heading = NSTextField(labelWithString: "Touch the sensor to send this email")
        heading.font = NSFont.systemFont(ofSize: 15, weight: .semibold)
        content.addArrangedSubview(heading)

        func fieldRow(_ name: String, _ value: String) {
            let label = NSTextField(labelWithString: name.uppercased())
            label.font = NSFont.systemFont(ofSize: 10, weight: .medium)
            label.textColor = .secondaryLabelColor
            let field = NSTextField(wrappingLabelWithString: value.isEmpty ? "(none)" : value)
            field.font = name == "to"
                ? NSFont.systemFont(ofSize: 16, weight: .bold)
                : NSFont.systemFont(ofSize: 13)
            field.isSelectable = true
            content.addArrangedSubview(label)
            content.addArrangedSubview(field)
        }

        fieldRow("to", email.to.joined(separator: ", "))
        if !email.cc.isEmpty {
            fieldRow("cc", email.cc.joined(separator: ", "))
        }
        fieldRow("from", email.from)
        fieldRow("subject", email.subject)

        let bodyLabel = NSTextField(labelWithString: "MESSAGE (canonical form, this is what gets signed)")
        bodyLabel.font = NSFont.systemFont(ofSize: 10, weight: .medium)
        bodyLabel.textColor = .secondaryLabelColor
        content.addArrangedSubview(bodyLabel)

        let bodyView = NSTextView()
        bodyView.string = email.body
        bodyView.isEditable = false
        bodyView.isSelectable = true
        bodyView.font = NSFont.systemFont(ofSize: 13)
        bodyView.textContainerInset = NSSize(width: 6, height: 8)
        bodyView.autoresizingMask = [.width]
        let scroll = NSScrollView()
        scroll.documentView = bodyView
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 180).isActive = true
        content.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: content.widthAnchor, constant: -40).isActive = true

        let note = NSTextField(wrappingLabelWithString:
            "Touch ID signs exactly the content above and sends the email. Press Cancel or Escape to stop.")
        note.font = NSFont.systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        content.addArrangedSubview(note)

        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.spacing = 12
        let cancel = NSButton(title: "Cancel", target: nil, action: nil)
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        buttons.addArrangedSubview(cancel)
        content.addArrangedSubview(buttons)

        let context = LAContext()
        let session = SigningSession<T>(context: context)
        cancel.target = session
        cancel.action = #selector(SigningSession<T>.cancel(_:))

        window.contentView = content
        NSLayoutConstraint.activate([
            content.widthAnchor.constraint(greaterThanOrEqualToConstant: 520)
        ])

        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)

        // Kick off the biometric-gated signature right away. It blocks this
        // background thread on the system Touch ID sheet while the modal loop
        // below keeps the window drawn and the Cancel button live.
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome: Result<T, Error>
            do { outcome = .success(try sign(context)) } catch { outcome = .failure(error) }
            DispatchQueue.main.async { session.finish(outcome) }
        }

        NSApp.runModal(for: window)
        window.orderOut(nil)

        guard let outcome = session.outcome else {
            throw PresenceKeyError.cancelled
        }
        return try outcome.get()
    }
}

private final class SigningSession<T>: NSObject {
    let context: LAContext
    private(set) var outcome: Result<T, Error>?
    private var stopped = false

    init(context: LAContext) {
        self.context = context
    }

    @objc func cancel(_ sender: Any?) {
        // Tears down the Touch ID sheet; the signing call then fails with a
        // cancel error and finish() records it, but we stop the modal now so
        // the window closes immediately.
        context.invalidate()
        stop()
    }

    func finish(_ result: Result<T, Error>) {
        if outcome == nil { outcome = result }
        stop()
    }

    private func stop() {
        guard !stopped else { return }
        stopped = true
        NSApp.stopModal()
    }
}
