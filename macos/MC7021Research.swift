import Cocoa
import Darwin

// Native UI and JSON-lines bridge. No web server, network client or terminal.
// Reports are read as local JSON and rendered with AppKit text controls.
final class ResearchApp: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private var pages: [NSView] = []
    private let tabs = NSSegmentedControl(labels: ["演示", "采样", "分析", "报告"], trackingMode: .selectOne, target: nil, action: nil)
    private let status = NSTextField(wrappingLabelWithString: "就绪。先选演示，可以体验完整流程。")
    private let folderLabel = NSTextField(wrappingLabelWithString: "首次使用时选择本机数据文件夹。")
    private let host = NSTextField(string: "")
    private let udid = NSTextField(string: "")
    private let consent = NSButton(checkboxWithTitle: "我确认现场条件符合上述要求，只测同一组普通灯", target: nil, action: nil)
    private let stepTitle = NSTextField(wrappingLabelWithString: "等待开始")
    private let instruction = NSTextField(wrappingLabelWithString: "")
    private let promptText = NSTextField(wrappingLabelWithString: "")
    private let promptButtons = NSStackView()
    private let promptInput = NSTextField(string: "")
    private let progress = NSProgressIndicator()
    private let stopButton = NSButton(title: "结束并保存", target: nil, action: nil)
    private let reportPicker = NSPopUpButton(frame: .zero, pullsDown: false)
    private let reportText = NSTextView()
    private var logView = NSTextView()
    private var taskPanel: NSView?
    private var logPanel: NSView?
    private var worker: Process?
    private var inputPipe: Pipe?
    private var pendingPrompt: String?
    private var promptValues: [ObjectIdentifier: String] = [:]
    private var reportDirectories: [URL] = []
    private var dataDirectory: URL?
    private var lastReport: URL?
    private var finishedEvent = false
    private var lastFinishedOK = false
    private var lastCaptureStatus: String?
    private var lastError = ""
    private var isStopping = false
    private var quitAfterCleanup = false
    private var activeMode: String?
    private var stderrTail = ""
    private let outputQueue = DispatchQueue(label: "org.mc7021.research.output")
    private let errorQueue = DispatchQueue(label: "org.mc7021.research.error")

    private var busy: Bool { worker != nil }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let path = UserDefaults.standard.string(forKey: "data-directory"),
           FileManager.default.fileExists(atPath: path) { dataDirectory = URL(fileURLWithPath: path, isDirectory: true) }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 800),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "MC7021 单灯研究工具 · v0.3.0"
        window.minSize = NSSize(width: 920, height: 740)
        window.delegate = self
        let content = window.contentView!
        let root = NSStackView()
        root.orientation = .vertical; root.alignment = .leading; root.distribution = .fill; root.spacing = 14
        root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 26),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -26),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20)])
        root.addArrangedSubview(label("摩根 MC7021 · 一组普通灯", 24, .semibold))
        root.addArrangedSubview(label("保留原主机和面板。代码公开，住户抓包及完整报告只存本机、私下处理。", 13, .regular))
        tabs.target = self; tabs.action = #selector(changePage); tabs.selectedSegment = 0
        tabs.setAccessibilityIdentifier("main-navigation")
        root.addArrangedSubview(tabs)
        let container = NSView(); container.translatesAutoresizingMaskIntoConstraints = false
        container.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        root.addArrangedSubview(container)
        container.widthAnchor.constraint(equalTo: root.widthAnchor).isActive = true
        container.heightAnchor.constraint(greaterThanOrEqualToConstant: 245).isActive = true
        for page in [makeDemoPage(), makeCapturePage(), makeAnalysisPage(), makeReportsPage()] {
            page.translatesAutoresizingMaskIntoConstraints = false
            page.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
            container.addSubview(page)
            NSLayoutConstraint.activate([page.leadingAnchor.constraint(equalTo: container.leadingAnchor),
                page.trailingAnchor.constraint(equalTo: container.trailingAnchor),
                page.topAnchor.constraint(equalTo: container.topAnchor), page.bottomAnchor.constraint(equalTo: container.bottomAnchor)])
            pages.append(page)
        }
        let rule = NSBox(); rule.boxType = .separator; root.addArrangedSubview(rule)
        rule.widthAnchor.constraint(equalTo: root.widthAnchor).isActive = true
        let task = NSStackView(); task.orientation = .vertical; task.alignment = .leading; task.spacing = 7
        taskPanel = task; task.isHidden = true
        stepTitle.font = .systemFont(ofSize: 16, weight: .semibold)
        instruction.font = .systemFont(ofSize: 13)
        promptText.font = .systemFont(ofSize: 13, weight: .medium)
        for item in [stepTitle, instruction, promptText] { task.addArrangedSubview(item); item.widthAnchor.constraint(equalTo: task.widthAnchor).isActive = true }
        promptButtons.orientation = .horizontal; promptButtons.spacing = 8
        task.addArrangedSubview(promptButtons)
        promptInput.placeholderString = "需要文字输入时在这里填写"; promptInput.isHidden = true
        task.addArrangedSubview(promptInput)
        let taskRow = NSStackView(); taskRow.orientation = .horizontal; taskRow.spacing = 14
        progress.style = .bar; progress.isIndeterminate = true; progress.minValue = 0; progress.maxValue = 20
        progress.widthAnchor.constraint(equalToConstant: 260).isActive = true
        stopButton.target = self; stopButton.action = #selector(stopTask); stopButton.isEnabled = false
        taskRow.addArrangedSubview(progress); taskRow.addArrangedSubview(stopButton)
        task.addArrangedSubview(taskRow)
        root.addArrangedSubview(task); task.widthAnchor.constraint(equalTo: root.widthAnchor).isActive = true
        let logs = scrollText(logView)
        logPanel = logs; logs.isHidden = true
        logView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logs.heightAnchor.constraint(equalToConstant: 82).isActive = true
        root.addArrangedSubview(logs); logs.widthAnchor.constraint(equalTo: root.widthAnchor).isActive = true
        status.font = .systemFont(ofSize: 12); status.textColor = .secondaryLabelColor
        status.setContentHuggingPriority(.required, for: .vertical)
        root.addArrangedSubview(status)
        let footer = NSStackView(); footer.orientation = .horizontal; footer.spacing = 12
        footer.setHuggingPriority(.required, for: .vertical)
        folderLabel.font = .systemFont(ofSize: 11); folderLabel.textColor = .secondaryLabelColor
        footer.addArrangedSubview(button("选择数据文件夹…", #selector(chooseDataDirectory)))
        footer.addArrangedSubview(button("运行记录", #selector(toggleLogs)))
        footer.addArrangedSubview(folderLabel)
        root.addArrangedSubview(footer)
        changePage(); updateFolderLabel(); reloadReports()
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    private func label(_ text: String, _ size: CGFloat = 14, _ weight: NSFont.Weight = .regular) -> NSTextField {
        let result = NSTextField(wrappingLabelWithString: text)
        result.font = .systemFont(ofSize: size, weight: weight)
        result.setContentHuggingPriority(.required, for: .vertical)
        result.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return result
    }

    private func button(_ title: String, _ action: Selector) -> NSButton {
        let result = NSButton(title: title, target: self, action: action)
        result.bezelStyle = .rounded; result.setAccessibilityIdentifier(title)
        return result
    }

    private func stack(_ items: [NSView]) -> NSStackView {
        let result = NSStackView(views: items)
        result.orientation = .vertical; result.alignment = .leading; result.distribution = .fill; result.spacing = 14
        for item in items { item.widthAnchor.constraint(lessThanOrEqualTo: result.widthAnchor).isActive = true }
        return result
    }

    private func topAligned(_ contents: NSView) -> NSView {
        let wrapper = NSView(); contents.translatesAutoresizingMaskIntoConstraints = false
        wrapper.addSubview(contents)
        NSLayoutConstraint.activate([contents.leadingAnchor.constraint(equalTo: wrapper.leadingAnchor),
            contents.trailingAnchor.constraint(equalTo: wrapper.trailingAnchor),
            contents.topAnchor.constraint(equalTo: wrapper.topAnchor),
            contents.bottomAnchor.constraint(lessThanOrEqualTo: wrapper.bottomAnchor)])
        return wrapper
    }

    private func makeDemoPage() -> NSView {
        let result = stack([label("先看完整流程", 20, .semibold),
            label("生成明确标为合成的通信和操作记录，自动完成离线分析，并在应用内查看中文报告。\n不用手机、不填 IP / UDID、不提权，不接触家庭设备。"),
            button("生成演示报告", #selector(startDemo)),
            label("演示证明软件流程，不能验证任何住宅，也不是可安装的 Home Assistant 集成。", 12)])
        return topAligned(result)
    }

    private func makeCapturePage() -> NSView {
        host.placeholderString = "已从现有 App 或设备记录确认的当前 IP"; host.setAccessibilityLabel("MC7021 当前 IP")
        udid.placeholderString = "在 Finder 中选中 iPhone 后复制 UDID"; udid.setAccessibilityLabel("iPhone UDID")
        let grid = NSGridView(views: [[label("MC7021 当前 IP"), host], [label("iPhone UDID"), udid]])
        grid.rowSpacing = 12; grid.columnSpacing = 16; grid.column(at: 0).width = 130
        grid.column(at: 1).xPlacement = .fill
        let available = FileManager.default.isExecutableFile(atPath: "/Library/Apple/usr/bin/rvictl")
        let tools = label(available ? "Apple USB 抓包组件：已找到。实际使用前仍会检查连接和信任状态。" :
            "缺少 Apple USB 抓包组件 rvictl，真实采样暂不可用；演示、分析和报告仍可使用。", 12)
        let result = stack([label("只采同一组普通灯", 20, .semibold),
            label("需要人在这套房子里，iPhone 连平时的家庭 Wi-Fi，USB 接 Mac 并信任。原厂 App 和面板本来就能正常控制这组灯。\n只做正常 App / 面板操作，不扫描、不修改配置、不涉及场景、总断电或安防。", 13),
            grid, consent, button("开始采样", #selector(startCapture)), tools])
        grid.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true
        return topAligned(result)
    }

    private func makeAnalysisPage() -> NSView {
        return topAligned(stack([label("分析已有采样", 20, .semibold),
            label("选择包含 session.json、events.jsonl、traffic.pcap 的完整采样文件夹。原件只读，无需手机或管理员权限。"),
            button("选择采样文件夹并分析…", #selector(startAnalysis)),
            label("报告会检查完整性、关联操作时间线，并区分开关请求、执行应答、ACK 和状态候选。不能识别或证据不足时保留未知。", 13)]))
    }

    private func scrollText(_ text: NSTextView) -> NSScrollView {
        let scroll = NSScrollView(); scroll.borderType = .bezelBorder; scroll.hasVerticalScroller = true
        scroll.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        text.isEditable = false; text.isSelectable = true; text.isRichText = false
        text.autoresizingMask = [.width]; text.isVerticallyResizable = true; text.isHorizontallyResizable = false
        text.textContainer?.widthTracksTextView = true; text.textContainerInset = NSSize(width: 12, height: 10)
        scroll.documentView = text
        return scroll
    }

    private func makeReportsPage() -> NSView {
        reportPicker.target = self; reportPicker.action = #selector(selectReport)
        let row = NSStackView(views: [reportPicker, button("刷新列表", #selector(refreshReports)), button("在 Finder 查看完整文件", #selector(revealReport))])
        row.orientation = .horizontal; row.spacing = 10
        reportPicker.widthAnchor.constraint(equalToConstant: 370).isActive = true
        let scroll = scrollText(reportText); reportText.font = .systemFont(ofSize: 13)
        let result = stack([label("本机报告 · 私下处理", 20, .semibold), row, scroll])
        scroll.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 170).isActive = true
        return result
    }

    @objc private func changePage() {
        for (index, view) in pages.enumerated() { view.isHidden = index != tabs.selectedSegment }
        if tabs.selectedSegment == 3 { reloadReports() }
    }

    private func updateFolderLabel() {
        folderLabel.stringValue = dataDirectory.map { "数据位置：\($0.lastPathComponent)（只存本机）" } ?? "首次使用时选择本机数据文件夹。"
    }

    @objc private func chooseDataDirectory() {
        guard !busy else { alert("任务进行中", "请先结束并保存，再更换数据文件夹。"); return }
        let panel = NSOpenPanel(); panel.title = "选择本机数据文件夹"; panel.message = "演示、采样和完整报告只保存在这里，不会自动上传。可新建一个专用文件夹。"
        panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.canCreateDirectories = true; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let selected = panel.url {
            guard FileManager.default.isWritableFile(atPath: selected.path) else { alert("无法写入", "请选择你有写入权限的文件夹。"); return }
            dataDirectory = selected; UserDefaults.standard.set(selected.path, forKey: "data-directory")
            updateFolderLabel(); reloadReports()
        }
    }

    private func requireDataDirectory() -> URL? {
        if dataDirectory == nil { chooseDataDirectory() }
        return dataDirectory
    }

    @objc private func startDemo() { start(mode: "demo", arguments: []) }

    @objc private func startAnalysis() {
        guard !busy else { alert("任务进行中", "请先结束并保存当前任务。"); return }
        let panel = NSOpenPanel(); panel.title = "选择完整采样文件夹"; panel.canChooseFiles = false
        panel.canChooseDirectories = true; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let selected = panel.url else { return }
        guard FileManager.default.fileExists(atPath: selected.appendingPathComponent("session.json").path) else {
            alert("请选择完整文件夹", "该目录没有 session.json。请选择同一轮采样的完整结果文件夹。"); return
        }
        start(mode: "analyze", arguments: ["--session-dir", selected.path])
    }

    @objc private func startCapture() {
        guard !busy else { alert("任务进行中", "请先结束并保存当前任务。"); return }
        guard consent.state == .on else { alert("先确认现场条件", "请确认你在这套房子内，且原 App / 面板均能正常控制同一组普通灯。"); return }
        let address = host.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let identifier = udid.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        var v4 = in_addr(); var v6 = in6_addr()
        guard inet_pton(AF_INET, address, &v4) == 1 || inet_pton(AF_INET6, address, &v6) == 1 else {
            alert("IP 格式不正确", "只填已确认的单个数字 IP，不带端口、网段或命令；不知道时不要猜或扫描。"); return
        }
        let pattern = "^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})$"
        guard identifier.range(of: pattern, options: .regularExpression) != nil,
              !identifier.replacingOccurrences(of: "-", with: "").allSatisfy({ $0 == "0" }) else {
            alert("UDID 格式不正确", "请在 Finder 选中已连接的 iPhone，点击设备信息切换后复制 UDID。不要填序列号。"); return
        }
        start(mode: "capture", arguments: ["--host-ip", address, "--udid", identifier])
    }

    private func start(mode: String, arguments: [String]) {
        guard !busy else { alert("任务进行中", "同一时间只运行一个任务。"); return }
        guard let directory = requireDataDirectory(), let resources = Bundle.main.resourceURL else { return }
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "x86_64"
        #endif
        let runtime = resources.appendingPathComponent("runtime/\(architecture)/python")
        let python = runtime.appendingPathComponent("bin/python3")
        let script = resources.appendingPathComponent("tools/gui_worker.py")
        guard FileManager.default.isExecutableFile(atPath: python.path), FileManager.default.fileExists(atPath: script.path) else {
            alert("应用内容不完整", "请使用完整解压的 .app，不能只复制其中的可执行文件。无需安装 Python 或打开终端。"); return
        }
        let process = Process(); process.executableURL = python
        process.arguments = ["-u", script.path, "--data-dir", directory.path, mode] + arguments
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONHOME"] = runtime.path; environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONUNBUFFERED"] = "1"; environment["PYTHONNOUSERSITE"] = "1"
        environment.removeValue(forKey: "PYTHONPATH")
        environment["MC7021_CAPTURE_HELPER"] = resources.appendingPathComponent("capture-helper").path
        process.environment = environment
        let input = Pipe(), output = Pipe(), error = Pipe()
        process.standardInput = input; process.standardOutput = output; process.standardError = error
        worker = process; inputPipe = input; finishedEvent = false; lastFinishedOK = false
        lastCaptureStatus = nil; lastError = ""; isStopping = false; activeMode = mode; stderrTail = ""
        taskPanel?.isHidden = false; logPanel?.isHidden = true
        stepTitle.stringValue = mode == "capture" ? "正在检查并准备采样" : mode == "demo" ? "正在生成合成演示" : "正在分析本地样本"
        instruction.stringValue = mode == "capture" ? "系统授权框可能询问 Mac 管理员密码；密码只由系统读取。" : "全部在本机处理，原始采样只读。"
        promptText.stringValue = ""; clearPrompt(); logView.string = ""; stopButton.isEnabled = true
        progress.isIndeterminate = true; progress.startAnimation(nil); status.stringValue = "任务进行中，结果不会自动上传。"
        do { try process.run() }
        catch { worker = nil; inputPipe = nil; stopButton.isEnabled = false; taskPanel?.isHidden = true; progress.stopAnimation(nil); alert("未能启动", "应用内置运行组件无法启动。请保留完整应用并重新解压。"); return }
        outputQueue.async { [weak self] in
            var buffer = Data()
            while true {
                let chunk = output.fileHandleForReading.readData(ofLength: 4096)
                if chunk.isEmpty { break }
                buffer.append(chunk)
                if buffer.count > 4 * 1024 * 1024 { DispatchQueue.main.async { self?.protocolFailure() }; break }
                while let newline = buffer.firstIndex(of: 10) {
                    let line = buffer.prefix(upTo: newline); buffer.removeSubrange(...newline)
                    guard !line.isEmpty else { continue }
                    if let value = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                        DispatchQueue.main.async { self?.receive(value) }
                    } else { DispatchQueue.main.async { self?.appendLog("无法识别一条工具输出，原始样本仍保留。") } }
                }
            }
            process.waitUntilExit()
            DispatchQueue.main.async { self?.workerEnded(process.terminationStatus) }
        }
        errorQueue.async { [weak self] in
            while true {
                let chunk = error.fileHandleForReading.readData(ofLength: 4096)
                if chunk.isEmpty { break }
                let text = String(data: chunk, encoding: .utf8) ?? ""
                DispatchQueue.main.async { self?.stderrTail = String(((self?.stderrTail ?? "") + text).suffix(4000)) }
            }
        }
    }

    private func protocolFailure() { appendLog("输出超过限制，正在结束并保存。"); stopTask() }

    private func appendLog(_ text: String) {
        logView.string = String((logView.string + text + (text.hasSuffix("\n") ? "" : "\n")).suffix(16000))
        logView.scrollToEndOfDocument(nil)
    }

    private func clearPrompt() {
        for item in promptButtons.arrangedSubviews { promptButtons.removeArrangedSubview(item); item.removeFromSuperview() }
        promptValues.removeAll(); promptInput.isHidden = true; pendingPrompt = nil
    }

    private func receive(_ event: [String: Any]) {
        switch event["type"] as? String {
        case "log": appendLog(event["text"] as? String ?? "")
        case "step":
            stepTitle.stringValue = event["title"] as? String ?? "当前步骤"
            instruction.stringValue = event["instruction"] as? String ?? ""
        case "prompt":
            clearPrompt(); pendingPrompt = event["id"] as? String
            promptText.stringValue = event["text"] as? String ?? "按提示选择"
            let options = event["options"] as? [[String: Any]] ?? []
            for option in options {
                guard let value = option["value"] as? String else { continue }
                let control = button(option["label"] as? String ?? value, #selector(answerPrompt(_:)))
                control.isEnabled = !isStopping; promptValues[ObjectIdentifier(control)] = value
                if value.isEmpty { control.keyEquivalent = "\r" }
                promptButtons.addArrangedSubview(control)
            }
            if options.isEmpty {
                promptInput.isHidden = false; promptInput.stringValue = event["default_value"] as? String ?? ""
                promptButtons.addArrangedSubview(button("提交", #selector(submitText)))
            }
        case "progress":
            if let remaining = event["remaining_seconds"] as? NSNumber {
                progress.isIndeterminate = false; progress.maxValue = max(progress.maxValue, remaining.doubleValue)
                progress.doubleValue = progress.maxValue - remaining.doubleValue
                status.stringValue = "正在观察，剩余 \(remaining.intValue) 秒。"
            }
        case "result":
            lastCaptureStatus = event["capture_status"] as? String
            if let path = event["report_dir"] as? String {
                lastReport = URL(fileURLWithPath: path, isDirectory: true)
                reloadReports(); tabs.selectedSegment = 3; changePage()
            }
            status.stringValue = "报告已保留在本机。完整报告、原始样本只私下处理。"
        case "error":
            lastError = event["message"] as? String ?? "工具未完成，请保留提示。"
            appendLog(lastError); logPanel?.isHidden = false; status.stringValue = lastError
        case "finished":
            finishedEvent = true
            let ok = event["ok"] as? Bool ?? false
            lastFinishedOK = ok
            stepTitle.stringValue = ok ? "处理完成" : "任务已停止，请查看保留记录"
            instruction.stringValue = "收到 ACK、生成报告或测试通过，均不等于住户实机接入已验证。"
            promptText.stringValue = ""; clearPrompt()
            status.stringValue = ok ? "处理完成。报告和原始数据只保存在本机。" :
                lastError.isEmpty ? "任务已停止。请查看保留报告及清理记录。" : lastError
        default: appendLog("未知工具事件已忽略。")
        }
    }

    @objc private func answerPrompt(_ sender: NSButton) {
        if let value = promptValues[ObjectIdentifier(sender)] { sendAnswer(value) }
    }
    @objc private func submitText() { sendAnswer(promptInput.stringValue) }
    private func sendAnswer(_ value: String) {
        guard let identifier = pendingPrompt, let pipe = inputPipe else { return }
        do {
            var data = try JSONSerialization.data(withJSONObject: ["id": identifier, "value": value])
            data.append(10); try pipe.fileHandleForWriting.write(contentsOf: data)
            clearPrompt(); promptText.stringValue = "正在记录…"
        } catch { appendLog("无法发送选择，正在结束并保存。"); stopTask() }
    }

    @objc private func stopTask() {
        guard let process = worker, process.isRunning, !isStopping else { return }
        isStopping = true; stopButton.isEnabled = false
        if pendingPrompt != nil { sendAnswer("q") }
        process.interrupt()
        clearPrompt(); promptText.stringValue = "正在停止、保存并确认清理，请保留窗口。"
        status.stringValue = "如果系统授权框仍打开，请在系统框选择取消。"
    }

    private func workerEnded(_ code: Int32) {
        inputPipe?.fileHandleForWriting.closeFile(); inputPipe = nil; worker = nil
        stopButton.isEnabled = false; progress.stopAnimation(nil); progress.isIndeterminate = false
        clearPrompt()
        if !finishedEvent {
            logPanel?.isHidden = false
            stepTitle.stringValue = "工具意外结束"
            instruction.stringValue = "原始文件保留。若采样中途强制退出，可能需要人工确认接口清理；不要重试扫描或改配置。"
            appendLog("退出码：\(code)。\n\(stderrTail)")
        }
        if finishedEvent && lastFinishedOK { taskPanel?.isHidden = true }
        if quitAfterCleanup && (!finishedEvent || lastCaptureStatus == "cleanup_incomplete") {
            quitAfterCleanup = false; taskPanel?.isHidden = false; logPanel?.isHidden = false
            status.stringValue = "尚未确认清理完成，已保留窗口与记录。请先查看停止原因。"
        }
        activeMode = nil; isStopping = false
        if quitAfterCleanup { NSApp.terminate(nil) }
    }

    private func reloadReports() {
        let previous = lastReport ?? (reportPicker.indexOfSelectedItem >= 0 && reportPicker.indexOfSelectedItem < reportDirectories.count ? reportDirectories[reportPicker.indexOfSelectedItem] : nil)
        reportDirectories = []
        if let folder = dataDirectory?.appendingPathComponent("private_reports") {
            let children = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.isSymbolicLinkKey])) ?? []
            reportDirectories = children.filter { url in
                let linked = (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) ?? true
                return !linked && FileManager.default.fileExists(atPath: url.appendingPathComponent("report.json").path)
            }.sorted { $0.lastPathComponent > $1.lastPathComponent }
        }
        reportPicker.removeAllItems()
        for url in reportDirectories { reportPicker.addItem(withTitle: url.lastPathComponent) }
        if let selected = previous, let index = reportDirectories.firstIndex(of: selected) { reportPicker.selectItem(at: index) }
        selectReport()
    }

    @objc private func refreshReports() { reloadReports() }
    @objc private func toggleLogs() { logPanel?.isHidden.toggle() }
    private func text(_ value: Any?) -> String {
        guard let value = value, !(value is NSNull) else { return "未知" }
        if let values = value as? [String] { return values.isEmpty ? "无" : values.joined(separator: "、") }
        if let values = value as? [Any] { return values.isEmpty ? "无" : values.map { text($0) }.joined(separator: "、") }
        return String(describing: value)
    }
    private func observed(_ value: Any?) -> String {
        let labels = ["on": "亮 / 开", "off": "灭 / 关", "unknown": "不确定", "not_visible": "未显示"]
        return labels[text(value)] ?? text(value)
    }
    private func evidenceStatus(_ value: Any?) -> String {
        let labels = ["limited": "存在限制", "reviewable": "可供人工复核", "blocked": "受阻", "pass": "通过", "warn": "需注意", "fail": "未通过", "recorded": "记录完整", "completed": "记录完成", "partial": "部分记录", "skipped": "已跳过", "incomplete": "不完整"]
        return labels[text(value)] ?? text(value)
    }
    @objc private func selectReport() {
        let index = reportPicker.indexOfSelectedItem
        guard index >= 0 && index < reportDirectories.count else {
            reportText.string = "尚无本机报告。请先运行演示，或选择已有采样文件夹分析。"; return
        }
        let directory = reportDirectories[index]
        let url = directory.appendingPathComponent("report.json")
        guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size <= 16 * 1024 * 1024,
              let data = try? Data(contentsOf: url), let report = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            reportText.string = "报告不可读或超过应用内16MiB展示上限。可在Finder查看完整文件；原件不改动。"; return
        }
        let synthetic = report["simulation"] as? Bool
        let quality = report["quality"] as? [String: Any] ?? [:]
        let metrics = report["summary"] as? [String: Any] ?? [:]
        var lines = [synthetic == true ? "合成演示 · 不是住户通信" : synthetic == false ? "住户采样声明 · 尚未经身份核验" : "样本来源未知",
            "私有报告，不上传到公开仓库或业主群。", "Home Assistant 实机接入：待人工验证。", "",
            "样本质量：\(evidenceStatus(quality["level"]))", "包：\(text(metrics["packet_count"]))    目标主机包：\(text(metrics["target_packet_count"]))    明文帧：\(text(metrics["frame_count"]))    设备候选：\(text(metrics["device_count"]))", "", "质量检查"]
        for row in quality["checks"] as? [[String: Any]] ?? [] { lines.append("• \(text(row["name"]))：\(evidenceStatus(row["status"])) · \(evidenceStatus(row["detail"]))") }
        for warning in quality["warnings"] as? [String] ?? [] { lines.append("• 注意：" + warning) }
        lines += ["", "动作时间线", "实际动作只位于准备至确认区间；时间邻近不证明因果，ACK不是状态。"]
        for row in (report["events"] as? [[String: Any]] ?? []).prefix(200) {
            lines.append("\n\(text(row["step"])) [\(evidenceStatus(row["status"]))]\n  肉眼：\(observed(row["physical_light"]))；App：\(observed(row["app_display"]))\n  请求：\(text(row["command_count"]))；执行应答：\(text(row["execution_response_count"]))；ACK：\(text(row["ack_count"]))；状态：\(text(row["state_count"]))\n  帧：\(text(row["frame_indices"]))\n  准备：\(text(row["ready_at"]))\n  确认：\(text(row["confirmed_at"]))")
        }
        lines += ["", "设备候选（私有标识，尚未确认实际灯路）"]
        for row in (report["device_candidates"] as? [[String: Any]] ?? []).prefix(200) {
            lines.append("• \(text(row["identifier_hex"])) · 开\(text(row["command_on_count"])) / 关\(text(row["command_off_count"])) / 状态\(text(row["state_record_count"]))\n  面板窗口：\(text(row["panel_state_windows"]))；重进App：\(text(row["reopen_state_windows"]))")
        }
        lines += ["", "证据缺口与下一步"]
        for item in (report["unknowns"] as? [String] ?? []) + (report["next_actions"] as? [String] ?? []) { lines.append("• " + item) }
        lines += ["", "完整帧字段、原始状态、私有HTML及匿名摘要保存在本报告目录；使用上方Finder按钮查看。", "输入和报告都不自动上传。"]
        reportText.string = lines.joined(separator: "\n")
        reportText.scrollToBeginningOfDocument(nil)
    }

    @objc private func revealReport() {
        let index = reportPicker.indexOfSelectedItem
        guard index >= 0 && index < reportDirectories.count else { return }
        NSWorkspace.shared.activateFileViewerSelecting([reportDirectories[index].appendingPathComponent("报告.html")])
    }

    private func alert(_ title: String, _ message: String) {
        let dialog = NSAlert(); dialog.messageText = title; dialog.informativeText = message
        dialog.addButton(withTitle: "好"); dialog.runModal()
    }

    private func askToStopAndQuit() {
        let dialog = NSAlert(); dialog.messageText = "任务仍在进行"
        dialog.informativeText = "请等待停止、保存和接口清理确认。直接强制退出可能留下不完整采样。"
        dialog.addButton(withTitle: "继续等待"); dialog.addButton(withTitle: "结束保存后退出")
        if dialog.runModal() == .alertSecondButtonReturn { quitAfterCleanup = true; stopTask() }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool { if busy { askToStopAndQuit(); return false }; return true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if busy { askToStopAndQuit(); return .terminateCancel }; return .terminateNow
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { return true }
}

let application = NSApplication.shared
let delegate = ResearchApp()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
