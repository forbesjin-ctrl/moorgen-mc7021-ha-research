import Cocoa
import Darwin

final class ReviewDocumentView: NSView { override var isFlipped: Bool { true } }

// Native UI and JSON-lines bridge. No web server, network client or terminal.
// Reports are read as local JSON and rendered with AppKit text controls.
final class ResearchApp: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private var pages: [NSView] = []
    private let tabs = NSSegmentedControl(labels: ["演示", "采样", "分析", "报告", "首组核对", "HA接入"], trackingMode: .selectOne, target: nil, action: nil)
    private let status = NSTextField(wrappingLabelWithString: "就绪。先选演示，可以体验完整流程。")
    private let folderLabel = NSTextField(wrappingLabelWithString: "首次使用时选择本机数据文件夹。")
    private let host = NSTextField(string: "")
    private let udid = NSTextField(string: "")
    private let targetName = NSTextField(string: "")
    private let targetRoom = NSTextField(string: "")
    private var collectionID = UUID().uuidString
    private var baselineConnection: String?
    private var baselineKey: String?
    private var activeCaptureKey: String?
    private var activeReviewFile: URL?
    private var activeReviewPassed = false
    private let reviewGate = NSTextField(wrappingLabelWithString: "首组尚未通过核对。采完会自动检查，并引导逐项人工复核。")
    private let reviewSummary = NSTextView()
    private let reviewCandidate = NSPopUpButton(frame: .zero, pullsDown: false)
    private let reviewerLabel = NSTextField(string: "")
    private let reviewIDs = ["sample_quality", "target_identity", "switch_semantics", "panel_feedback", "reopen_readback"]
    private var reviewChoices: [String: NSPopUpButton] = [:]
    private var reviewNotes: [String: NSTextField] = [:]
    private var reviewEvidence: [String: NSTextField] = [:]
    private var reviewReport: [String: Any]?
    private var reviewReportDirectory: URL?
    private var reviewSessionDirectory: URL?
    private var reportSessions: [String: URL] = [:]
    private var evidenceWindow: NSWindow?
    private var lastReviewMessage: String?
    private let haStatus = NSTextField(wrappingLabelWithString: "请先完成首组逐项核对，或载入有效的已通过记录。")
    private let haSummary = NSTextView()
    private var handoffDirectory: URL?
    private var wizardFile: URL?
    private var wizardState: [String: Any] = [:]
    private var haDriverEvidence: [String: NSTextField] = [:]
    private let haStepPicker = NSPopUpButton(frame: .zero, pullsDown: false)
    private var haStepViews: [NSView] = []
    private let haEntityID = NSTextField(string: "")
    private let haInstallNotes = NSTextField(string: "")
    private let haCasePicker = NSPopUpButton(frame: .zero, pullsDown: false)
    private let haCaseInstruction = NSTextField(wrappingLabelWithString: "")
    private let haDecision = NSPopUpButton(frame: .zero, pullsDown: false)
    private let haPhysical = NSPopUpButton(frame: .zero, pullsDown: false)
    private let haObserved = NSPopUpButton(frame: .zero, pullsDown: false)
    private let haEventID = NSTextField(string: "")
    private let haObservationNotes = NSTextField(string: "")
    private let haCases = ["ha_on_1", "ha_off_1", "ha_on_2", "ha_off_2", "panel_on", "panel_off", "disconnect", "reconnect"]
    private let haCaseNames = ["HA开灯第1次", "HA关灯第1次", "HA开灯第2次", "HA关灯第2次", "面板开灯", "面板关灯", "断线不可用", "重连读回"]
    private var captureCleanupUncertain = false
    private var capturePreflightPassed = false
    private var lastCollectionFailedCount = 0
    private let consent = NSButton(checkboxWithTitle: "我确认现场仍是本人确认的这户MC7021，本轮只操作填写的这一组普通灯", target: nil, action: nil)
    private var captureContents: NSView?
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
        window.title = "MC7021 研究工具 · v0.6.1"
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
        root.addArrangedSubview(label("摩根 MC7021 · 逐灯采样与研究", 24, .semibold))
        root.addArrangedSubview(label("保留原主机和面板。代码公开，住户抓包及完整报告只存本机、私下处理。", 13, .regular))
        tabs.target = self; tabs.action = #selector(changePage); tabs.selectedSegment = 0
        tabs.setAccessibilityIdentifier("main-navigation")
        root.addArrangedSubview(tabs)
        let container = NSView(); container.translatesAutoresizingMaskIntoConstraints = false
        container.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        root.addArrangedSubview(container)
        container.widthAnchor.constraint(equalTo: root.widthAnchor).isActive = true
        container.heightAnchor.constraint(greaterThanOrEqualToConstant: 245).isActive = true
        for page in [makeDemoPage(), makeCapturePage(), makeAnalysisPage(), makeReportsPage(), makeReviewPage(), makeHAPage()] {
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
            button("多轮合成演示与汇总", #selector(startCollectionDemo)),
            label("演示证明软件流程，不能验证任何住宅，也不是可安装的 Home Assistant 集成。", 12)])
        return topAligned(result)
    }

    private func makeCapturePage() -> NSView {
        host.placeholderString = "已从现有 App 或设备记录确认的当前 IP"; host.setAccessibilityLabel("MC7021 当前 IP")
        udid.placeholderString = "在 Finder 中选中 iPhone 后复制 UDID"; udid.setAccessibilityLabel("iPhone UDID")
        targetName.placeholderString = "例如客厅主灯；用于私下区分轮次，不是设备地址"
        targetName.setAccessibilityLabel("本轮灯名")
        targetRoom.placeholderString = "可选，例如客厅"; targetRoom.setAccessibilityLabel("本轮房间")
        let grid = NSGridView(views: [[label("MC7021 当前 IP"), host], [label("iPhone UDID"), udid],
            [label("本轮灯名"), targetName], [label("本轮房间（可选）"), targetRoom]])
        grid.rowSpacing = 12; grid.columnSpacing = 16; grid.column(at: 0).width = 130
        grid.column(at: 1).xPlacement = .fill
        let available = FileManager.default.isExecutableFile(atPath: "/Library/Apple/usr/bin/rvictl")
        let tools = label(available ? "Apple USB 抓包组件：已找到。实际使用前仍会检查连接和信任状态。" :
            "缺少 Apple USB 抓包组件 rvictl，真实采样暂不可用；演示、分析和报告仍可使用。", 12)
        let result = stack([label("可以采多盏，每轮只操作一组", 20, .semibold),
            label("需要人在这套房子里，iPhone 连平时的家庭 Wi-Fi，USB 接 Mac 并信任。原厂 App 和面板本来就能正常控制这组灯。\n只做正常 App / 面板操作，不扫描、不修改配置、不涉及场景、总断电或安防。", 13),
            label("先采第一组并人工对准请求、面板变化、肉眼状态与App回读，再逐组扩展。每轮独立保存；报告成功不自动确认身份或状态。IP/UDID可在本次打开期间复用。", 12),
            grid, consent, reviewGate, button("开始本轮采样", #selector(startCapture)), tools])
        grid.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true
        captureContents = result
        return topAligned(result)
    }

    private func makeAnalysisPage() -> NSView {
        return topAligned(stack([label("分析已有采样", 20, .semibold),
            label("选择包含 session.json、events.jsonl、traffic.pcap 的完整采样文件夹。原件只读，无需手机或管理员权限。"),
            button("选择采样文件夹并分析…", #selector(startAnalysis)),
            button("汇总本机多轮采样", #selector(startCollection)),
            label("汇总当前数据文件夹的captures目录，每一轮独立分析。旧样本无灯名时显示未知；相同报文标识只提示冲突，不自动合并为同一灯。", 12),
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
        let result = stack([label("本机报告 · 私下处理", 20, .semibold), row,
            button("核对此报告的首组证据", #selector(openSelectedReview)), scroll])
        scroll.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 170).isActive = true
        return result
    }

    private func makeReviewPage() -> NSView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        let document = ReviewDocumentView(); document.translatesAutoresizingMaskIntoConstraints = false
        let form = stack([]); form.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(form); scroll.documentView = document
        NSLayoutConstraint.activate([document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            form.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 4),
            form.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -12),
            form.topAnchor.constraint(equalTo: document.topAnchor, constant: 4),
            form.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -16)])
        func add(_ view: NSView) { form.addArrangedSubview(view); view.widthAnchor.constraint(equalTo: form.widthAnchor).isActive = true }
        add(label("首组核对 · 自动证据 + 人工复核", 20, .semibold))
        add(label("有经验的业主可自行核对，无需等待指定人员。‘已确认’限文件和结构事实；设备身份、状态含义及肉眼对应需要逐项复核。保存待验证或需补采不会解锁，合成演示不能通过。", 13))
        let navigation = NSStackView(views: [button("核对当前单轮报告", #selector(openSelectedReview)),
            button("载入已保存核对记录…", #selector(loadReviewRecord)), button("查看逐帧证据", #selector(showReviewEvidence))])
        navigation.orientation = .horizontal; navigation.spacing = 10; add(navigation)
        reviewSummary.string = "请先采样或分析一轮。采完会自动进入此页，列出已确认、待验证和需补采。"
        reviewSummary.font = .systemFont(ofSize: 13)
        let summaryScroll = scrollText(reviewSummary); summaryScroll.heightAnchor.constraint(equalToConstant: 210).isActive = true; add(summaryScroll)
        add(label("人工复核对象（完整线上候选标识，灯名不作为地址）", 14, .semibold))
        reviewCandidate.addItem(withTitle: "请选择报文候选；未选择不能通过"); add(reviewCandidate)
        reviewerLabel.placeholderString = "复核者代号，可匿名，例如业主A；只存本机"; reviewerLabel.setAccessibilityLabel("复核者代号"); add(reviewerLabel)
        let titles = ["样本与现场记录可靠", "对象标识与所选普通灯对准", "重复开关语义一致", "面板独立状态与肉眼一致", "App重进回读当前状态一致"]
        for (index, identifier) in reviewIDs.enumerated() {
            add(label("\(index + 1). \(titles[index])", 14, .semibold))
            let evidence = label("等待本轮检查结果。", 12); reviewEvidence[identifier] = evidence; add(evidence)
            let choice = NSPopUpButton(frame: .zero, pullsDown: false)
            choice.addItems(withTitles: ["待验证 · 尚未确认", "通过 · 已核对并有证据", "需补采 · 有缺失或矛盾"])
            choice.setAccessibilityLabel("\(titles[index])结论"); reviewChoices[identifier] = choice; add(choice)
            let note = NSTextField(string: ""); note.placeholderString = "填写帧号和判断依据；通过时每项必填。例：帧8/11，同一标识，两次开对应肉眼亮。"
            note.setAccessibilityLabel("\(titles[index])依据"); reviewNotes[identifier] = note; add(note)
        }
        add(label("请在‘查看逐帧证据’中核对方向、对象、原始状态、操作窗口与现场记录。窗口邻近不能证明因果，ACK不是状态。原始样本及报告若变化，已保存记录将失效。", 12))
        let actions = NSStackView(views: [button("保存逐项核对并检查结论", #selector(saveReviewForm)),
            button("继续采下一组普通灯", #selector(continueAfterReview)), button("进入HA接入阶段", #selector(enterHAStage))])
        actions.orientation = .horizontal; actions.spacing = 10; add(actions)
        return scroll
    }

    private func makeHAPage() -> NSView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        let document = ReviewDocumentView(); document.translatesAutoresizingMaskIntoConstraints = false; scroll.documentView = document
        let body = stack([]); body.translatesAutoresizingMaskIntoConstraints = false; document.addSubview(body)
        NSLayoutConstraint.activate([document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor), body.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 2), body.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -12), body.topAnchor.constraint(equalTo: document.topAnchor, constant: 6), body.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -12)])
        func add(_ view: NSView) { body.addArrangedSubview(view); view.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true }
        add(label("单灯 HA 接入向导 · 五步保存进度", 20, .semibold))
        add(label("先有本户真实首组复核，再由有能力的业主提供已核对驱动。Mac只检查文件和证据，不执行导入代码、不连接家庭设备。缺少驱动时停在准备步骤。", 13))
        let navigation = NSStackView(views: [button("新建单灯接入向导", #selector(createHAWizard)), button("载入向导进度…", #selector(loadHAWizard)), button("演示HA向导", #selector(demoHAWizard))]); navigation.spacing = 8; add(navigation)
        haStepPicker.addItems(withTitles: ["1 · 首组和灯路", "2 · 核对适配驱动", "3 · 安装并配置HA", "4 · 单灯真实状态验收", "5 · 验收报告"])
        haStepPicker.target = self; haStepPicker.action = #selector(changeHAStep); haStepPicker.setAccessibilityLabel("HA向导步骤"); add(haStepPicker); add(haStatus)
        haSummary.string = "选择演示可以练习流程；正式向导需要首组真实复核记录。各步和现场观察只存本机。"; haSummary.font = .systemFont(ofSize: 12)
        let summary = scrollText(haSummary); summary.heightAnchor.constraint(equalToConstant: 155).isActive = true; add(summary)
        let first = stack([label("第一步：核对目标", 16, .semibold), label("确认当前MC7021、房间、普通灯及完整对象标识与首组一致。新建、载入、生成包和验收都会重新校验原件；原件改变应重新分析复核。未通过不能安装。", 13), button("保留原研究包（可选）", #selector(exportHAHandoff))])
        let adapter = stack([label("第二步：准备并检查驱动", 16, .semibold), label("导出接口模板后，由有协议与Python经验的业主编写driver.py及清单，说明认证/会话、开关编码和独立状态依据。模板不能直接控制灯。导入只检查语法、接口和绑定，不认证代码安全或协议正确。导入代码将来在HA内具有自定义集成的执行权限，请先自行审阅。", 13), button("导出驱动接口模板", #selector(exportHAStarter))])
        for (key, title) in [("protocol", "连接与协议依据"), ("session", "认证和当前会话依据"), ("commands", "开关命令与序号依据"), ("independent_state", "独立状态及面板回读依据")] {
            let field = NSTextField(string: ""); field.placeholderString = title + "（填写证据引用与结论）"; field.setAccessibilityLabel(title); haDriverEvidence[key] = field; adapter.addArrangedSubview(field); field.widthAnchor.constraint(equalTo: adapter.widthAnchor).isActive = true
        }
        adapter.addArrangedSubview(button("选择已核对驱动并自动生成清单…", #selector(importHADriver)))
        adapter.addArrangedSubview(button("高级：导入已有清单和驱动…", #selector(importHAAdapter)))
        adapter.addArrangedSubview(button("在Finder查看向导文件", #selector(revealHAWizard)))
        haEntityID.placeholderString = "HA实际创建的light实体ID，例如light.study_ceiling"; haEntityID.setAccessibilityLabel("HA灯实体ID")
        haInstallNotes.placeholderString = "记录HA版本、配置结果及只启用此单灯的依据"; haInstallNotes.setAccessibilityLabel("HA安装记录")
        let install = stack([label("第三步：安装并配置HA", 16, .semibold), button("生成单灯HA安装包", #selector(buildHABundle)), button("在Finder查看安装包", #selector(revealHAWizard)), label("完整解压安装包，通过已有文件管理工具，把custom_components/mc7021_single_light复制到HA配置目录。先备份HA，已有同名集成时停止，勿直接覆盖。然后在HA界面重启，在设置→设备与服务→添加集成中搜索“MC7021 单灯业主验收”。核对绑定主机和对象，明确确认驱动及现场单灯测试后，HA才加载驱动。无需猜测未知端口或寄存器。", 13), haEntityID, haInstallNotes, button("记录已在HA安装并配置", #selector(recordHAInstallation)), label("Mac不替你登录、安装、启用或更改HA。安装成功是人工声明；后续须导回同一安装包的HA诊断和实际亮灭观察。", 12)])
        haCasePicker.addItems(withTitles: haCaseNames); haCasePicker.target = self; haCasePicker.action = #selector(changeHACase); haCasePicker.setAccessibilityLabel("单灯验收步骤")
        haDecision.addItems(withTitles: ["待验证", "人工观察通过", "需重测"]); haDecision.setAccessibilityLabel("本步人工结论")
        haPhysical.addItems(withTitles: ["实际亮灭未知", "亲眼看到亮", "亲眼看到灭"]); haPhysical.setAccessibilityLabel("物理灯观察")
        haObserved.addItems(withTitles: ["HA显示未知", "HA显示开", "HA显示关", "HA显示不可用"]); haObserved.setAccessibilityLabel("HA状态观察")
        haEventID.placeholderString = "对应诊断状态事件ID，十进制整数"; haEventID.setAccessibilityLabel("状态证据事件ID")
        haObservationNotes.placeholderString = "实际亮灭、HA显示及事件依据；ACK不算状态"; haObservationNotes.setAccessibilityLabel("单灯现场观察依据")
        let acceptance = stack([label("第四步：一组普通灯，八项验收", 16, .semibold), label("在HA设备页验收步骤选择器中选同一步，点“开始记录所选验收步骤”后再操作。四次HA开关后做面板操作，最后用集成断开/重连按钮验证不可用和回读，不断电、不改路由或厂家配置。每步看实体灯及HA，最后下载此集成诊断JSON并导入。", 13), haCasePicker, haCaseInstruction, haDecision, haPhysical, haObserved, haEventID, haObservationNotes, button("保存本步观察并核对", #selector(saveHAAcceptance)), button("导入HA诊断JSON并核对…", #selector(importHADiagnostics)), button("查看本机HA事件证据", #selector(showHAWizardEvidence))])
        let report = stack([label("第五步：看结论再扩展", 16, .semibold), label("上方报告分为已确认、待验证、需重测。机器只核对日志和绑定一致性；物理亮灭来自业主逐项观察。缺少步骤、窗口不符、只有ACK、旧会话或重连无当前读回，都不能通过。未完成时补测这一组；通过也仅适用于本户这组普通灯。", 13), button("查看完整向导及验收证据", #selector(showHAWizardEvidence)), button("在Finder查看私有验收报告", #selector(revealHAWizard))])
        haStepViews = [first, adapter, install, acceptance, report]; for view in haStepViews { add(view) }
        changeHAStep(); changeHACase(); return scroll
    }

    @objc private func changeHAStep() { for (index, view) in haStepViews.enumerated() { view.isHidden = index != haStepPicker.indexOfSelectedItem } }
    private func selectedHAWizard() -> URL? {
        guard !busy, let file = wizardFile else { alert("先新建或载入向导", "可以先演示，正式接入需要有效首组复核及自行核对的驱动。"); return nil }; return file
    }
    @objc private func createHAWizard() {
        guard !busy, activeReviewPassed, let review = activeReviewFile else { alert("先完成首组复核", "没有有效真实首组记录时，可先演示HA向导。"); return }
        var arguments = ["--review-file", review.path]; let ip = host.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !ip.isEmpty { arguments += ["--host-ip", ip] }; start(mode: "ha-wizard-create", arguments: arguments)
    }
    @objc private func demoHAWizard() { guard !busy else { return }; start(mode: "ha-wizard-demo", arguments: []) }
    @objc private func loadHAWizard() {
        guard !busy, let root = requireDataDirectory() else { return }
        let panel = NSOpenPanel(); panel.title = "选择本机state.json向导进度"; panel.allowedFileTypes = ["json"]; panel.allowsMultipleSelection = false; panel.directoryURL = root.appendingPathComponent("private_ha_wizards")
        if panel.runModal() == .OK, let url = panel.url { start(mode: "ha-wizard-load", arguments: ["--wizard-file", url.path]) }
    }
    @objc private func exportHAStarter() { if let file = selectedHAWizard() { start(mode: "ha-wizard-starter", arguments: ["--wizard-file", file.path]) } }
    @objc private func buildHABundle() { if let file = selectedHAWizard() { start(mode: "ha-wizard-bundle", arguments: ["--wizard-file", file.path]) } }
    @objc private func importHADriver() {
        guard let file = selectedHAWizard() else { return }
        let evidence = haDriverEvidence.mapValues { $0.stringValue }
        guard evidence.values.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) else { alert("先填写四项依据", "接口检查不能替代本户协议核对。请填写连接、会话、命令和独立状态依据。"); return }
        let panel = NSOpenPanel(); panel.title = "选择自行编写并审阅的driver.py（不在Mac执行）"; panel.allowedFileTypes = ["py"]; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let path = panel.url else { return }
        do { let form = try writeHAForm(evidence); start(mode: "ha-wizard-driver", arguments: ["--wizard-file", file.path, "--driver-file", path.path, "--form-file", form.path]) }
        catch { alert("驱动依据未保存", "请检查本机数据文件夹。") }
    }
    @objc private func importHAAdapter() {
        guard let file = selectedHAWizard() else { return }
        let manifest = NSOpenPanel(); manifest.title = "选择已填写的驱动清单JSON"; manifest.allowedFileTypes = ["json"]; manifest.allowsMultipleSelection = false
        guard manifest.runModal() == .OK, let m = manifest.url else { return }
        let driver = NSOpenPanel(); driver.title = "选择已自行审阅的driver.py（Mac不会执行）"; driver.allowedFileTypes = ["py"]; driver.allowsMultipleSelection = false
        guard driver.runModal() == .OK, let d = driver.url else { return }
        start(mode: "ha-wizard-adapter", arguments: ["--wizard-file", file.path, "--manifest-file", m.path, "--driver-file", d.path])
    }
    private func writeHAForm(_ object: [String: Any]) throws -> URL {
        guard let root = requireDataDirectory() else { throw CocoaError(.fileWriteNoPermission) }
        let folder = root.appendingPathComponent("private_ha_forms", isDirectory: true)
        if (try? folder.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw CocoaError(.fileWriteNoPermission) }
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else { throw CocoaError(.fileWriteFileExists) }
        } else { try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        let path = folder.appendingPathComponent(UUID().uuidString + ".json")
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: path, options: [.withoutOverwriting])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path); return path
    }
    @objc private func recordHAInstallation() {
        guard let file = selectedHAWizard() else { return }
        do { let form = try writeHAForm(["entity_id": haEntityID.stringValue, "confirmed": true, "notes": haInstallNotes.stringValue]); start(mode: "ha-wizard-install", arguments: ["--wizard-file", file.path, "--form-file", form.path]) }
        catch { alert("安装记录未保存", "请选择有效数据文件夹，并填写实体ID和安装依据。") }
    }
    @objc private func importHADiagnostics() {
        guard let file = selectedHAWizard() else { return }
        let panel = NSOpenPanel(); panel.title = "选择该单灯集成下载的诊断JSON"; panel.allowedFileTypes = ["json"]; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { start(mode: "ha-wizard-diagnostics", arguments: ["--wizard-file", file.path, "--diagnostics-file", url.path]) }
    }
    @objc private func changeHACase() {
        let index = max(0, haCasePicker.indexOfSelectedItem)
        let details = ["HA选择“1 · HA开灯（第一次）”，点“开始记录所选验收步骤”，再点灯开关；等独立状态，亲眼确认亮。", "选择“2 · HA关灯（第一次）”并开始记录，再HA关灯；等独立状态，确认灭。", "选择“3 · HA开灯（第二次）”并开始记录，重复HA开灯。", "选择“4 · HA关灯（第二次）”并开始记录，重复HA关灯；ACK不算状态。", "选择“5 · 面板开灯”并开始记录，只按原面板开灯，不点HA；检查HA独立更新为开。", "选择“6 · 面板关灯”并开始记录，只按原面板关灯，不点HA；检查HA独立更新为关。", "选择“7 · 仅断开本集成，检查不可用”并开始记录，点“仅断开本单灯适配连接”；HA不可用后用面板开灯，记录实物亮。", "选择“8 · 面板开灯后，重连读回”并开始记录，点“重连本单灯适配并读回”；须新代次独立读回，HA显示与此刻实物一致。"]
        haCaseInstruction.stringValue = details[index]
        let row = (wizardState["observations"] as? [String: [String: Any]] ?? [:])[haCases[index]] ?? [:]
        haDecision.selectItem(at: ["pending": 0, "pass": 1, "resample": 2][row["decision"] as? String ?? "pending"] ?? 0)
        haPhysical.selectItem(at: ["unknown": 0, "on": 1, "off": 2][row["physical_light"] as? String ?? "unknown"] ?? 0)
        haObserved.selectItem(at: ["unknown": 0, "on": 1, "off": 2, "unavailable": 3][row["ha_state"] as? String ?? "unknown"] ?? 0)
        haEventID.stringValue = (row["event_id"] as? NSNumber)?.stringValue ?? ""; haObservationNotes.stringValue = row["notes"] as? String ?? ""
    }
    @objc private func saveHAAcceptance() {
        guard let file = selectedHAWizard() else { return }
        var observations = wizardState["observations"] as? [String: [String: Any]] ?? [:]
        for key in haCases where observations[key] == nil { observations[key] = ["decision": "pending", "physical_light": "unknown", "ha_state": "unknown", "notes": "", "event_id": NSNull()] }
        let event: Any = Int(haEventID.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)).map { $0 as Any } ?? NSNull()
        observations[haCases[max(0, haCasePicker.indexOfSelectedItem)]] = ["decision": ["pending", "pass", "resample"][max(0, haDecision.indexOfSelectedItem)], "physical_light": ["unknown", "on", "off"][max(0, haPhysical.indexOfSelectedItem)], "ha_state": ["unknown", "on", "off", "unavailable"][max(0, haObserved.indexOfSelectedItem)], "notes": haObservationNotes.stringValue, "event_id": event]
        do { let form = try writeHAForm(observations); start(mode: "ha-wizard-acceptance", arguments: ["--wizard-file", file.path, "--form-file", form.path]) }
        catch { alert("观察未保存", "请检查本机数据文件夹。") }
    }
    @objc private func showHAWizardEvidence() {
        guard !wizardState.isEmpty, let data = try? JSONSerialization.data(withJSONObject: wizardState, options: [.prettyPrinted, .sortedKeys]), let text = String(data: data, encoding: .utf8) else { alert("尚无向导", "先新建或载入向导。"); return }
        evidenceWindow?.close()
        let evidence = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 650), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        evidence.title = "私有HA向导与事件证据 · 只读"; evidence.isReleasedWhenClosed = false
        let view = NSTextView(); view.string = text; view.isEditable = false; view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        evidence.contentView = scrollText(view); evidenceWindow = evidence; evidence.center(); evidence.makeKeyAndOrderFront(nil)
    }
    @objc private func revealHAWizard() {
        guard let file = wizardFile else { alert("尚无向导", "请新建或载入向导。"); return }; NSWorkspace.shared.activateFileViewerSelecting([file.deletingLastPathComponent()])
    }
    private func receiveHAWizard(_ event: [String: Any]) {
        guard let value = event["state"] as? [String: Any] else { return }; let changed = (wizardState["wizard_id"] as? String) != (value["wizard_id"] as? String); wizardState = value
        if changed { for field in haDriverEvidence.values { field.stringValue = "" } }
        if let path = event["wizard_file"] as? String { wizardFile = URL(fileURLWithPath: path) }
        let assessment = value["assessment"] as? [String: Any] ?? [:]; let simulated = value["simulation"] as? Bool ?? false; let valid = event["valid"] as? Bool ?? true
        var lines = [simulated ? "【合成演示 · 永不作为实机验收通过】" : "【私有单灯向导 · 人工观察与日志核对】", "进度：\(["adapter": "核对适配驱动", "bundle": "生成安装包", "installation": "安装并配置HA", "acceptance": "现场验收", "complete": "本轮人工验收通过", "invalid": "来源失效"][value["stage"] as? String ?? ""] ?? "准备")"]
        if let baseline = value["baseline"] as? [String: Any] { lines += ["主机：\(baseline["host_ip"] as? String ?? "演示")", "完整标识：\(baseline["target_identifier"] as? String ?? "待核对")"] }
        for (key, title) in [("confirmed", "已确认"), ("pending", "待验证"), ("resample", "需重测")] { lines += ["", title + "："] + ((assessment[key] as? [String]) ?? ["请看完整证据"]) }
        if let errors = event["errors"] as? [String], !errors.isEmpty { lines += ["", "失效原因："] + errors }
        haSummary.string = lines.joined(separator: "\n"); haSummary.scrollToBeginningOfDocument(nil)
        haStatus.stringValue = valid ? (simulated ? "演示可练习流程，不能安装真实驱动或通过验收。" : "进度已保存；驱动接口检查不等于代码安全或物理状态认证。") : "向导来源已失效，先重新核对原件，不能继续安装或验收。"
        if let installation = value["installation"] as? [String: Any] { haEntityID.stringValue = installation["entity_id"] as? String ?? ""; haInstallNotes.stringValue = installation["notes"] as? String ?? "" } else { haEntityID.stringValue = ""; haInstallNotes.stringValue = "" }
        if activeMode == "ha-wizard-create" || activeMode == "ha-wizard-demo" { haStepPicker.selectItem(at: 0) }
        else if activeMode == "ha-wizard-driver" || activeMode == "ha-wizard-adapter" || activeMode == "ha-wizard-bundle" { haStepPicker.selectItem(at: 2) }
        else if activeMode == "ha-wizard-install" || activeMode == "ha-wizard-diagnostics" { haStepPicker.selectItem(at: 3) }
        else if activeMode == "ha-wizard-acceptance", assessment["passed"] as? Bool == true { haStepPicker.selectItem(at: 4) }
        changeHAStep(); changeHACase(); tabs.selectedSegment = 5; changePage(); lastReviewMessage = haStatus.stringValue
    }

    @objc private func enterHAStage() {
        guard !busy, activeReviewPassed, activeReviewFile != nil else {
            alert("先完成首组核对", "请逐项核对并保存通过结论，或载入有效的已通过记录。合成、待验证、需补采或原件变化时不能进入后续工作。"); return
        }
        tabs.selectedSegment = 5; changePage()
        haStatus.stringValue = "已选择首组人工通过记录。请点“新建单灯接入向导”，按五步完成适配、安装和验收；不会自动连接或发送控制命令。"
    }

    @objc private func exportHAHandoff() {
        guard !busy, activeReviewPassed, let path = activeReviewFile else {
            alert("没有有效通过记录", "请先在首组核对页完成复核。研究包不接受演示或待验证记录。"); return
        }
        var arguments = ["--review-file", path.path]
        let address = host.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !address.isEmpty { arguments += ["--host-ip", address] }
        start(mode: "ha-handoff", arguments: arguments)
    }

    @objc private func revealHAHandoff() {
        guard let directory = handoffDirectory else { alert("尚无研究包", "首组通过后可生成本机私有研究包。"); return }
        NSWorkspace.shared.activateFileViewerSelecting([directory])
    }

    private func resetReviewForm() {
        for key in reviewIDs { reviewChoices[key]?.selectItem(at: 0); reviewNotes[key]?.stringValue = "" }
        reviewerLabel.stringValue = ""
    }

    private func readPrivateJSON(_ url: URL) -> [String: Any]? {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isSymbolicLinkKey]),
              values.isSymbolicLink != true, let size = values.fileSize, size <= 16 * 1024 * 1024,
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func prepareReview(_ directory: URL, session: URL? = nil) {
        guard let report = readPrivateJSON(directory.appendingPathComponent("report.json")) else { return }
        reviewReport = report; reviewReportDirectory = directory
        reviewSessionDirectory = session ?? reportSessions[directory.path]
        if reviewSessionDirectory == nil, let source = report["source"] as? [String: Any],
           let folder = source["folder"] as? String, folder == URL(fileURLWithPath: folder).lastPathComponent,
           folder != ".", folder != "..", let root = dataDirectory {
            for parent in ["captures", "demo_runs"] {
                let candidate = root.appendingPathComponent(parent).appendingPathComponent(folder)
                if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("session.json").path) { reviewSessionDirectory = candidate; break }
            }
        }
        let assessment = report["baseline_assessment"] as? [String: Any] ?? [:]
        resetReviewForm(); reviewCandidate.removeAllItems(); reviewCandidate.addItem(withTitle: "请选择四次重复开关候选；未选择不能通过")
        for identifier in assessment["candidate_identifiers"] as? [String] ?? [] { reviewCandidate.addItem(withTitle: identifier) }
        let target = report["target_context"] as? [String: Any] ?? [:]
        let source = report["source"] as? [String: Any] ?? [:]
        var lines = [report["simulation"] as? Bool == true ? "合成演示 · 不能通过首组核对" : "本轮首组核对 · 人工结论尚未完成",
            "本轮：\(text(target["room"])) · \(text(target["label"]))；主机：\(text(source["target_ip"]))；报告：\(directory.lastPathComponent)",
            "自动检查不确认物理身份或HA可用。", ""]
        for (key, title) in [("confirmed", "已确认（机器文件/结构事实）"), ("pending", "待验证（需人工核对）"), ("resample", "需补采（具体缺口）")] {
            lines.append(title)
            let rows = assessment[key] as? [String] ?? []
            lines += rows.isEmpty ? [assessment.isEmpty ? "• 旧报告没有首组检查，请重新分析原始采样。" : "• 当前未列出项目，不代表自动通过。"] : rows.map { "• " + $0 }
            lines.append("")
        }
        reviewSummary.string = lines.joined(separator: "\n"); reviewSummary.scrollToBeginningOfDocument(nil)
        for row in assessment["criteria"] as? [[String: Any]] ?? [] {
            guard let identifier = row["id"] as? String else { continue }
            let evidence = row["evidence"] as? [String] ?? []
            reviewEvidence[identifier]?.stringValue = "机器检查：\(evidenceStatus(row["machine_status"]))；仍需人工复核。\n" + evidence.joined(separator: "\n")
        }
    }

    @objc private func openSelectedReview() {
        guard !busy else { return }
        let index = reportPicker.indexOfSelectedItem
        guard index >= 0 && index < reportDirectories.count,
              FileManager.default.fileExists(atPath: reportDirectories[index].appendingPathComponent("report.json").path) else {
            alert("请选择单轮报告", "多轮汇总用于比较；首组核对需要一轮完整原始样本及它的单轮报告。"); return
        }
        prepareReview(reportDirectories[index]); tabs.selectedSegment = 4; changePage()
    }

    @objc private func showReviewEvidence() {
        guard let report = reviewReport else { alert("先选择单轮报告", "采样或离线分析后即可查看逐帧证据。"); return }
        let viewer = NSTextView(); viewer.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        var content = "私有逐帧证据 · 仅本机查看\n核对方向、标识、原始状态与现场观察。时间邻近不证明因果，ACK不是状态。\n\n"
        if let data = try? JSONSerialization.data(withJSONObject: ["source": report["source"] ?? [:],
            "target_context": report["target_context"] ?? NSNull(), "events": report["events"] ?? [],
            "flows": report["flows"] ?? [], "frames": report["frames"] ?? []], options: [.prettyPrinted, .sortedKeys]),
           let json = String(data: data, encoding: .utf8) { content += json }
        viewer.string = content
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 980, height: 680),
            styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "首组核对 · 私有报文与现场记录"; panel.contentView = scrollText(viewer)
        panel.center(); panel.makeKeyAndOrderFront(nil); evidenceWindow = panel
    }

    @objc private func saveReviewForm() {
        guard !busy, let directory = reviewReportDirectory, let root = requireDataDirectory() else { return }
        if reviewSessionDirectory == nil {
            let panel = NSOpenPanel(); panel.title = "选择本报告对应的原始采样文件夹"
            panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.allowsMultipleSelection = false
            guard panel.runModal() == .OK, let url = panel.url else { return }; reviewSessionDirectory = url
        }
        guard let session = reviewSessionDirectory else { return }
        let values = ["pending", "pass", "resample"]
        var decisions: [String: String] = [:], notes: [String: String] = [:]
        for key in reviewIDs {
            decisions[key] = values[reviewChoices[key]?.indexOfSelectedItem ?? 0]
            notes[key] = reviewNotes[key]?.stringValue ?? ""
        }
        let selected = reviewCandidate.indexOfSelectedItem > 0 ? reviewCandidate.titleOfSelectedItem ?? "" : ""
        let form: [String: Any] = ["decisions": decisions, "notes": notes, "selected_identifier": selected, "reviewer_label": reviewerLabel.stringValue]
        do {
            let parent = root.appendingPathComponent("private_reviews/forms", isDirectory: true)
            for folder in [root, root.appendingPathComponent("private_reviews"), parent] {
                if (try? folder.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw CocoaError(.fileWriteNoPermission) }
            }
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.appendingPathComponent("private_reviews").path)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: parent.path)
            let path = parent.appendingPathComponent(UUID().uuidString + ".json")
            try JSONSerialization.data(withJSONObject: form).write(to: path, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
            start(mode: "review-save", arguments: ["--report-dir", directory.path, "--session-dir", session.path, "--form-file", path.path])
        } catch { alert("未能保存表单", "请检查数据目录写入权限；原始样本和报告不修改。"); return }
    }

    @objc private func loadReviewRecord() {
        guard !busy else { return }
        let panel = NSOpenPanel(); panel.title = "选择本机已保存的首组核对JSON记录"
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        if let root = dataDirectory { panel.directoryURL = root.appendingPathComponent("baseline_reviews") }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        start(mode: "review-validate", arguments: ["--review-file", url.path])
    }

    @objc private func continueAfterReview() {
        guard !busy, activeReviewPassed, activeReviewFile != nil else {
            alert("首组尚未通过", "请先完成自动检查和所有必要人工核对，再保存结论；待验证、需补采、合成或原件变化均不能继续扩展。"); return
        }
        targetName.stringValue = ""; targetRoom.stringValue = ""; consent.state = .off
        tabs.selectedSegment = 1; changePage()
        status.stringValue = "首组核对记录已选择。填写下一组普通灯；开始前会重新校验原件和主机，仍需本人点击开始。"
    }

    private func receiveReview(_ validation: [String: Any], path: String?) {
        let valid = validation["valid"] as? Bool == true
        let passed = valid && validation["passed"] as? Bool == true
        activeReviewPassed = passed; activeReviewFile = passed ? path.map { URL(fileURLWithPath: $0) } : nil
        if valid, let record = validation["record"] as? [String: Any],
           let source = record["source"] as? [String: Any], let root = dataDirectory,
           let report = source["report_dir"] as? String, let session = source["session_dir"] as? String {
            prepareReview(root.appendingPathComponent(report), session: root.appendingPathComponent(session))
            let choices = ["pending": 0, "pass": 1, "resample": 2]
            for key in reviewIDs {
                let decisions = record["decisions"] as? [String: String] ?? [:]
                reviewChoices[key]?.selectItem(at: choices[decisions[key] ?? "pending"] ?? 0)
                reviewNotes[key]?.stringValue = (record["notes"] as? [String: String])?[key] ?? ""
            }
            if let selected = record["selected_identifier"] as? String, !selected.isEmpty { reviewCandidate.selectItem(withTitle: selected) }
            reviewerLabel.stringValue = record["reviewer_label"] as? String ?? ""
            if let target = record["target_context"] as? [String: Any],
               let name = target["label"] as? String, let room = target["room"] as? String { baselineKey = room + "\n" + name }
            if host.stringValue.isEmpty, let address = record["host_ip"] as? String { host.stringValue = address }
        }
        let message: String
        if passed {
            message = "首组人工核对已通过并绑定原件，可继续同一主机的其它普通灯。该结论是本机人工声明，HA仍待验证。"
        } else if valid {
            message = "核对记录已保存或恢复：仍有待验证/需补采项，后续采样保持锁定；请补齐证据再逐项核对。"
        } else {
            message = "核对记录无效，不能继续扩展。" + (validation["errors"] as? [String] ?? []).joined(separator: "；")
            resetReviewForm()
        }
        reviewGate.stringValue = message; lastReviewMessage = message; status.stringValue = message
        haStatus.stringValue = passed ? "首组人工通过记录已选择，可新建图形向导继续单灯适配、安装与验收。" : "首组尚未通过，HA接入后续工作保持锁定。"
        reviewSummary.string = message + "\n\n" + reviewSummary.string
        reviewSummary.scrollToBeginningOfDocument(nil)
        tabs.selectedSegment = 4; changePage()
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
            baselineKey = nil; activeReviewFile = nil; activeReviewPassed = false
            baselineConnection = nil; collectionID = UUID().uuidString
            reviewGate.stringValue = "数据目录已更换。请采首组，或载入本目录中已经完成的核对记录。"
            reviewReport = nil; reviewReportDirectory = nil; reviewSessionDirectory = nil
            reviewSummary.string = "请先采样或分析一轮，再逐项核对。"; resetReviewForm()
            wizardFile = nil; wizardState = [:]; for field in haDriverEvidence.values { field.stringValue = "" }; haEntityID.stringValue = ""; haInstallNotes.stringValue = ""; changeHACase()
            handoffDirectory = nil; haStatus.stringValue = "数据目录已更换，请载入本目录中有效的首组核对记录。"
            reviewCandidate.removeAllItems(); reviewCandidate.addItem(withTitle: "等待当前目录的重复开关候选")
            for key in reviewIDs { reviewEvidence[key]?.stringValue = "等待当前数据目录的本轮检查。" }
            updateFolderLabel(); reloadReports()
        }
    }

    private func requireDataDirectory() -> URL? {
        if dataDirectory == nil { chooseDataDirectory() }
        return dataDirectory
    }

    @objc private func startDemo() { start(mode: "demo", arguments: []) }
    @objc private func startCollectionDemo() { start(mode: "collection-demo", arguments: []) }
    @objc private func startCollection() {
        guard let directory = requireDataDirectory() else { return }
        start(mode: "collection", arguments: ["--capture-root", directory.path])
    }

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
        guard !captureCleanupUncertain else { alert("先确认清理记录", "上次采样没有确认接口和进程清理，已停止后续采样。请保留日志并人工核对；不要直接换灯重试。"); return }
        guard consent.state == .on else { alert("先确认现场条件", "请确认你在这套房子内，且原 App / 面板均能正常控制同一组普通灯。"); return }
        guard requireDataDirectory() != nil else { return }
        let address = host.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let identifier = udid.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = targetName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let room = targetRoom.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 80, room.count <= 80,
              name.rangeOfCharacter(from: .controlCharacters) == nil,
              room.rangeOfCharacter(from: .controlCharacters) == nil else {
            alert("请填写本轮灯名", "用房间和灯名区分每轮，如客厅主灯。每项最多80字，不能有控制字符；标签不证明线上设备身份。"); return
        }
        let key = room + "\n" + name
        let connection = address + "\n" + identifier.lowercased()
        if let previous = baselineConnection, previous != connection {
            baselineKey = nil; activeReviewFile = nil; activeReviewPassed = false
            reviewGate.stringValue = "连接信息已更换。请先采首组或载入对应主机的有效核对记录。"
            collectionID = UUID().uuidString; baselineConnection = nil
        }
        if let first = baselineKey, key != first,
           (!activeReviewPassed || activeReviewFile == nil) {
            tabs.selectedSegment = 4; changePage()
            alert("先完成首组核对", "请在首组核对页逐项查看证据、选择结论并填写依据。全部必要项人工通过、机器检查合格且原件未改变后，才能换其它灯；也可保持原灯名补采。经验业主可以自行复核。"); return
        }
        var v4 = in_addr(); var v6 = in6_addr()
        guard inet_pton(AF_INET, address, &v4) == 1 || inet_pton(AF_INET6, address, &v6) == 1 else {
            alert("IP 格式不正确", "只填已确认的单个数字 IP，不带端口、网段或命令；不知道时不要猜或扫描。"); return
        }
        let pattern = "^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})$"
        guard identifier.range(of: pattern, options: .regularExpression) != nil,
              !identifier.replacingOccurrences(of: "-", with: "").allSatisfy({ $0 == "0" }) else {
            alert("UDID 格式不正确", "请在 Finder 选中已连接的 iPhone，点击设备信息切换后复制 UDID。不要填序列号。"); return
        }
        var arguments = ["--host-ip", address, "--udid", identifier,
            "--target-label", name, "--room-label", room, "--collection-id", collectionID]
        if activeReviewPassed, let review = activeReviewFile { arguments += ["--review-file", review.path] }
        start(mode: "capture", arguments: arguments)
        if busy {
            if baselineKey == nil { baselineKey = key }
            baselineConnection = connection
            activeCaptureKey = key
        }
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
        lastReviewMessage = nil
        capturePreflightPassed = false
        lastCollectionFailedCount = 0
        lastCaptureStatus = nil; lastError = ""; isStopping = false; activeMode = mode; stderrTail = ""
        taskPanel?.isHidden = false; logPanel?.isHidden = true
        if mode == "capture" { captureContents?.isHidden = true }
        stepTitle.stringValue = mode == "capture" ? "正在检查并准备采样" : mode == "demo" ? "正在生成合成演示" : "正在分析本地样本"
        instruction.stringValue = mode == "capture" ? "本轮：\(targetRoom.stringValue) · \(targetName.stringValue)。系统授权框可能询问Mac管理员密码。" : "全部在本机处理，原始采样只读。"
        promptText.stringValue = ""; clearPrompt(); logView.string = ""; stopButton.isEnabled = true
        progress.isIndeterminate = true; progress.startAnimation(nil); status.stringValue = "任务进行中，结果不会自动上传。"
        do { try process.run() }
        catch { worker = nil; inputPipe = nil; stopButton.isEnabled = false; taskPanel?.isHidden = true; captureContents?.isHidden = false; progress.stopAnimation(nil); alert("未能启动", "应用内置运行组件无法启动。请保留完整应用并重新解压。"); return }
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
        case "capture_preflight": capturePreflightPassed = event["status"] as? String == "validated"
        case "step":
            stepTitle.stringValue = event["title"] as? String ?? "当前步骤"
            let detail = event["instruction"] as? String ?? ""
            instruction.stringValue = activeMode == "capture" ? "本轮：\(targetRoom.stringValue) · \(targetName.stringValue)\n" + detail : detail
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
            if event["report_kind"] as? String == "collection", let summary = event["summary"] as? [String: Any] {
                lastCollectionFailedCount = (summary["failed_count"] as? NSNumber)?.intValue ?? 0
            }
            if let path = event["report_dir"] as? String {
                lastReport = URL(fileURLWithPath: path, isDirectory: true)
                if let session = event["session_dir"] as? String { reportSessions[path] = URL(fileURLWithPath: session, isDirectory: true) }
                reloadReports()
                if event["baseline_assessment"] is [String: Any] {
                    prepareReview(lastReport!, session: reportSessions[path]); tabs.selectedSegment = 4
                } else { tabs.selectedSegment = 3 }
                changePage()
            }
            status.stringValue = "报告已保留在本机。完整报告、原始样本只私下处理。"
        case "review_saved":
            receiveReview(event["validation"] as? [String: Any] ?? [:], path: event["record_path"] as? String)
        case "review_validation":
            receiveReview(event, path: event["review_file"] as? String)
        case "ha_wizard":
            receiveHAWizard(event)
        case "ha_handoff":
            if let path = event["directory"] as? String {
                handoffDirectory = URL(fileURLWithPath: path, isDirectory: true)
                haSummary.string = "私有HA接入研究包已生成：\(handoffDirectory!.lastPathComponent)\n\n包含首组复核记录、完整私有报告、原件索引、单灯离线状态内核与接入步骤。\n\n可以据此继续编写和验证适配器。认证、端口、命令编码及会话参数仍留空；此包不能直接安装为HA集成，也不授权未知控制。\n\n先完成单灯HA开关、面板同步、掉线不可用和重连回读，再逐步扩展。全部文件仅存本机，不上传。"
                lastReviewMessage = "HA接入研究包已生成，实际适配及现场控制仍待验证。"
                tabs.selectedSegment = 5; changePage()
            }
        case "error":
            lastError = event["message"] as? String ?? "工具未完成，请保留提示。"
            if activeMode == "capture" && lastError.contains("首组核对") {
                activeReviewPassed = false; activeReviewFile = nil; reviewGate.stringValue = lastError
            }
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
            if ok && lastCollectionFailedCount > 0 {
                status.stringValue = "汇总文件已生成，但有\(lastCollectionFailedCount)轮失败；请逐轮查看缺口，不能视为采样或对准通过。"
            }
            if ok, let message = lastReviewMessage { status.stringValue = message }
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
        captureContents?.isHidden = false
        if activeMode == "capture", capturePreflightPassed,
           (!finishedEvent || lastCaptureStatus == nil || lastCaptureStatus == "cleanup_incomplete") {
            captureCleanupUncertain = true
        }
        activeCaptureKey = nil
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
                return !linked && (FileManager.default.fileExists(atPath: url.appendingPathComponent("report.json").path) || FileManager.default.fileExists(atPath: url.appendingPathComponent("collection.json").path))
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
        let labels = ["ready": "自动条件齐备", "pending": "待验证", "resample": "需补采", "limited": "存在限制", "reviewable": "可供人工复核", "blocked": "受阻", "pass": "通过", "warn": "需注意", "fail": "未通过", "recorded": "记录完整", "completed": "记录完成", "partial": "部分记录", "skipped": "已跳过", "incomplete": "不完整"]
        return labels[text(value)] ?? text(value)
    }

    private func showCollection(_ directory: URL) {
        let url = directory.appendingPathComponent("collection.json")
        guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size <= 16 * 1024 * 1024,
              let data = try? Data(contentsOf: url), let report = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            reportText.string = "多轮汇总不可读或超过16MiB。请在Finder查看完整文件。"; return
        }
        let summary = report["summary"] as? [String: Any] ?? [:]
        let quality = report["quality"] as? [String: Any] ?? [:]
        var lines = [report["simulation"] as? Bool == true ? "多轮合成演示 · 不是住户通信" : "私有多轮样本汇总 · 来源须逐轮核对",
            "首组先人工核对，再扩展同类普通灯。汇总不会确认设备身份或自动生成HA设置。",
            "原始样本、标签、完整标识和报告只存本机，不发群或公开GitHub。", "",
            "样本轮次：\(text(summary["round_count"]))；分析成功：\(text(summary["analyzed_count"]))；失败：\(text(summary["failed_count"]))",
            "状态：\(evidenceStatus(quality["level"]))；明文帧：\(text(summary["frame_count"]))；跨轮重复标识：\(text(summary["identifier_collision_count"]))", ""]
        for warning in quality["warnings"] as? [String] ?? [] { lines.append("• " + warning) }
        for row in (report["rounds"] as? [[String: Any]] ?? []).prefix(32) {
            let target = row["target_context"] as? [String: Any] ?? [:]
            let metrics = row["summary"] as? [String: Any] ?? [:]
            let steps = row["steps"] as? [String: Any] ?? [:]
            let status = row["status"] as? String == "analyzed" ? "已分析，仍需人工核对" : "失败，保留缺口"
            lines += ["\n\(text(row["round_id"])) · \(text(target["room"])) · \(text(target["label"]))",
                "  业主标签与普通灯类型声明均未验证；\(status)",
                "  核心步骤：\(text(steps["complete_required_count"]))/\(text(steps["required_count"]))；帧：\(text(metrics["frame_count"]))；候选：\(text(metrics["device_count"]))"]
            for gap in row["gaps"] as? [String] ?? [] { lines.append("  • " + gap) }
            if let error = row["error"] as? String { lines.append("  错误：" + error) }
            for device in row["device_candidates"] as? [[String: Any]] ?? [] {
                lines.append("  候选 \(text(device["identifier_hex"]))：App开\(text(device["command_on_count"])) / 关\(text(device["command_off_count"]))；面板状态窗口：\(text(device["panel_state_windows"]))；重进App：\(text(device["reopen_state_windows"]))")
            }
        }
        lines += ["", "跨轮相同字节只提示冲突，不认作同一物理灯，也不证明是两个已知实体。"]
        for collision in report["identifier_collisions"] as? [[String: Any]] ?? [] {
            lines.append("• 标识 \(text(collision["identifier_hex"])) 在多轮出现，需人工逐包复核。")
        }
        lines += ["", "完整逐轮报告见Finder；认证、类型、独立物理状态和HA实机控制仍待验证。"]
        reportText.string = lines.joined(separator: "\n"); reportText.scrollToBeginningOfDocument(nil)
    }
    @objc private func selectReport() {
        let index = reportPicker.indexOfSelectedItem
        guard index >= 0 && index < reportDirectories.count else {
            reportText.string = "尚无本机报告。请先运行演示，或选择已有采样文件夹分析。"; return
        }
        let directory = reportDirectories[index]
        if FileManager.default.fileExists(atPath: directory.appendingPathComponent("collection.json").path) {
            showCollection(directory); return
        }
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
        if let target = report["target_context"] as? [String: Any] {
            lines.insert("本轮业主标签：\(text(target["room"])) · \(text(target["label"]))（身份和设备类型未验证）", at: 3)
        }
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
        let directory = reportDirectories[index]
        let name = FileManager.default.fileExists(atPath: directory.appendingPathComponent("collection.html").path) ? "collection.html" : "报告.html"
        NSWorkspace.shared.activateFileViewerSelecting([directory.appendingPathComponent(name)])
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
