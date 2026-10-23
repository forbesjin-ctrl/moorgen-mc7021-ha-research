# Moorgen MC7021 × Home Assistant

业主共同研究保留 **MC7021 主机和原面板** 的 Home Assistant 接入方式。首个目标只有一组普通灯：能明确开/关，并在原面板操作或重连后取得独立状态。

**当前是研究工具，尚不是可安装的 Home Assistant/HACS 集成。** 已有离线采样工具、明文帧解析和原厂 App 静态证据摘要；尚无在本项目登记的住户实测兼容组合。采样完成、执行 ACK 或 App 按钮变色均不等于真实灯状态已验证。

这是业主自发项目，非厂家项目。代码和文档公开，住户原始抓包只私下提交。

## 业主怎样参加

先找一位在自己家、主机明确为MC7021、原厂App和面板本来就能正常控制普通灯的业主，使用Mac、iPhone和USB数据线采样。只操作同一组普通灯，不扫描设备、不改主机/面板/路由器配置，不涉及场景、总断电或安防。

下载并完整解压项目，在Finder双击 **[开始单灯采样.command](开始单灯采样.command)**。只填自己主机当前IP与iPhone UDID；按提示正常操作，回车和数字记录实际灯与App显示。系统需要一次Mac管理员授权，密码不会进入日志。Mac需已有Python3和Apple的rvictl；缺少时停止，不自动安装。

结果仅存在本机 `captures/`，没有上传功能。每户样本分别标记，先只公开匿名现象和版本组合。原始PCAP可能含认证及会话信息，不上传Issue、PR或业主群。详见[采样操作](docs/CAPTURE.md)和[私下提交样本](docs/PRIVATE_SAMPLES.md)。

## 程序员可以做什么

- 核对明文帧、TLV、设备类型和状态语义，补充合成测试；从真实样本得出的结论注明匿名来源和版本组合。
- 分别验证认证/加密、目标完整标识、初次同步、面板变化、刷新回读与重连。
- 在证据足够后实现一个普通灯HA原型，状态来自已确认的设备报告；断线或未知时不可假定已成功。

当前工具没有网络控制或重放接口。`tools/offline_shcp.py`只解析本地应用层HEX，也可在内存生成合成候选帧；它不是PCAP解析器，生成的字节不会发送。配置偏移和内部引用不能当通信地址，Mo-Bus或9000端口不能直接等同标准Modbus。

## 离线运行

工具仅依赖Python标准库。真实采样支持Mac；离线解析和测试可在有Python3.9+的Mac/Linux运行。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 tools/check_public_tree.py
```

不接手机的提示演练：

```sh
python3 tools/capture_mc7021_light.py --demo
```

演练结果放在 `demo_runs/`，明确标记模拟，不生成PCAP。`captures/`、`demo_runs/`、`private_reports/`等目录被Git忽略，公开清单检查还会拒绝跟踪原始抓包、日志和未知文件。

## 资料和当前状态

- [协议候选及证据边界](docs/PROTOCOL_CANDIDATE.md)：普通灯命令、明文帧、独立状态、认证与加密条件。
- [兼容性记录](docs/COMPATIBILITY.md)：按型号、固件、App平台/版本分别登记，不按品牌宣称全系可用。
- [阶段目标](docs/ROADMAP.md)：先完成单灯闭环，再考虑扩展。
- [贡献方式](CONTRIBUTING.md)：业主、协议分析和开发任务。

代码和文档采用[MIT许可](LICENSE)。不随项目分发原厂APK、反汇编、住户配置或第三方原始报文；公开研究来源在协议说明中列出。
