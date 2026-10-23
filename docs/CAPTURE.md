# 单组普通灯：Mac + iPhone

需要MC7021、在家且原App/面板本来能正常控制、Mac现成的Python3/rvictl/tcpdump、iPhone和USB数据线。不同型号、只云端可用或App本来不能控制的情况先记录，不为采样改配置。

1. iPhone连接平常的家庭Wi-Fi，USB接Mac，解锁并信任电脑。正常划掉摩根App，不退出账号。
2. 双击项目根目录的`开始单灯采样.command`。原App或已确认的设备记录只读查看当前MC7021 IP；不能确认时停止，不猜或扫描。iPhone UDID在Finder选中手机后点击设备信息切换并复制。
3. 输入这两个值，再按系统提示输入Mac管理员密码。不要sudo整个脚本。若缺工具或出现安装/安全拦截，先取消并反馈，不关闭安全保护。
4. 按提示：初次进App读状态；App开关各两次；App保持前台而不点开关，用面板开关同一灯；未自动更新时单独记录原有刷新；关闭App后面板改变灯，再重进App读状态。
5. 用数字填写实际灯亮灭及App显示。动作时刻记录为“准备”到“完成确认”的区间，不能代替硬件精确时间。可选恢复这组灯原来的亮灭；不要操作其它设备。
6. 完成后自动停止、保存并清理本次明确创建的RVI。途中q或Control+C同样进入保存；不要强制杀进程。强制终止、断电、磁盘故障可能造成不完整结果。

每次独立保存在本机`captures/MC7021_日期_时间_后缀/`：`traffic.pcap`、`events.jsonl`、`事件记录.txt`、`session.json`、`tcpdump.log`。失败时不一定有PCAP；0包、丢包、跳过或清理失败都会标记。已有该手机RVI时停止，不接管别人的会话。摘要默认声明`external_owner_household`，不表示其它住宅已经验证。

采样只匹配已知主机IP的双向TCP/UDP，不限定9000，不做名称查询或扫描。USB RVI记录iPhone收发，不能看到面板与主机之间的独立Mo-Bus总线，也不会自动解密。收到ACK、App本地变色、主机报告状态和肉眼亮灭要分别核对。

工具没有上传或接收后端。样本回传按[私下提交说明](PRIVATE_SAMPLES.md)；先确认接收者、用途和保存期限，不把原始文件发公开群。

Apple官方：[USB RVI采样原理](https://developer.apple.com/documentation/network/recording-a-packet-trace)、[查找UDID](https://developer.apple.com/documentation/xcode/locating-device-identifiers)。
