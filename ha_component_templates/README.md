# 可安装的单灯 HA 桥接层

此目录是通用 HA 集成，**没有摩根协议驱动**。示例 `driver.py` 不联网、不可
安装使用；Mac 引导须替换成业主另行核对的真实驱动并生成私有 `binding.json`。
它不扫描或发现设备，不猜测协议、端口、认证、寄存器或发送字节。

## 驱动接口（版本 1）

驱动只使用 Python 标准库；`DRIVER_API_VERSION = 1`，无参 `Driver` 类实现：

```python
async def async_connect(self, *, host, identifier, on_state, on_disconnect): ...
async def async_set_power(self, power): ...
async def async_request_state(self): ...
async def async_disconnect(self): ...
```

只允许连接指定 `host` 与这一组完整 8 字节 `identifier`，不得发现其他设备、
操作其他通道或写入厂家配置。`async_connect` 返回后才接受回调，随后桥接层
会请求当前独立状态。回调在 HA 事件循环执行：

```python
on_state({'identifier': identifier, 'power': True,
          'source': 'independent_readback'})
on_state({'identifier': identifier, 'power': False,
          'source': 'independent_push'})
on_disconnect()
```

读回和主动上报必须来自实际独立状态解析；ACK、命令成功返回、App缓存或
本地目标值不能调用 `on_state`。每次连接捕获新的接收代次；旧回调被丢弃。
首次及每次重连先独立读回，才能显示可用；断线/状态超过60秒置不可用。
60秒、20秒查询和30秒重连均是可审阅的本地策略，不是厂家心跳结论。
驱动必须非阻塞、可取消；单次操作10秒超时。回调不能带入原始报文或密钥。

Mac 只做语法、接口与哈希核对，不导入或执行驱动。HA 的配置表单在明确
同意前也不导入驱动。**同意后，驱动作为完整权限的 Python 代码在 HA 执行；
静态检查和哈希不能证明代码安全、协议正确或实物身份。** 驱动需求若仍涉及
未知认证或无法独立读回，应补研究，不可填写假值生成包。

## 无终端安装和验收

1. 在 Mac 图形引导通过首组复核，检查并选择真实驱动，生成私有安装ZIP。
2. 用 HA 的 Samba 共享或现有图形文件管理器，把 ZIP 的
   `custom_components/mc7021_single_light` 完整目录复制到 HA 配置目录的
   `custom_components` 下。保留原件；不要覆盖已有同名集成而不核对其用途。
   从 HA 设置的系统菜单重启 HA。不同 HA 安装没有统一上传集成按钮；
   若没有图形文件通道，应先设置现有共享，不需要使用终端来发送灯控命令。
3. HA 设置→设备与服务→添加集成→“MC7021 单灯业主验收”，核对包绑定IP、
   填这一组灯的名称。明确勾选“已审阅并信任驱动代码”与“授权单灯在线读写”。
   未勾选不启动连接；配置流程自身不连接或扫描设备。
4. 打开新增设备。先确认这一盏灯获得当前独立状态。图形界面包含一盏灯、
   “单灯验收步骤”下拉框及五个按钮。先按“清空本轮验收日志重新开始”。
5. 按顺序选择八个步骤，每步按“开始记录所选验收步骤”后才操作。四次 HA
   开/关用灯实体开关；等待实物和独立状态同步后才进入下一步。面板步骤用
   原面板开/关，不点 HA 开关；每步先确认起始状态相反，避免把缓存当新状态。
6. 第七步选择“仅断开本集成，检查不可用”，按开始，再按“仅断开本单灯适配
   连接”，确认 HA 显示不可用。**不关闭厂家主机、面板或家庭网络。** 断开期间
   用原面板把同一盏灯打开。第八步选择“面板开灯后，重连读回”，按开始，再按
   “重连本单灯适配并读回”，确认 HA 由不可用恢复为真实的开灯状态。
7. 设备与服务中，在该集成菜单选择“下载诊断”，把 JSON 留在私下。返回 Mac
   引导导入该诊断并逐项填写实物及 HA 观察，核对八项后生成验收报告。

诊断含本户IP、完整标识、包/复核/驱动哈希和紧凑事件，不含原始报文、凭据
或任意驱动异常。它是**私有材料**，不要发群、公开工单或GitHub。HA 下载可能
把内容包在 `data` 字段下，Mac工具会识别正常包装。日志仅在内存，HA重启或
卸载会丢失；容量1000条，丢日志会标记，不能据截断记录宣称验收通过。

目前只有离线模拟驱动测试，没有本户真实摩根驱动、真实HA安装和实物验收。
人工通过不能自动认证物理反馈；业主仍需将实物观察和报文来源逐项对应。

HA接口参考：[配置流程](https://contributors.home-assistant.io/core/integrations/config-flow/)、
[单灯实体](https://contributors.home-assistant.io/core/entities/light/)、
[诊断](https://contributors.home-assistant.io/core/integrations/diagnostics/)。
