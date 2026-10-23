# Mac 图形应用的构建与运行时来源

普通参与者使用发布的 `MC7021-Mac-v0.4.0-universal2.zip`，完整解压后打开 `MC7021 单灯研究工具.app`。应用名称保留兼容，窗口版本为v0.4.0，每轮仍只操作一组普通灯。演示、分析、报告查看均不需要另装 Python、Xcode 或打开终端。真实采样仍要求现场 iPhone、原 App 正常控制和已具备 Apple `rvictl`；图形应用不会自动安装这些工具。

以下步骤供维护者从源码重复构建。构建不是逐字节可复现声明：编译器版本、Mach-O 标识和签名会影响最终 ZIP。每次生成的构建清单记录源码和 ZIP 的 SHA256。

## 构建需求

- macOS，完整 Xcode 和支持 arm64、x86_64 的 Swift SDK；构建脚本本身需要 Python 3.9+。
- 三份从下列官方固定发布取得的本地归档。脚本不下载、不联网、不提权、不安装软件。
- 显式指定一个新的工作区输出目录。脚本不覆盖已有应用，不向 `/Applications` 或用户主目录安装。

Swift 原生窗口编译为 universal2，最低系统目标 macOS 12.0。资源内分别放置 Apple Silicon 和 Intel 的完整 CPython 3.12.14，应用按自身运行架构选择。静态检查确认两套运行时架构；在一台机器上只执行本机架构的标准库导入检查。Intel 真机和 macOS 12 实际运行仍需单独验证，不能由交叉编译代替。

## 固定来源与校验

运行时来自 [Astral 维护的 python-build-standalone](https://github.com/astral-sh/python-build-standalone)，固定 [20260901 发布](https://github.com/astral-sh/python-build-standalone/releases/tag/20260901)。[上游运行文档](https://gregoryszorc.com/docs/python-build-standalone/main/running.html)说明了两种 macOS 架构、可独立使用的安装归档及许可证要求。

下载链接与 SHA256：

- [Apple Silicon install_only_stripped](https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.12.14%2B20260901-aarch64-apple-darwin-install_only_stripped.tar.gz)
  `81a359f1cfadd4da11766534c5913791cea55f26e1bb902cacd2a531bb1e4b2b`
- [Intel install_only_stripped](https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.12.14%2B20260901-x86_64-apple-darwin-install_only_stripped.tar.gz)
  `65b195c9cedc1fef6767f044f9822069adbd1bd9204d424ece4628776fdc04bb`
- [同一发布的 full 归档，仅补充依赖许可证](https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.12.14%2B20260901-aarch64-apple-darwin-pgo%2Blto-full.tar.zst)
  `dbefa04d4107b449e17022f9c78d3eacbd37a1aa8c166c6220dbd95addf3f318`

维护者应从上游发布页核对这些值，并先保存归档。构建脚本逐个比较内置固定 SHA256，全部通过后才解压，完成签名后才启动本机 CPython 做无网络的标准库检查。SHA256 不符即停止，没有跳过校验的选项。

完整归档仅读取 `python/licenses/LICENSE.*.txt` 和许可元数据，不复制或执行其 build 对象；这些依赖许可文本随应用置于 `Contents/Resources/Licenses`。两套安装归档中的 Python、pip 和其附带许可文本也全部保留。自写代码为 MIT；内置运行时各自服从原许可证，不能统一声称为本项目 MIT。

## 构建命令

在仓库根目录，用维护者保存的三个本地路径替换示例占位路径：

```sh
python3 tools/build_macos_app.py \
  --arm64-archive work/cpython-3.12.14+20260901-aarch64-apple-darwin-install_only_stripped.tar.gz \
  --x86_64-archive work/cpython-3.12.14+20260901-x86_64-apple-darwin-install_only_stripped.tar.gz \
  --licenses-archive work/cpython-3.12.14+20260901-aarch64-apple-darwin-pgo+lto-full.tar.zst \
  --output-dir artifacts/macos-v0.4.0 \
  --version 0.4.0
```

脚本输出 `.app`、保留符号链接与可执行权限的 ZIP，以及构建 JSON。源码只复制 `TOOL_FILES` 和 `DOCUMENT_FILES` 中列出的自写文件；不复制整个项目文件夹。住户配置、实际抓包、事件记录、私有报告、源码压缩包、APK、Git 历史和构建缓存均不在应用输入范围内。

v0.4.0的工具清单为11个文件：`gui_worker.py`、`gui_capture_backend.py`、`capture_mc7021_light.py`、`analyze_capture.py`、`demo_sample.py`、`offline_shcp.py`、`pcap_reader.py`、`report_view.py`、`light_state_model.py`、`research_tool.py`、`collection_report.py`。文档清单为6个文件：`MAC_APP_BUILD.md`、`MAC_GUI.md`、`CAPTURE.md`、`AFTER_CAPTURE.md`、`PRIVATE_SAMPLES.md`、`MULTI_DEVICE.md`；另单独复制`README.md`和自写代码的`LICENSE`。运行时及其许可按前述固定来源单独打包。多轮演示在应用运行时生成，不把演示PCAP或报告作为应用资源分发。

可分别用 `lipo -archs`、`codesign --verify --deep --strict` 和 ZIP SHA256 检查产物。签名方式是 **ad-hoc**，没有付费 Developer ID 签名，也没有 Apple 公证。不要称它为已通过 Gatekeeper 或已获 Apple 认证。用户通过互联网下载时可能遇到系统提示；保留提示并按图形使用说明处理，不应让用户全局关闭 Gatekeeper。

应用打包不会执行采样，不创建 RVI、不弹出管理员授权，也不访问任何家庭设备。

v0.4.0的首组人工声明和多轮汇总不改变验证边界：住户真实通信样本为0，真实USB采样及管理员授权尚未现场验证，Intel和macOS12真机尚未测试。构建成功、合成演示或汇总成功不能替代这些验证，也不能证明HA已经兼容。
