#!/usr/bin/env python3
"""Chinese entry menu: capture, complete synthetic demonstration, local analysis.

The optional browser opening is a local file only. No server/upload endpoint.
"""
import argparse
from pathlib import Path
import shlex
import sys
import webbrowser

try:
    from .analyze_capture import analyze_session, ROOT
    from .demo_sample import create_demo_sample, DEVICE
except ImportError:
    from analyze_capture import analyze_session, ROOT
    from demo_sample import create_demo_sample, DEVICE


def show_report(destination, report, open_browser=True):
    path = destination / '报告.html'
    print('\n报告已生成：{}\n完整帧：{}，设备候选：{}。'.format(path,
        report['summary']['frame_count'], report['summary']['device_count']))
    print('完整报告/抓包只私下处理；匿名摘要也请先本人审阅。HA实机接入尚未验证。')
    if open_browser:
        try:
            if not webbrowser.open(path.resolve().as_uri()):
                print('未能自动打开浏览器，请在Finder双击报告.html。')
        except (OSError, webbrowser.Error):
            print('未能自动打开浏览器，请在Finder双击报告.html。')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='complete synthetic demonstration, no capture')
    parser.add_argument('--session-dir', type=Path, help='analyze an existing local session directory')
    parser.add_argument('--no-open', action='store_true', help='do not open the local HTML report')
    args = parser.parse_args(argv)
    print('摩根 MC7021 单灯研究工具 v0.2.0\n采样 → 私有报告 → 人工核对 → 单灯HA适配研究')
    if args.demo and args.session_dir:
        parser.error('--demo与--session-dir不能同时使用')
    try:
        if args.demo:
            selection = '2'
        elif args.session_dir:
            selection = '3'
        else:
            print('\n1 开始真实采样，结束后自动分析\n2 完整离线演示（自动生成合成报文和报告）\n3 分析已有采样文件夹\n4 退出')
            selection = input('选择1/2/3/4：').strip()
        if selection in ('4', 'q', ''):
            return 0
        if selection == '1':
            print('仅供在家且原App与面板均能正常控制同一组普通灯时使用。')
            try:
                from . import capture_mc7021_light as capture
            except ImportError:
                import capture_mc7021_light as capture
            # Same backend checks as the direct capture tool; does not scan.
            capture.SystemBackend().prepare()
            return capture.main(['--analyze-after'])
        if selection == '2':
            print('全部报文和观察为合成数据，不连接手机，不提权，不抓包，不操作灯。')
            directory = create_demo_sample(ROOT / 'demo_runs')
            destination, report = analyze_session(directory, ordinary_ids=(DEVICE,))
        elif selection == '3':
            if args.session_dir:
                directory = args.session_dir
            else:
                text = input('把含session.json/events.jsonl/traffic.pcap的文件夹拖进终端，再回车：').strip()
                values = shlex.split(text)
                if len(values) != 1:
                    raise ValueError('请选择一个完整采样文件夹；不要输入命令')
                directory = Path(values[0]).expanduser()
            destination, report = analyze_session(directory)
        else:
            raise ValueError('请选择1、2、3或4')
        show_report(destination, report, not args.no_open)
        return 0
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as error:
        print('\n未完成：{}\n不会扫描、写设备配置或自动安装工具；原始文件保留。'.format(error))
        return 1
    except RuntimeError as error:
        print('\n采样未开始或已停止：{}\n先保留提示，不更改设备配置。'.format(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
