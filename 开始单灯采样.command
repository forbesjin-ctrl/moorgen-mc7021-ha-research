#!/bin/zsh
# Double-click in Finder. Do not sudo this launcher.
set -u
capture_launcher_dir="${0:A:h}"
capture_demo=0
for capture_arg in "$@"; do
  [[ "$capture_arg" == '--demo' ]] && capture_demo=1
done
if [[ "$capture_demo" == 0 ]]; then
  for capture_tool in /Library/Apple/usr/bin/rvictl /usr/sbin/tcpdump /usr/bin/sudo; do
    if [[ ! -x "$capture_tool" ]]; then
      print "缺少现有系统工具：$capture_tool"
      print '本次停止，不自动安装，不连接手机或抓包。'
      if [[ -t 0 ]]; then
        read -r 'capture_close?按回车关闭。'
      fi
      exit 1
    fi
  done
fi
if [[ ! -x /usr/bin/python3 ]]; then
  print '缺少Mac Python3。本次未安装软件、未连接手机或抓包。'
  read -r 'capture_close?按回车关闭。'
  exit 1
fi
/usr/bin/python3 "$capture_launcher_dir/tools/capture_mc7021_light.py" "$@"
capture_exit=$?
if [[ -t 0 ]]; then
  read -r 'capture_close?按回车关闭此窗口；结果已保存在上方显示的目录。'
fi
exit "$capture_exit"
