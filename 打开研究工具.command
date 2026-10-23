#!/bin/zsh
# Finder entry point. No sudo for the launcher or Python process.
set -u
research_tool_dir="${0:A:h}"
if [[ ! -x /usr/bin/python3 ]]; then
  print '缺少现有Python3，已停止；不会自动安装或连接设备。'
  read -r 'research_close?按回车关闭。'
  exit 1
fi
/usr/bin/python3 "$research_tool_dir/tools/research_tool.py" "$@"
research_exit=$?
if [[ -t 0 ]]; then
  read -r 'research_close?按回车关闭；报告位置见上方。'
fi
exit "$research_exit"
