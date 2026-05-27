# alarm-cleaner

自动登录车辆信息综合服务平台，批量「补充处理」报警。提供命令行与 tkinter GUI 两种用法。

## 文件

- `main.py` —— 核心 HTTP 逻辑（登录、查询、补充处理），可独立作为命令行工具运行。
- `gui.py` —— tkinter 图形界面：登录后每隔 N 分钟自动处理一次「今天 00:00 ~ 当前时刻」的报警，
  实时显示进度并写入日志文件。

## 命令行用法

```bash
# 处理「昨天一整天」的全部报警
python main.py

# 指定时间窗
python main.py --begin "2026-05-20 00:00:00" --end "2026-05-20 23:59:59"

# 干跑（只查询不提交）
python main.py --dry-run
```

## GUI 用法

```bash
# 本地预览（macOS / Windows / Linux 均可，tkinter 为 Python 标准库）
python gui.py
# 或使用 uv
uv run python gui.py
```

界面操作：填写用户名 / 密码 → 设定间隔（默认 10 分钟）→ 点击「开始」。
登录成功后程序按间隔循环处理报警，过程显示在窗口中，并写入 `logs/alarm-cleaner-YYYYMMDD.log`。
点击「停止」可在当前等待结束前立即中止循环。

## Windows 打包（在线构建）

本机为 macOS（Apple Silicon），无法直接产出 Windows 可执行文件，因此使用 GitHub Actions 在线打包：

- 工作流：[.github/workflows/build-windows.yml](.github/workflows/build-windows.yml)
- 触发方式：
  1. 在 GitHub 仓库 **Actions → Build Windows EXE → Run workflow** 手动触发；或
  2. 推送 `v*` 标签（如 `git tag v0.1.0 && git push --tags`），构建产物会自动附加到对应 Release。
- 产物：`alarm-cleaner.exe`（单文件、无控制台窗口），可在 Actions 运行记录的 Artifacts 中下载。

> 运行 EXE 后，日志会写入 EXE 同目录下的 `logs/` 文件夹。

## 本地构建（仅 Windows 机器）

```bash
pip install pyinstaller requests pycryptodome
pyinstaller --onefile --windowed --name alarm-cleaner --collect-submodules Crypto gui.py
# 产物位于 dist/alarm-cleaner.exe
```
