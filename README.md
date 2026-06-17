# alarm-cleaner

自动登录**车辆信息综合服务平台（新版 Vue + API）**，批量处理报警、自动应答查岗。提供命令行与 tkinter GUI 两种用法。


## 文件

- `api_client.py` —— 新平台 HTTP/WebSocket 客户端 `CgoApiClient`（登录、异步报表查询、报警处理、查岗应答）。
- `processors.py` —— 编排层：按时间窗依次跑 类型1 / 类型2 / 查岗，含失败重登。
- `main.py` —— 命令行入口。
- `gui.py` —— tkinter 图形界面：登录后每隔 N 分钟自动处理一次「今天 00:00 ~ 当前时刻」。

## 三类处理

| 功能 | 新平台菜单 | 处理方式 |
| --- | --- | --- |
| 类型1·报警处理 | 报表分析 › 报警查询 › 报警处理查询 | `alarmHandle` processMode=9（补充处理）销账 |
| 类型2·安全报警 | 主动安全 › 证据中心 › 报警处理查询 | 同上 |
| 查岗应答 | 报表分析 › 监管记录 › 查岗记录查询 | WebSocket `sendCmd`，算术题自动求值应答 |

## 安全开关：干跑（dry-run）

所有写操作默认 **dry-run（只查询、打印待提交内容，绝不真实提交）**。
- 命令行：默认干跑；加 `--commit` 才真实销账 / 应答。
- GUI：默认勾选「干跑」；取消勾选会二次确认后真实提交。

## 命令行用法

```bash
# 干跑（推荐先跑）：今天 00:00 ~ 当前时刻，三类都查
python main.py --user NAME --password ****

# 真实提交（销账 + 查岗应答）
python main.py --user NAME --password **** --commit

# 指定时间窗、只跑类型1、用「停止报警(2)」方式
python main.py --user NAME --password **** \
    --begin "2026-06-16 00:00:00" --end "2026-06-16 23:59:59" \
    --no-type2 --no-chagang --process-mode 2 --commit
```

`--process-mode` 取「报警处理方式」字典 code（`dict typeId=19`）：`9`=补充处理（默认）、`2`=停止报警、`4`=确认报警 等。

## GUI 用法

```bash
python gui.py
# 或： uv run python gui.py
```

填写用户名 / 密码 → 设定间隔（默认 10 分钟）→ 选择处理类型 → （默认勾选「干跑」先验证）→ 点击「开始」。
登录成功后按间隔循环处理，过程显示在窗口并写入 `logs/alarm-cleaner-YYYYMMDD.log`。点击「停止」可在当前等待结束前立即中止。

## 依赖

`requests`、`pycryptodome`（登录 RSA）、`websocket-client`（查岗应答）。使用 `uv sync` 安装。

## Windows 打包（在线构建）

本机为 macOS（Apple Silicon），无法直接产出 Windows 可执行文件，使用 GitHub Actions 在线打包：

- 工作流：[.github/workflows/build-windows.yml](.github/workflows/build-windows.yml)
- 触发：仓库 **Actions → Build Windows EXE → Run workflow** 手动触发；或推送 `v*` 标签。
- 产物：`alarm-cleaner.exe`（单文件、无控制台窗口）。

> 运行 EXE 后，日志会写入 EXE 同目录下的 `logs/` 文件夹。

## 本地构建（仅 Windows 机器）

```bash
pip install pyinstaller requests pycryptodome websocket-client
pyinstaller --onefile --windowed --name alarm-cleaner --collect-submodules Crypto gui.py
# 产物位于 dist/alarm-cleaner.exe
```
