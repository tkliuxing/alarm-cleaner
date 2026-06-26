#!/usr/bin/env python3
"""命令行入口：登录新平台并按时间窗批量处理报警 / 查岗应答。

新平台为 Vue + REST API，底层逻辑见 api_client.py，
编排见 processors.py，接口调研见 docs/新平台改造设计.md。

用法示例：
  # 干跑（只查询不提交，默认安全）：今天 00:00 ~ 当前时刻
  python main.py --user 江林 --password ****

  # 真实销账 + 应答（去掉 --dry-run 不行，必须显式 --commit）
  python main.py --user 江林 --password **** --commit

  # 指定时间窗、只跑类型1
  python main.py --user 江林 --password **** --begin "2026-06-16 00:00:00" \
      --end "2026-06-16 23:59:59" --no-type2 --no-chagang --commit
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime

import processors
from api_client import PROCESS_MODE_STOP_ALARM, PROCESS_MODES, CgoApiClient


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="报(预)警批量处理 + 查岗应答自动化（新平台）")
    p.add_argument("--user", required=True, help="登录用户名（userCode）")
    p.add_argument("--password", required=True, help="登录密码")
    p.add_argument("--begin", help="起始时间 yyyy-mm-dd HH:MM:SS，默认今天 00:00:00")
    p.add_argument("--end", help="结束时间 yyyy-mm-dd HH:MM:SS，默认当前时刻")
    p.add_argument("--page-size", type=int, default=200)
    p.add_argument("--no-type1", dest="type1", action="store_false", help="不处理 类型1·报警处理")
    p.add_argument("--no-type2", dest="type2", action="store_false", help="不处理 类型2·安全报警")
    p.add_argument("--no-chagang", dest="chagang", action="store_false", help="不处理 查岗应答")
    p.add_argument(
        "--process-mode", type=int, default=PROCESS_MODE_STOP_ALARM,
        help=f"报警处理方式 code（默认 {PROCESS_MODE_STOP_ALARM}=停止报警）；可选: "
             + ", ".join(f"{k}={v}" for k, v in PROCESS_MODES.items()),
    )
    p.add_argument("--process-content", default="报警解除", help="处理说明文本")
    p.add_argument(
        "--commit", action="store_true",
        help="真实提交（销账 / 下发应答）。不加此项时为干跑（只查询不提交）。",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    begin, end = processors.today_time_window()
    begin = args.begin or begin
    end = args.end or end
    dry_run = not args.commit

    def log(msg: str) -> None:
        print(f"[{datetime.now():%F %T}] {msg}")

    client = CgoApiClient(log=log)
    try:
        log(f"登录 {args.user} ...")
        client.login(args.user, args.password)
        if args.chagang and not dry_run:
            # 预先建立查岗应答的 WebSocket 长连接（失败不阻断主流程，发送时会惰性重连）。
            try:
                client.connect_ws()
            except Exception as exc:  # noqa: BLE001
                log(f"预连接查岗 WebSocket 失败（将于下发时重试）：{exc}")

        def relogin(_exc: Exception) -> None:
            log("尝试重新登录 ...")
            client.login(args.user, args.password)
            if args.chagang and not dry_run:
                try:
                    client.connect_ws()
                except Exception as exc:  # noqa: BLE001
                    log(f"重连查岗 WebSocket 失败（将于下发时重试）：{exc}")

        log(f"{'[干跑] ' if dry_run else ''}处理时间窗：{begin} ~ {end}")
        total = processors.process_all(
            client, begin, end,
            page_size=args.page_size,
            dry_run=dry_run,
            run_type1=args.type1,
            run_type2=args.type2,
            run_chagang=args.chagang,
            process_mode=args.process_mode,
            process_content=args.process_content,
            log=log,
            on_error=relogin,
        )
        log(f"完成。本次{'（干跑）' if dry_run else ''}涉及 {total} 条。")
    except Exception as exc:  # noqa: BLE001
        print(f"出错: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
