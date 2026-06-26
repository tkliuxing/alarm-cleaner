#!/usr/bin/env python3
"""新平台编排层：在已登录的 ``CgoApiClient`` 上，按时间窗执行三类自动处理。

复用旧 ``main.process_all`` 的调用约定（同一 begin/end、log 回调、on_error 重登），
但底层全部走新平台接口（见 docs/新平台改造设计.md）：

  - 类型1·报警处理   listId 664 → alarmHandle(processMode=2 停止报警)
  - 类型2·安全报警   listId 738 → alarmHandle(processMode=2 停止报警)
  - 查岗            listId 1143（query_type=1 且 未应答）→ WebSocket sendCmd 应答

注：664 与 738 底层是同一批报警的两个过滤视图（实测 alarm_id 完全重合）。本工具
刻意只按时间窗查询、不加各页内置的 alarm_flag 过滤，从而全量销账——包括像 4007
「驾驶行为监测功能失效报警」这类不在任何页面默认类型列表里的报警（见设计文档 §5.5）。
因此类型1 处理后类型2 多为空跑，保留两者仅为对应两个 UI 入口并兜底轮询间隙的新报警。
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable

from api_client import (
    LIST_ID_TYPE1,
    LIST_ID_TYPE2,
    PROCESS_MODE_STOP_ALARM,
    TIME_FIELD_TYPE1,
    TIME_FIELD_TYPE2,
    CgoApiClient,
)


def today_time_window() -> tuple[str, str]:
    """返回「前一天 00:00:00 ~ 当天 24:00:00」的时间窗（共 48 小时）。

    end 取「当天 24 点」，即次日 00:00:00。
    """
    now = datetime.now()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    begin = (midnight - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    end = (midnight + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    return begin, end


def _process_alarm_report(
    client: CgoApiClient,
    list_id: int,
    time_field: str,
    begin: str,
    end: str,
    *,
    page_size: int,
    dry_run: bool,
    process_mode: int,
    process_content: str,
    log: Callable[[str], None],
) -> int:
    """查询某报表的未处理报警并（补充处理）销账，返回处理条数。"""
    cond = [
        client.dynamic_time_condition(time_field, begin, end),
        # 服务端只取未处理（处理状态=否），避免拉回大量已处理报警。实测生效。
        {"fieldType": "radio", "fieldCode": "is_process", "symbol": "equal", "value": "0"},
    ]
    rows = client.query_report(list_id, cond, page_size=page_size)
    # 服务端已过滤；此处再按 is_process 客户端兜底一次。
    unprocessed = [r for r in rows if client.is_unprocessed(r)]
    log(f"  共 {len(rows)} 行，未处理 {len(unprocessed)} 行")
    if unprocessed:
        client.alarm_handle(
            unprocessed,
            process_mode=process_mode,
            process_content=process_content,
            dry_run=dry_run,
        )
    return len(unprocessed)


def process_type1(client, begin, end, *, page_size=200, dry_run=True,
                  process_mode=PROCESS_MODE_STOP_ALARM, process_content="报警解除",
                  log=print) -> int:
    return _process_alarm_report(
        client, LIST_ID_TYPE1, TIME_FIELD_TYPE1, begin, end,
        page_size=page_size, dry_run=dry_run,
        process_mode=process_mode, process_content=process_content, log=log,
    )


def process_type2(client, begin, end, *, page_size=200, dry_run=True,
                  process_mode=PROCESS_MODE_STOP_ALARM, process_content="报警解除",
                  log=print) -> int:
    return _process_alarm_report(
        client, LIST_ID_TYPE2, TIME_FIELD_TYPE2, begin, end,
        page_size=page_size, dry_run=dry_run,
        process_mode=process_mode, process_content=process_content, log=log,
    )


def process_chagang(client, begin, end, *, page_size=200, dry_run=True, log=print) -> int:
    """查询待应答查岗记录并自动应答（算术求值，WebSocket 下发）。返回应答条数。"""
    rows = client.query_chagang(begin, end, page_size=page_size)
    unanswered = [r for r in rows if client.chagang_unanswered(r)]
    log(f"  共 {len(rows)} 行，待应答 {len(unanswered)} 行")
    return client.reply_chagang(unanswered, dry_run=dry_run)


def process_all(
    client: CgoApiClient,
    begin: str,
    end: str,
    *,
    page_size: int = 200,
    dry_run: bool = True,
    run_type1: bool = True,
    run_type2: bool = True,
    run_chagang: bool = True,
    process_mode: int = PROCESS_MODE_STOP_ALARM,
    process_content: str = "报警解除",
    log: Callable[[str], None] = print,
    on_error: Callable[[Exception], None] | None = None,
) -> int:
    """依次运行所选三类处理，返回总处理条数。

    每类独立 try/except：某类失败（多为 token 过期）不阻断其它类；失败时若提供
    ``on_error`` 回调（例如重新登录）会先调用它再继续下一类。
    """
    tasks: list[tuple[str, Callable[..., int]]] = []
    if run_type1:
        tasks.append(("类型1·报警处理", lambda: process_type1(
            client, begin, end, page_size=page_size, dry_run=dry_run,
            process_mode=process_mode, process_content=process_content, log=log)))
    if run_type2:
        tasks.append(("类型2·安全报警", lambda: process_type2(
            client, begin, end, page_size=page_size, dry_run=dry_run,
            process_mode=process_mode, process_content=process_content, log=log)))
    if run_chagang:
        tasks.append(("查岗", lambda: process_chagang(
            client, begin, end, page_size=page_size, dry_run=dry_run, log=log)))

    total = 0
    for name, fn in tasks:
        log(f"----- {name} -----")
        try:
            total += fn() or 0
        except Exception as exc:  # noqa: BLE001 - 单类失败不应中断其它类
            log(f"  {name} 出错：{exc}")
            if on_error is not None:
                on_error(exc)
    return total
