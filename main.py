#!/usr/bin/env python3
"""
自动登录内蒙古寰游天下车辆信息综合服务平台，查询并批量"补充处理"报警。

基本流程：
  1. 登录 (POST /CGO8/Login/setSessionAbandon, POST /CGO8/Login/ProSubmit)
     密码：MD5 → RSA(PKCS#1 v1.5, 1024 bit) → base64 → encodeURIComponent
  2. 查询报警 (POST /TopGps/Report/AlarmProcessQuery/Search)
  3. 逐页"补充处理"：
     - GET /TopGps/Report/AlarmProcessQuery/AlarmEXProc?ids=...
       从 HTML 中抓取 __RequestVerificationToken
     - POST /TopGps/Report/AlarmProcessQuery/AlarmEXProc?ids=...
       提交 ProMode=补充处理 + AlarmId (uniqueid|begintime 的逗号串)

用法示例：
  # 处理"昨天一整天"的全部报警
  python3 main.py

  # 指定时间窗
  python3 main.py --begin "2026-05-20 00:00:00" --end "2026-05-20 23:59:59"

  # 只处理第一页 50 行（最接近 UI 的"全选当前页+补充处理"行为）
  python3 main.py --first-page-only

  # 干跑（只查询不提交）
  python3 main.py --dry-run

"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Callable

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

BASE = "http://116.113.104.68:8188"

LOGIN_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF8q75qA4tcm6kJNj2aCj33/4QfNgA"
    "E1Q4U7z8KpYoqrULOOqcjkB3HKjSz9XcQMih4+swV8YNqthnerrV8mK1TGdGptObzBN0"
    "eQBV0dcvL9/g21qxAkBV9kMaXCWAPmRyfX3JW2/b1lGwfsYUySKqeNPiTYMgzypreTj/"
    "7MDkWwIDAQAB"
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

# Search 默认参数（来源：抓取了页面 datagrid('options').queryParams）
DEFAULT_SEARCH_PARAMS = {
    "OrgAndCarList.OrgId": "7250",            # 1 = 根组织
    "OrgAndCarList.Text": "土右运管所",
    "OrgAndCarList.CarId": "",
    "OrgAndCarList.CarNun": "",
    "QuickChoice": "0",
    "ComboTree_AlarmFlag": "-1_t6",
    "AlarmFlag.Value": (
        "-1_t1_1,-1_t1_2,-1_t1_4,-1_t1_8192,-1_t1_16384,-1_t1_262144,"
        "-1_t1_8388608,-1_t1_4294967296,-1_t1_17179869184,-1_t1_34359738368,"
        "-1_t1_137438953472,-1_t1_140737488355328,-1_t1_2251799813685248,"
        "-1_t1_4503599627370496,-1_t1_9007199254740992,"
        "-1_t1_18014398509481984,-1_t2_16,-1_t2_32,-1_t2_64,-1_t2_128,"
        "-1_t2_256,-1_t2_512,-1_t2_1024,-1_t2_2048,-1_t2_4096,"
        "-1_t2_16777216,-1_t2_33554432,-1_t2_67108864,-1_t2_134217728,"
        "-1_t2_268435456,-1_t2_68719476736,-1_t2_274877906944,"
        "-1_t2_549755813888,-1_t3_536870912,-1_t3_1073741824,-1_t4_8,"
        "-1_t4_524288,-1_t4_1048576,-1_t4_2097152,-1_t4_4194304,"
        "-1_t4_2147483648,-1_t4_1152921504606846976,-1_t5_1099511627776,"
        "-1_t5_2199023255552,-1_t5_4398046511104,-1_t5_8796093022208,"
        "-1_t5_17592186044416,-1_t5_35184372088832,-1_t5_70368744177664,"
        "-1_t5_281474976710656,-1_t5_562949953421312,-1_t5_1125899906842624,"
        "-1_t5_36028797018963968,-1_t5_144115188075855872,"
        "-1_t5_288230376151711744,-1_t5_576460752303423488,"
        "-1_t5_4611686018427387904,-1_t6_8589934592,-1_t6_72057594037927936"
    ),
    "OperateType.SelectedValue": "0",
    "AlarmSorce.SelectedValue": "0",
    "RiskLevel.Value": "",
    "MoreOrLess.SelectedValue": "0",
    "Speed.Value": "0",
    "AlarmTime.Value": "0",
    "ProcessModel.SelectedValue": "0",
    "ProcessResult.SelectedValue": "0",
    "ProStatus.SelectedValue": "0",
    "UPTicket.SelectedValue": "0",
    "UserName.Value": "",
    "IsMisreport.SelectedValue": "-1",
}

DEFAULT_SEARCH_PARAMS2 = {
    'OrgAndCarList.OrgId': '7250',
    'OrgAndCarList.Text': '土右运管所',
    'OrgAndCarList.CarId': '',
    'OrgAndCarList.CarNun': '',
    'QuickChoice': '0',
    'RptTimeCtrl.BeginTime': '2026-05-27 00:00:00',
    'RptTimeCtrl.EndTime': '2026-05-28 00:00:00',
    'alarmDetail_DriverName.Value': '',
    'alarmDetail_DriverId.Value': '',
    'Speed.Value': '',
    'VehicleTypeCode.SelectedValue': '0',
    'NickName.Value': '',
    'AlarmFlagTreeCheckBox_AlarmFlag': '8_4',
    'AlarmFlag.Value': '0,1,1_1,1_2,1_4,1_8,1_16,1_32,1_64,1_32768,1_65536,2,2_1073741824,2_4294967296,2_8589934592,2_17179869184,2_34359738368,2_68719476736,2_274877906944,2_70368744177664,2_140737488355328,2_281474976710656,2_562949953421312,2_2305843009213693952,2_4611686018427387904,2_2147483648,4,4_1,4_2,4_4,4_8,4_16,8,8_1,8_2,8_4',
    'AlarmLevel.SelectedValue': '0',
    'DangerType.SelectedValue': '0',
    'UPTicket.SelectedValue': '0',
    'ProcessModel.SelectedValue': '0',
    'ProStatus.SelectedValue': '2',
    'ProName.Value': '',
    'IsMisreport.SelectedValue': '-1',
    'HasReceiveAttachmentOption.SelectedValue': '0',
    'HasReceiveAttachmentNum.Value': '',
}

def encrypt_password(plain: str) -> str:
    """对密码做 MD5 后再用 RSA(PKCS#1 v1.5) 加密，与前端 JEncryptPwd 行为一致。"""
    md5_hex = hashlib.md5(plain.encode("utf-8")).hexdigest()  # 32 字符
    der = base64.b64decode(LOGIN_PUBLIC_KEY_B64)
    rsa_key = RSA.import_key(der)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(md5_hex.encode("ascii"))
    return base64.b64encode(encrypted).decode("ascii")


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept-Language": "zh-CN,zh;q=0.9",
        }
    )
    return s


def login(session: requests.Session, username: str, password: str) -> None:
    # 1) 首页（拿到第一波 cookie / __RequestVerificationToken）
    session.get(f"{BASE}/cgo8", timeout=30)

    enc_pwd = encrypt_password(password)

    # 前端调用 encodeURIComponent 后再让 jQuery 再做一次 form 编码，
    # 形成"双重 URL 编码"。我们这里手动模拟第一层 encodeURIComponent，
    # requests 会再做一次表单编码。
    user_enc = urllib.parse.quote(username, safe="")
    pwd_enc = urllib.parse.quote(enc_pwd, safe="")
    url_enc = urllib.parse.quote(BASE, safe="")

    # 2) setSessionAbandon
    session.post(
        f"{BASE}/CGO8/Login/setSessionAbandon",
        data={"userId": user_enc},
        headers={
            "Referer": f"{BASE}/cgo8",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "text/plain, */*; q=0.01",
        },
        timeout=30,
    )

    # 3) ProSubmit
    resp = session.post(
        f"{BASE}/CGO8/Login/ProSubmit",
        data={
            "user": user_enc,
            "pwd": pwd_enc,
            "pType": "mrs",
            "isRemember": "0",
            "url": url_enc,
            "vcode": "",
            "lType": "0",
        },
        headers={
            "Referer": f"{BASE}/cgo8",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "text/plain, */*; q=0.01",
        },
        timeout=30,
    )

    body = resp.text.strip()
    parts = body.split("|")
    if not parts or parts[0] != "0":
        raise RuntimeError(f"登录失败: {body!r}")

    # 4) 把主框架 cookie 拉齐
    session.get(f"{BASE}/CGO8/MainPage/", timeout=30)
    # 给报表子系统种 cookie
    session.get(f"{BASE}/TopGps/Index/?sys=TopReport", timeout=30)


def search_alarms(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        page: int = 1,
        rows: int = 50,
        extra: dict | None = None,
    ) -> dict:
    """查询报警，返回 {"total": int, "rows": [...]}。"""
    params = dict(DEFAULT_SEARCH_PARAMS)
    params["RptTimeCtrl.BeginTime"] = begin_time
    params["RptTimeCtrl.EndTime"] = end_time
    params["ProStatus.SelectedValue"] = '2'
    params["page"] = str(page)
    params["rows"] = str(rows)
    if extra:
        params.update(extra)

    resp = session.post(
        f"{BASE}/TopGps/Report/AlarmProcessQuery/Search",
        data=params,
        headers={
            "Referer": f"{BASE}/TopGps/Report/AlarmProcessQuery",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if "rows" not in data:
        raise RuntimeError(f"搜索接口未返回 rows: {data}")
    return data


def search_alarms2(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        page: int = 1,
        rows: int = 50,
        extra: dict | None = None,
    ) -> dict:
    """查询报警，返回 {"total": int, "rows": [...]}。"""
    params = dict(DEFAULT_SEARCH_PARAMS2)
    params["RptTimeCtrl.BeginTime"] = begin_time
    params["RptTimeCtrl.EndTime"] = end_time
    params["ProStatus.SelectedValue"] = '2'
    params["page"] = str(page)
    params["rows"] = str(rows)
    if extra:
        params.update(extra)

    resp = session.post(
        f"{BASE}/CGO8/SafeAnly/SafeAlarmProRpt/Search",
        data=params,
        headers={
            "Referer": f"{BASE}/CGO8/SafeAnly/SafeAlarmProRpt",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if "rows" not in data:
        raise RuntimeError(f"搜索接口未返回 rows: {data}")
    return data


def search_chagang(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        page: int = 1,
        rows: int = 50,
        extra: dict | None = None,
    ) -> dict:
    """查询报警，返回 {"total": int, "rows": [...]}。"""
    params = {
        "QueryType.SelectedValue": "0",
        "QueryId.Value": "",
        "QuickChoice": "0",
        "UserName.Value": "",
        "QueryPlatform.Value": "",
        "Remark.Value": "",
    }
    params["RptTimeCtrl.BeginTime"] = begin_time
    params["RptTimeCtrl.EndTime"] = end_time
    params["IsResponse.SelectedValue"] = '2'
    params["page"] = str(page)
    params["rows"] = str(rows)
    if extra:
        params.update(extra)

    resp = session.post(
        f"{BASE}/TopGps/Report/PlatformQuery/Search",
        data=params,
        headers={
            "Referer": f"{BASE}/TopGps/Report/PlatformQuery",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if "rows" not in data:
        raise RuntimeError(f"搜索接口未返回 rows: {data}")
    return data


_TOKEN_RE = re.compile(
    r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
    re.IGNORECASE,
)


def fetch_verify_token(session: requests.Session, ids_param: str) -> str:
    """打开 AlarmEXProc 弹窗页，从返回的 HTML 中抓 __RequestVerificationToken。"""
    url = (
        f"{BASE}/TopGps/Report/AlarmProcessQuery/AlarmEXProc"
        f"?ids={urllib.parse.quote(ids_param, safe=',')}"
        f"&rd={time.time():.16f}&pop=1&popName=_dialog_window_normal"
    )
    resp = session.get(
        url,
        headers={"Referer": f"{BASE}/TopGps/Report/AlarmProcessQuery"},
        timeout=30,
    )
    resp.raise_for_status()
    m = _TOKEN_RE.search(resp.text)
    if not m:
        raise RuntimeError("未能从弹窗页面中找到 __RequestVerificationToken")
    return m.group(1), url


def fetch_verify_token2(session: requests.Session) -> str:
    """打开 AlarmEXProc 弹窗页，从返回的 HTML 中抓 __RequestVerificationToken。"""
    url = (
        f"{BASE}/CGO8/SafeAnly/SafeAlarmProRpt/AlarmPro?pop=1&popName=_dialog_window_"
    )
    resp = session.get(
        url,
        headers={"Referer": f"{BASE}/CGO8/SafeAnly/SafeAlarmProRpt"},
        timeout=30,
    )
    resp.raise_for_status()
    m = _TOKEN_RE.search(resp.text)
    if not m:
        raise RuntimeError("未能从弹窗页面中找到 __RequestVerificationToken")
    return m.group(1), url


def build_alarm_id2(rows: list[dict]) -> str:
    """按页面前端逻辑拼接：uniqueid，逗号分隔。"""
    parts = []
    for r in rows:
        parts.append(r.get("uniqueid") or r.get("alarmid") or "")
    return ",".join(parts)


def build_alarm_id(rows: list[dict]) -> str:
    """按页面前端逻辑拼接：uniqueid|begintime，逗号分隔。"""
    parts = []
    for r in rows:
        uniqueid = r.get("uniqueid") or r.get("alarmid") or ""
        begintime = r.get("begintime") or ""
        parts.append(f"{uniqueid}|{begintime}")
    return ",".join(parts)


def supplement_process(
        session: requests.Session,
        rows: list[dict],
        pro_mode: str = "补充处理",
        remark: str = " ",
    ) -> str:
    """对给定的报警行执行"补充处理"。返回响应文本。"""
    if not rows:
        return ""
    # ids 参数用 rownum（前端用的就是这个；服务器结合 session 还原数据）
    ids_param = ",".join(str(r["rownum"]) for r in rows)

    token, ref_url = fetch_verify_token(session, ids_param)
    alarm_id = build_alarm_id(rows)

    resp = session.post(
        f"{BASE}/TopGps/Report/AlarmProcessQuery/AlarmEXProc"
        f"?ids={urllib.parse.quote(ids_param, safe=',')}"
        f"&rd={time.time():.16f}&pop=1&popName=_dialog_window_normal",
        data={
            "__RequestVerificationToken": token,
            "ProMode": pro_mode,
            "AlarmId": alarm_id,
            "Remark": remark,
        },
        headers={
            "Referer": ref_url,
            "Origin": BASE,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.text


def supplement_process2(
        session: requests.Session,
        rows: list[dict],
        pro_mode: str = "补充处理",
        remark: str = " ",
    ) -> str:
    """对给定的报警行执行"补充处理"。返回响应文本。"""
    if not rows:
        return ""
    # ids 参数用 rownum（前端用的就是这个；服务器结合 session 还原数据）

    token, ref_url = fetch_verify_token2(session)
    alarm_id = build_alarm_id2(rows)

    resp = session.post(
        f"{BASE}/CGO8/SafeAnly/SafeAlarmProRpt/AlarmPro"
        f"?pop=1&popName=_dialog_window_normal",
        data={
            "__RequestVerificationToken": token,
            "ProMode": pro_mode,
            "UniqueId": alarm_id,
            "Remark": remark,
        },
        headers={
            "Referer": ref_url,
            "Origin": BASE,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.text


def process_once(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        org_id: str = "1",
        page_size: int = 50,
        dry_run: bool = False,
        all_pages: bool = True,
        log: Callable[[str], None] = print,
    ) -> int:
    """执行一轮完整的查询 + 补充处理，返回本轮实际处理的行数。

    通过 ``log`` 回调输出进度，便于 CLI（print）与 GUI（日志窗口）复用同一逻辑。
    调用方需保证 ``session`` 已经登录。
    """
    extra = {"OrgAndCarList.OrgId": org_id}

    total_done = 0
    page = 1
    while True:
        log(f"查询第 {page} 页 ({begin_time} ~ {end_time}) ...")
        data = search_alarms(
            session,
            begin_time=begin_time,
            end_time=end_time,
            page=page,
            rows=page_size,
            extra=extra,
        )
        rows = data.get("rows") or []
        total = int(data.get("total") or 0)
        log(f"  本页 {len(rows)} 行 / 共 {total} 行")
        if not rows:
            break

        if not dry_run:
            resp_text = supplement_process(session, rows)
            log(f"  提交完成: {resp_text[:200]}")
            total_done += len(rows)
        else:
            log("  [dry-run] 跳过提交")

        if not all_pages:
            break
        if page * page_size >= total:
            break
        page += 1
        time.sleep(0.5)

    return total_done


def process_once2(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        org_id: str = "1",
        page_size: int = 50,
        dry_run: bool = False,
        all_pages: bool = True,
        log: Callable[[str], None] = print,
    ) -> int:
    """执行一轮完整的查询 + 补充处理，返回本轮实际处理的行数。

    通过 ``log`` 回调输出进度，便于 CLI（print）与 GUI（日志窗口）复用同一逻辑。
    调用方需保证 ``session`` 已经登录。
    """
    extra = {"OrgAndCarList.OrgId": org_id}

    total_done = 0
    page = 1
    while True:
        log(f"查询第 {page} 页 ({begin_time} ~ {end_time}) ...")
        data = search_alarms2(
            session,
            begin_time=begin_time,
            end_time=end_time,
            page=page,
            rows=page_size,
            extra=extra,
        )
        rows = data.get("rows") or []
        total = int(data.get("total") or 0)
        log(f"  本页 {len(rows)} 行 / 共 {total} 行")
        if not rows:
            break

        if not dry_run:
            resp_text = supplement_process2(session, rows)
            log(f"  提交完成: {resp_text[:200]}")
            total_done += len(rows)
        else:
            log("  [dry-run] 跳过提交")

        if not all_pages:
            break
        if page * page_size >= total:
            break
        page += 1
        time.sleep(0.5)

    return total_done


def fetch_verify_token_chagang(session: requests.Session, chagang_id: str):
    """打开 SupplyReply 弹窗页，从返回的 HTML 中抓 __RequestVerificationToken。"""
    url = (
        f"{BASE}/TopGps/Report/PlatformQuery/SupplyReply?id={chagang_id}&pop=1&popName=_dialog_window_normal"
    )
    resp = session.get(
        url,
        headers={"Referer": f"{BASE}/TopGps/Report/PlatformQuery"},
        timeout=30,
    )
    resp.raise_for_status()
    m = _TOKEN_RE.search(resp.text)
    if not m:
        raise RuntimeError("未能从弹窗页面中找到 __RequestVerificationToken")
    uniq_re = re.compile(
        r'name="UniqueId"[^>]*value="([^"]+)"',
        re.IGNORECASE,
    )
    um = uniq_re.search(resp.text)

    return m.group(1), url, um.group(1) if um else ''


def calc_suanshi(suanshi: str) -> str:
    """
    计算简单加减法算式字符串，返回结果字符串。
    
    示例:
        calc_expression("1+1=")   -> "2"
        calc_expression("10-7=")  -> "3"
    """
    # 去掉末尾的等号
    expr = suanshi.strip().rstrip("=")
    
    # 解析运算符和数字
    for op in ("+", "-"):
        if op in expr:
            left, right = expr.split(op, 1)
            a = int(left.strip())
            b = int(right.strip())
            result = a + b if op == "+" else a - b
            return str(result)
    
    raise ValueError(f"不支持的算式格式: {expr}")


def supplement_chagang(
        session: requests.Session,
        row: dict,
        log: Callable[[str], None] = print,
    ) -> str:
    """对给定的查岗行执行"补充处理"。返回响应文本。"""
    if not row:
        return ""

    chagang_id = row['id']
    suanshi = row['infocontent']
    rspcontent = calc_suanshi(suanshi)

    token, ref_url, unique_id = fetch_verify_token_chagang(session, chagang_id)
    tt = time.time()
    rd = f'{(tt - int(tt)):.16f}'

    body = [
        ("__RequestVerificationToken", token,),
        ("UniqueId", unique_id,),
        ("GovId", "116.113.104.69:8085",),
        ("QueryType", "2",),
        ("QueryId", '150200006057',),
        ("GovId", "116.113.104.69:8085",),
        ("InfoContent", row['infocontent'],),
        ("ReceiveTime", row['receivetime'],),
        ("AnswerTime", '0',),
        ("InfoId", row['infoid'],),
        ("OrderId", row['infoid'],),
        ("rspContent", rspcontent,),
        ("X-Requested-With", 'XMLHttpRequest',),
    ]

    log(f"  提交body: {body}")

    resp = session.post(
        f"{BASE}/TopGps/Report/PlatformQuery/SupplyReply"
        f"?id={chagang_id}&rd={rd}&pop=1&popName=_dialog_window_normal",
        data=body,
        headers={
            "Referer": ref_url,
            "Origin": BASE,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.text


def process_chagang(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        org_id: str = "1",
        page_size: int = 50,
        dry_run: bool = False,
        all_pages: bool = True,
        log: Callable[[str], None] = print,
    ) -> int:
    """执行一轮完整的查询 + 补充处理，返回本轮实际处理的行数。

    通过 ``log`` 回调输出进度，便于 CLI（print）与 GUI（日志窗口）复用同一逻辑。
    调用方需保证 ``session`` 已经登录。
    """
    extra = {"OrgAndCarList.OrgId": org_id}

    total_done = 0
    page = 1
    while True:
        log(f"查询第 {page} 页 ({begin_time} ~ {end_time}) ...")
        data = search_chagang(
            session,
            begin_time=begin_time,
            end_time=end_time,
            page=page,
            rows=page_size,
            extra=extra,
        )
        rows = data.get("rows") or []
        total = int(data.get("total") or 0)
        log(f"  本页 {len(rows)} 行 / 共 {total} 行")
        if not rows:
            break

        if not dry_run:
            for row in rows:
                try:
                    resp_text = supplement_chagang(session, row, log)
                    log(f"  提交完成: {resp_text[:200]}")
                    total_done += 1
                except Exception as e:
                    print(f"出错: {e}", file=sys.stderr)
                    continue

        else:
            log("  [dry-run] 跳过提交")

        if not all_pages:
            break
        if page * page_size >= total:
            break
        page += 1
        time.sleep(0.5)

    return total_done


def process_all(
        session: requests.Session,
        begin_time: str,
        end_time: str,
        org_id: str = "1",
        page_size: int = 50,
        dry_run: bool = False,
        all_pages: bool = True,
        log: Callable[[str], None] = print,
        run_type1: bool = True,
        run_type2: bool = True,
        on_error: Callable[[Exception], None] | None = None,
    ) -> int:
    """在同一个已登录 session 上，依次运行所选的两类报警处理，返回总处理行数。

    - ``run_type1``：类型1·报警处理（/TopGps/Report/AlarmProcessQuery）
    - ``run_type2``：类型2·安全报警（/CGO8/SafeAnly/SafeAlarmProRpt）

    每一类独立 try/except：某一类失败不会阻断另一类；失败时若提供了
    ``on_error`` 回调（例如重新登录），会先调用它再继续下一类。
    """
    tasks: list[tuple[str, Callable[..., int]]] = []
    tasks.append(("查岗", process_chagang))
    if run_type1:
        tasks.append(("类型1·报警处理", process_once))
    if run_type2:
        tasks.append(("类型2·安全报警", process_once2))

    total_done = 0
    for name, fn in tasks:
        log(f"----- {name} -----")
        try:
            total_done += fn(
                session,
                begin_time=begin_time,
                end_time=end_time,
                org_id=org_id,
                page_size=page_size,
                dry_run=dry_run,
                all_pages=all_pages,
                log=log,
            )
        except Exception as exc:  # noqa: BLE001 - 单类失败不应中断其它类
            log(f"  {name} 出错：{exc}")
            if on_error is not None:
                on_error(exc)
    return total_done


def run(
    username: str,
    password: str,
    begin_time: str,
    end_time: str,
    org_id: str = "1",
    page_size: int = 50,
    dry_run: bool = False,
    all_pages: bool = True,
    run_type1: bool = True,
    run_type2: bool = True,
) -> None:
    session = make_session()
    print(f"[{datetime.now():%F %T}] 登录 {username} ...")
    login(session, username, password)
    print("登录成功。")

    total_done = process_all(
        session,
        begin_time=begin_time,
        end_time=end_time,
        org_id=org_id,
        page_size=page_size,
        dry_run=dry_run,
        all_pages=all_pages,
        run_type1=run_type1,
        run_type2=run_type2,
        log=lambda msg: print(f"[{datetime.now():%F %T}] {msg}"),
    )

    print(f"[{datetime.now():%F %T}] 完成。本次共处理 {total_done} 行。")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="报(预)警批量补充处理自动化")
    p.add_argument("--user", default="")
    p.add_argument("--password", default="")
    p.add_argument(
        "--begin",
        help="起始时间 yyyy-mm-dd HH:MM:SS，默认昨天 00:00:00",
    )
    p.add_argument(
        "--end",
        help="结束时间 yyyy-mm-dd HH:MM:SS，默认昨天 23:59:59",
    )
    p.add_argument("--org-id", default="7250", help="组织 ID，默认 1（全部）")
    p.add_argument("--page-size", type=int, default=50)
    p.add_argument(
        "--first-page-only",
        action="store_true",
        help="仅处理第一页（默认会遍历所有页）",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="只查询不提交",
    )
    return p.parse_args(argv)


def today_time_window() -> tuple[str, str]:
    """返回「今天 00:00:00 ~ 当前时刻」的时间窗，供 GUI 定时处理使用。"""
    now = datetime.now()
    begin = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    end = now.strftime("%Y-%m-%d %H:%M:%S")
    return begin, end


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    begin, end = today_time_window()
    begin = args.begin or begin
    end = args.end or end

    try:
        run(
            username=args.user,
            password=args.password,
            begin_time=begin,
            end_time=end,
            org_id=args.org_id,
            page_size=args.page_size,
            dry_run=args.dry_run,
            all_pages=not args.first_page_only,
        )
    except Exception as e:
        print(f"出错: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
