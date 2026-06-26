#!/usr/bin/env python3
"""新平台（Vue + REST API）HTTP 客户端。

适配 `Cgo8 Pro 车辆主动安全智能防控平台`（http://***:8188）。
对应旧 main.py 的底层逻辑，但接口全部改为新网关 /api/**：

  - 登录：getPublicKey → RSA 加密密码 → POST /ims/user/login（JWT Bearer）
  - 查询：异步报表引擎 asyncRecord/listAsync → 轮询 result 取 dataList
  - 处理：POST /ims/alarm/alarmHandle（批量）

详见 docs/新平台改造设计.md。
"""
from __future__ import annotations

import base64
import hashlib
import threading
import time
from datetime import datetime
from typing import Any, Callable

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

BASE = "http://116.113.104.66:8188"
API = f"{BASE}/api"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

# 报表标识（实测，见设计文档 §4）
LIST_ID_TYPE1 = 664      # 报表分析 › 报警查询 › 报警处理查询
LIST_ID_TYPE2 = 738      # 主动安全 › 证据中心 › 报警处理查询（日期报表；132 是实时弹窗的配置）
LIST_ID_CHAGANG = 1143   # 报表分析 › 监管记录 › 查岗记录查询

# 各报表"时间窗"查询字段编码（实测）。
TIME_FIELD_TYPE1 = "fq_76491_222_alarm_begin_time"
TIME_FIELD_TYPE2 = "fq_80839_222_alarm_begin_time"
TIME_FIELD_CHAGANG = "fq_11103_338_rece_time"

# 异步报表轮询参数
POLL_INTERVAL = 0.4
POLL_MAX_RETRIES = 300

# 查岗应答（WebSocket sendCmd，实测，见设计文档 §5.6）
WS_PORT = 9087                       # sysConfig.wsPort
CHAGANG_CMD_CODE = 134812417         # 平台查岗应答 指令码
CHAGANG_SOURCE_DATA_TYPE = 37633
RSP_SOURCE_BROWSER = 2

# 报警处理方式 processMode（来源：dict typeId=19「报警处理方式」，实测）。
# alarmHandle.processMode 取这里的 code。其中 9=补充处理 即旧工具的销账行为。
PROCESS_MODES = {
    1: "发送信息", 2: "停止报警", 3: "电话处理", 4: "确认报警", 5: "确认误报",
    8: "严重人工干涉", 9: "补充处理", 10: "忽略", 11: "其他", 12: "语音通知",
    13: "短信通知", 14: "拍照", 15: "监听", 16: "语音对讲",
    17: "确认报警并上传传递单", 18: "亲情语音播报",
}
PROCESS_MODE_SUPPLEMENT = 9   # 补充处理（旧工具默认行为，仅生成处理记录销账）
PROCESS_MODE_STOP_ALARM = 2   # 停止报警

# asyncRecord/result 状态码
ST_TODO, ST_DOING, ST_DONE, ST_CANCEL = 0, 1, 2, 3
ST_FAILED, ST_EXPIRED, ST_NOT_FOUND = 8, 7, 9
ST_TERMINAL = {ST_DONE, ST_CANCEL, ST_EXPIRED, ST_FAILED, ST_NOT_FOUND}


class ApiError(RuntimeError):
    """业务接口返回非 0 rspCode。"""


class CgoApiClient:
    """新平台 API 客户端。线程内复用一个实例即可（持有 session + token）。"""

    def __init__(self, base: str = BASE, log: Callable[[str], None] = print) -> None:
        self.base = base.rstrip("/")
        self.api = f"{self.base}/api"
        self.log = log
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.user_id: str | None = None
        self.username: str | None = None   # 用于查岗应答 responder（企业/用户名）

        # 持久 WebSocket（查岗应答下发）。登录后调用 connect_ws() 预先建链，
        # 之后 reply_chagang 直接复用同一条连接，无需现连现登。
        self._ws = None
        self._ws_thread: threading.Thread | None = None
        self._ws_lock = threading.Lock()           # 串行化建链 / 发送批次
        self._ws_logged_in = threading.Event()     # loginRsp 成功后置位
        self._ws_client_id: str | None = None
        self._ws_token: str | None = None          # 当前连接所用 accessToken
        self._ws_order: dict[str, int] = {}        # orderId 计数（按 action）
        self._ws_batch: dict | None = None         # 当前在途发送批次的回执统计

    # ------------------------------------------------------------------ 基础
    def _url(self, path: str) -> str:
        return f"{self.api}{path}"

    def _post(self, path: str, payload: dict | None = None, *, auth: bool = True) -> Any:
        """POST JSON，自动带 Bearer + ?lang=zh-CN，并校验 rspCode。返回 data。"""
        headers = {}
        if auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        resp = self.session.post(
            self._url(path),
            params={"lang": "zh-CN"},
            json=payload if payload is not None else {},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("rspCode") != 0:
            raise ApiError(f"{path} 失败: rspCode={body.get('rspCode')} msg={body.get('msg')}")
        return body.get("data")

    def _get(self, path: str, *, auth: bool = True) -> Any:
        headers = {}
        if auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        resp = self.session.get(
            self._url(path), params={"lang": "zh-CN"}, headers=headers, timeout=60
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("rspCode") != 0:
            raise ApiError(f"{path} 失败: rspCode={body.get('rspCode')} msg={body.get('msg')}")
        return body.get("data")

    # ------------------------------------------------------------------ 登录
    @staticmethod
    def _rsa_encrypt(plain: str, public_key_b64: str) -> str:
        """用 base64(DER, SubjectPublicKeyInfo) 公钥做 RSA/PKCS#1 v1.5 加密，返回 base64。"""
        der = base64.b64decode(public_key_b64)
        rsa_key = RSA.import_key(der)
        cipher = PKCS1_v1_5.new(rsa_key)
        return base64.b64encode(cipher.encrypt(plain.encode("utf-8"))).decode("ascii")

    def get_public_key(self) -> str:
        data = self._get("/ims/user/getPublicKey", auth=False)
        pk = data.get("publicKey") if isinstance(data, dict) else None
        if not pk:
            raise ApiError("getPublicKey 未返回 publicKey")
        return pk

    def login(self, user_code: str, password: str, user_type: int = 1) -> None:
        """登录并保存 token。

        前端用 JSEncrypt 直接 RSA(明文密码)；但部分部署可能仍要求 RSA(MD5)。
        这里优先 RSA(明文)，失败再回退 RSA(MD5hex)。
        """
        public_key = self.get_public_key()

        candidates = [
            ("raw", password),
            ("md5", hashlib.md5(password.encode("utf-8")).hexdigest()),
        ]
        last_err: Exception | None = None
        for kind, plain in candidates:
            try:
                enc = self._rsa_encrypt(plain, public_key)
                data = self._post(
                    "/ims/user/login",
                    {
                        "userCode": user_code,
                        "password": enc,
                        "userType": user_type,
                        "loginMode": 1,
                    },
                    auth=False,
                )
                self.access_token = data["accessToken"]
                self.refresh_token = data.get("refreshToken")
                self.user_id = str(data.get("userId") or "")
                self.username = data.get("username") or self.username
                self.log(f"登录成功（密码加密方式: {kind}），userId={self.user_id}")
                return
            except (ApiError, KeyError, requests.HTTPError) as exc:
                last_err = exc
                self.log(f"登录尝试（{kind}）失败：{exc}")
        raise ApiError(f"登录失败（已尝试 raw/md5）：{last_err}")

    # ------------------------------------------------------------------ 查询（异步报表引擎）
    def query_report(
        self,
        list_id: int,
        query_conditions: list[dict],
        *,
        page_size: int = 200,
        max_pages: int = 100,
    ) -> list[dict]:
        """提交异步报表查询并轮询取全部 dataList（自动翻页）。"""
        all_rows: list[dict] = []
        current = 1
        while current <= max_pages:
            body = {
                "listId": list_id,
                "configLevel": 2,
                "configUserId": self.user_id,
                "current": current,
                "size": page_size,
                "last": 1,
                "parentReq": None,
                "queryConditions": query_conditions,
            }
            task = self._post("/fcdata/asyncRecord/listAsync", body)
            task_id = task.get("taskId") if isinstance(task, dict) else None
            if not task_id:
                raise ApiError("listAsync 未返回 taskId")
            result = self._poll_result(task_id)
            rows = (result or {}).get("dataList") or []
            total = (result or {}).get("total")
            all_rows.extend(rows)
            self.log(f"  第 {current} 页 {len(rows)} 行（累计 {len(all_rows)}，total={total}）")
            if not rows or len(rows) < page_size:
                break
            if total is not None and len(all_rows) >= int(total):
                break
            current += 1
        return all_rows

    def _poll_result(self, task_id: str) -> dict | None:
        """轮询 asyncRecord/result 直到 DONE/失败。返回 result（{dataList,total}）。"""
        for _ in range(POLL_MAX_RETRIES):
            data = self._post("/fcdata/asyncRecord/result", {"taskId": task_id})
            status = (data or {}).get("status")
            if status in ST_TERMINAL:
                if status == ST_DONE:
                    return (data or {}).get("result") or {}
                raise ApiError(f"报表任务结束但非成功 status={status}")
            time.sleep(POLL_INTERVAL)
        raise ApiError("报表查询轮询超时")

    @staticmethod
    def dynamic_time_condition(field_code: str, begin: str, end: str) -> dict:
        return {
            "fieldType": "date",
            "fieldCode": field_code,
            "symbol": "dynamic",
            "value": [begin, end],
        }

    # ------------------------------------------------------------------ 处理
    @staticmethod
    def _cell(row: dict, key: str) -> Any:
        """取字段值：字典字段（{_text,_value}）取 _value，否则原值。"""
        v = row.get(key)
        if isinstance(v, dict) and "_value" in v:
            return v["_value"]
        return v

    @staticmethod
    def _cell_suffix(row: dict, suffix: str) -> Any:
        """按列名后缀取值（动态报表列名带 fs_<id>_<group>_ 前缀，如 _user_id）。"""
        for k, v in row.items():
            if k.endswith(suffix):
                return v["_value"] if isinstance(v, dict) and "_value" in v else v
        return None

    @classmethod
    def row_to_alarm_base(cls, row: dict) -> dict:
        """报表行 → alarmHandle.alarmBaseDataList 项。"""
        return {
            "alarmId": cls._cell(row, "alarm_id"),
            "alarmType": cls._cell(row, "alarm_type"),
            "alarmFlag": cls._cell(row, "alarm_flag"),
            "vehicleId": cls._cell(row, "vehicle_id"),
            "alarmBeginTime": cls._cell(row, "begin_time")
            or cls._cell(row, "fs_80426_222_alarm_begin_time"),
            "alarmLevel": cls._cell(row, "alarm_level"),
        }

    @staticmethod
    def is_unprocessed(row: dict) -> bool:
        v = row.get("is_process")
        if isinstance(v, dict):
            return v.get("_value") in (0, "0", False)
        return v in (0, "0", False, None)

    def build_alarm_handle_payload(
        self,
        rows: list[dict],
        *,
        process_mode: int = PROCESS_MODE_STOP_ALARM,
        process_content: str = "报警解除",
        remark: str = "",
    ) -> dict:
        """构造 alarmHandle 请求体（不发送），便于预演/dry-run。"""
        return {
            "alarmBaseDataList": [self.row_to_alarm_base(r) for r in rows],
            "processTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "userId": 100,
            "processType": 2,
            "processMode": process_mode,
            "processContent": process_content,
            "remark": remark,
        }

    def alarm_handle(
        self,
        rows: list[dict],
        *,
        process_mode: int = PROCESS_MODE_STOP_ALARM,   # 2=停止报警
        process_content: str = "报警解除",
        remark: str = "",
        dry_run: bool = True,
    ) -> Any:
        """对报表行批量执行报警处理（processType=2）。

        ``process_mode`` 取 dict typeId=19「报警处理方式」的 code（见 PROCESS_MODES）：
        默认 2=停止报警；9=补充处理（仅生成处理记录销账，等价旧工具）。

        ⚠️ ``process_content`` **不是自由文本**，必须是该 ``process_mode`` 的合法子选项，
        否则服务端返回 ``rspCode:0`` 却静默不生效（报警仍未处理）。实测：
          - process_mode=2（停止报警）→ process_content 必须为 "报警解除"
          - process_mode=9（补充处理）→ process_content 为 "补充处理"
        且成功响应 ``data`` 也是 null，无法据此判断成功，需重查 ``is_process`` 确认。

        ⚠️ ``dry_run=True``（默认）只构造并打印请求体、**不发送**（不会真实销账）。
        真实提交需显式传 ``dry_run=False``。
        """
        if not rows:
            self.log("无待处理报警。")
            return None
        payload = self.build_alarm_handle_payload(
            rows, process_mode=process_mode, process_content=process_content, remark=remark
        )
        mode_name = PROCESS_MODES.get(process_mode, "?")
        if dry_run:
            self.log(
                f"  [dry-run] alarmHandle 待提交 {len(rows)} 条："
                f"processMode={process_mode}({mode_name}) processContent={process_content!r}"
            )
            self.log(f"  [dry-run] 请求体: {payload}")
            self.log("[dry-run] 未发送（如需真实销账请传 dry_run=False）。")
            return None
        self.log(f"  提交 alarmHandle：{len(rows)} 条，processMode={process_mode}({mode_name})")
        return self._post("/ims/alarm/alarmHandle", payload)


    # ------------------------------------------------------------------ 查岗（监管记录）
    def query_chagang(self, begin: str, end: str, *, page_size: int = 200) -> list[dict]:
        """查询查岗记录（listId 1143，时间字段 rece_time）。

        附加限制条件：``query_type == 1``（仅查指定查岗类型）、``responded == 0``（仅未应答）。
        """
        cond = [
            self.dynamic_time_condition(TIME_FIELD_CHAGANG, begin, end),
            # {"fieldType": "select", "fieldCode": "query_type", "symbol": "equal", "value": 1},
            # {"fieldType": "switch", "fieldCode": "responded", "symbol": "equal", "value": 0},
        ]
        return self.query_report(LIST_ID_CHAGANG, cond, page_size=page_size)

    @staticmethod
    def chagang_unanswered(row: dict) -> bool:
        v = row.get("responded")
        if isinstance(v, dict):
            return not v.get("_value")
        return not v

    @staticmethod
    def calc_suanshi(expr: str) -> str:
        """计算简单加减算式字符串，返回结果字符串。 '1+1=' -> '2'，'10-7=' -> '3'。"""
        e = (expr or "").strip().rstrip("=").strip()
        for op in ("+", "-"):
            if op in e:
                left, right = e.split(op, 1)
                a, b = int(left.strip()), int(right.strip())
                return str(a + b if op == "+" else a - b)
        raise ValueError(f"不支持的算式格式: {expr!r}")

    @staticmethod
    def _ms(dt_str: str) -> int:
        """'YYYY-MM-DD HH:MM:SS' → 毫秒时间戳。"""
        return int(datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").timestamp() * 1000)

    def build_chagang_reply(self, row: dict, answer: str, *, responder: str = "") -> dict:
        """根据查岗记录行 + 应答内容，构造 WS sendCmd 帧（见设计文档 §5.6）。"""
        ext809 = self._cell(row, "ext809_id")
        platform_ids = [str(ext809)] if ext809 not in (None, "") else []
        req_time = self._cell(row, "rece_time") or self._cell(row, "fs_67764_222_req_time") or ""
        cmd_params = {
            "objectType": self._cell(row, "query_type"),
            # 登录接口不返回企业名；优先入参/登录名，回退记录行的应答人列（…_user_id）。
            "responder": responder or self.username or self._cell_suffix(row, "_user_id") or "",
            "responderTel": "",
            "objectId": self._cell(row, "query_id"),
            "infoId": self._cell(row, "info_id"),
            "infoContent": answer,
            "type": None,
            "answer": "",
            "userId": self.user_id,
            "rspSource": RSP_SOURCE_BROWSER,
            "rspIp": "",
            "sourceDataType": CHAGANG_SOURCE_DATA_TYPE,
            "sourceMsgSn": self._cell(row, "info_id"),   # 实测：= infoId
            "reqUniqueId": self._cell(row, "unique_id"),
            "reqTime": self._ms(req_time) if req_time else 0,
        }
        return {
            "action": "sendCmd",
            "version": "1",
            "body": {
                "cmdCode": CHAGANG_CMD_CODE,
                "clientCmdId": _rand_id(),
                "platformIds": platform_ids,
                "cmdParams": cmd_params,
                "cmdDesc": "平台查岗应答",
            },
        }

    def reply_chagang(
        self,
        rows: list[dict],
        *,
        responder: str = "",
        dry_run: bool = True,
        timeout: float = 15.0,
    ) -> int:
        """对待应答查岗记录自动应答（算术题求值）。通过 WebSocket sendCmd 下发。

        ⚠️ ``dry_run=True``（默认）只构造并打印帧、**不连接、不发送**。
        真实下发（``dry_run=False``）会向监管平台回送应答，请先用测试记录联调。
        返回成功下发的条数。
        """
        targets = [r for r in rows if self.chagang_unanswered(r)]
        if not targets:
            self.log("无待应答查岗记录。")
            return 0

        frames: list[dict] = []
        for r in targets:
            raw = self._cell(r, "info_content") or ""
            try:
                ans = self.calc_suanshi(raw)
            except ValueError:
                self.log(f"  跳过：无法识别查岗内容 {raw!r}（unique_id={self._cell(r,'unique_id')}）")
                continue
            frames.append(self.build_chagang_reply(r, ans, responder=responder))

        if dry_run:
            for f in frames:
                self.log(f"  [dry-run] 待发送应答帧: {f}")
            self.log(f"[dry-run] 共 {len(frames)} 条待应答（未发送）。")
            return 0

        return self._ws_send_cmds(frames, timeout=timeout)

    def _ws_order_id(self, action: str) -> int:
        """按 action 递增的 orderId（同一连接内对 login / sendCmd 各自单调递增）。"""
        self._ws_order[action] = self._ws_order.get(action, 0) + 1
        return self._ws_order[action]

    def connect_ws(self, *, timeout: float = 15.0) -> None:
        """建立**持久** WebSocket 连接并完成 login，供查岗应答复用。

        幂等：同一 token 且后台线程仍存活时直接复用（线程可能正在自动重连，
        此时仅在锁外等待登录态恢复）。建议登录成功后立即调用，这样查岗应答时
        无需现连现登，显著降低首条应答的下发延迟。

        断线由 websocket-client 的 ``run_forever(reconnect=...)`` 在后台自动重连，
        每次重连都会重新走 on_open→login→loginRsp，连接因此保持热态。

        协议（实测，见设计文档 §5.6）：连接后客户端先发 login（空 body），
        服务端回 loginRsp(rspCode==0) 并在 data.clientId 下发分配的 clientId。
        ``access_token`` 作为 WebSocket 子协议用于鉴权。
        """
        if not self.access_token:
            raise ApiError("未登录，无法建立 WebSocket")

        with self._ws_lock:
            alive = (self._ws is not None and self._ws_token == self.access_token
                     and self._ws_thread is not None and self._ws_thread.is_alive())
            if not alive:
                # 首次 / token 变化 / 线程已死 → 重建连接（内部会先清理旧连接）。
                self._build_ws_locked()

        # 锁外等待登录完成（含后台重连恢复），避免阻塞回调线程。
        if not self._ws_logged_in.wait(timeout):
            raise ApiError("WebSocket 登录/重连超时")

    def _build_ws_locked(self) -> None:
        """（重新）建立 WebSocket 连接并启动后台线程。调用方须持有 self._ws_lock。"""
        import json

        import websocket  # websocket-client

        self._close_ws_locked()
        self._ws_logged_in.clear()
        self._ws_client_id = None
        self._ws_order = {}
        self._ws_token = self.access_token

        host = self.base.split("//", 1)[-1].split(":")[0].split("/")[0]
        ws_url = f"ws://{host}:{WS_PORT}/ws"

        def now_ms() -> int:
            return int(time.time() * 1000)

        def on_open(ws):
            # 实测：服务端不主动推送 clientId，须由客户端先发 login（空 body）。
            # 每次（重）连都会触发，故自动重连后会重新登录。
            self._ws_logged_in.clear()
            self._ws_order = {}
            login = {"action": "login", "time": now_ms(), "version": 1,
                     "orderId": self._ws_order_id("login"), "body": {}}
            ws.send(json.dumps(login))
            self.log(f"WS 已连接 {ws_url}，已发送 login，等待 loginRsp ...")

        def on_message(ws, message):
            try:
                msg = json.loads(message)
            except Exception:
                return
            action = msg.get("action")
            # 登录应答：loginRsp(rspCode==0)，data.clientId = userId#hash。
            if action == "loginRsp" and msg.get("rspCode") == 0:
                self._ws_client_id = (msg.get("data") or {}).get("clientId")
                self._ws_logged_in.set()
                self.log(f"WS 登录成功 clientId={self._ws_client_id}")
                return
            # 指令回执（实测三段：sendCmdRsp 待提交 → cmdComRsp 已提交 → cmdDevRsp 下发成功）
            if action in ("sendCmdRsp", "cmdComRsp", "cmdDevRsp"):
                data = msg.get("data") or {}
                inner = data.get("rspCode")
                self.log(
                    f"  应答回执[{action}]: rspCode={inner} msg={data.get('msg')} "
                    f"cmdId={data.get('cmdId')}"
                )
                batch = self._ws_batch
                if batch is None:
                    return
                # cmdDevRsp 为终态（rspCode 201=下发成功,无需应答）；
                # sendCmdRsp 阶段若 rspCode!=0 表示直接失败，也计为终态避免阻塞。
                terminal = action == "cmdDevRsp" or (
                    action == "sendCmdRsp" and inner not in (0, None))
                if terminal:
                    batch["ack"] += 1
                    if batch["ack"] >= batch["sent"]:
                        batch["done"].set()

        def on_error(ws, err):
            self.log(f"WS 错误: {err}")

        def on_close(ws, code, reason):
            # 连接断开后清除登录态；reconnect>0 时 run_forever 会自动重连。
            self._ws_logged_in.clear()
            self.log(f"WS 连接关闭 code={code} reason={reason}（将自动重连）")

        ws = websocket.WebSocketApp(
            ws_url,
            subprotocols=[self.access_token],  # accessToken 作为子协议鉴权
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        self._ws = ws
        # reconnect=5：断线后每 5s 自动重连；ping 用于及时探测半开连接。
        self._ws_thread = threading.Thread(
            target=ws.run_forever,
            kwargs={"ping_interval": 20, "ping_timeout": 10, "reconnect": 5},
            daemon=True,
        )
        self._ws_thread.start()

    def _close_ws_locked(self) -> None:
        """关闭当前连接（调用方须持有 self._ws_lock）。"""
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
        self._ws = None
        self._ws_thread = None
        self._ws_logged_in.clear()

    def close_ws(self) -> None:
        """主动关闭持久 WebSocket 连接（程序退出 / 停止时调用）。"""
        with self._ws_lock:
            self._close_ws_locked()

    def _ws_send_cmds(self, frames: list[dict], *, timeout: float = 15.0) -> int:
        """在持久连接上依次 sendCmd，并等待回执。返回发送条数。

        若尚未建链（或连接已断 / token 变更），会先 ``connect_ws()`` 自动建链，
        因此既可由 ``connect_ws()`` 预热，也可在首次发送时惰性建链。
        """
        import json

        if not frames:
            return 0

        self.connect_ws(timeout=timeout)  # 幂等：已连接则立即返回

        with self._ws_lock:
            ws = self._ws
            if ws is None or not self._ws_logged_in.is_set():
                raise ApiError("WebSocket 未就绪，无法下发查岗应答")
            batch: dict = {"sent": 0, "ack": 0, "done": threading.Event()}
            self._ws_batch = batch
            self.log(f"WS 下发 {len(frames)} 条查岗应答 ...")
            for fr in frames:
                fr = dict(fr)
                fr["time"] = int(time.time() * 1000)
                fr["orderId"] = self._ws_order_id("sendCmd")
                ws.send(json.dumps(fr))
                batch["sent"] += 1

        batch["done"].wait(timeout)
        sent = batch["sent"]
        self._ws_batch = None
        return sent


_cmd_seq = 0


def _rand_id(n: int = 10) -> str:
    """生成唯一的 clientCmdId（时间戳 + 自增序列，base36）。"""
    global _cmd_seq
    _cmd_seq += 1
    val = int(time.time() * 1000) * 1000 + (_cmd_seq % 1000)
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    s = ""
    while val:
        s = chars[val % 36] + s
        val //= 36
    return (s or "0")[-n:]


# ---------------------------------------------------------------------- 自测
def _selftest() -> None:
    """命令行自测：登录 + 类型1 查询（只读，不处理）。

    用法： python api_client.py <用户名> <密码>
    """
    import sys

    if len(sys.argv) < 3:
        print("用法: python api_client.py <用户名> <密码>")
        raise SystemExit(2)
    user, pwd = sys.argv[1], sys.argv[2]

    client = CgoApiClient()
    client.login(user, pwd)

    now = datetime.now()
    begin = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
    end = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f"查询类型1 报警处理（{begin} ~ {end}）...")
    rows = client.query_report(
        LIST_ID_TYPE1,
        [client.dynamic_time_condition(TIME_FIELD_TYPE1, begin, end)],
    )
    unprocessed = [r for r in rows if client.is_unprocessed(r)]
    print(f"共 {len(rows)} 行，其中未处理 {len(unprocessed)} 行（仅查询，未提交处理）")
    if rows:
        print("样例 alarmBaseDataList 项:", client.row_to_alarm_base(rows[0]))
    if unprocessed:
        print("--- alarmHandle dry-run（补充处理，不发送）---")
        client.alarm_handle(unprocessed, dry_run=True)

    # 查岗（本月）— dry-run，只构造应答帧不发送
    print("查询查岗记录（本月）...")
    cg = client.query_chagang(
        now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S"),
        end,
    )
    cg_un = [r for r in cg if client.chagang_unanswered(r)]
    print(f"查岗 {len(cg)} 行，待应答 {len(cg_un)} 行（dry-run，不发送）")
    client.reply_chagang(cg_un[:3], dry_run=True)


if __name__ == "__main__":
    _selftest()
