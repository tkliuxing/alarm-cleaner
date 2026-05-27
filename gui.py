#!/usr/bin/env python3
"""报警自动处理 GUI。

在 Windows 上双击运行（或 ``python gui.py``）：
  1. 输入用户名 / 密码，点击「开始」后登录平台；
  2. 登录成功后每隔设定的分钟数（默认 10 分钟）自动处理一次
     「今天 00:00 ~ 当前时刻」的全部报警；
  3. 处理过程实时显示在窗口中，同时写入 ``logs/`` 目录下的日志文件。

核心 HTTP 逻辑全部复用 ``main.py``，本文件只负责界面与定时调度。
"""
from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk

import main as core

LOGGER_NAME = "alarm-cleaner"
DEFAULT_INTERVAL_MIN = 10


def app_dir() -> str:
    """返回程序所在目录：打包成 exe 时取可执行文件目录，否则取脚本目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class QueueHandler(logging.Handler):
    """把日志记录推进队列，供 Tk 主线程安全地取出并显示。"""

    def __init__(self, log_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        self.log_queue.put(self.format(record))


def setup_logger(log_queue: "queue.Queue[str]") -> tuple[logging.Logger, str]:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    log_dir = os.path.join(app_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"alarm-cleaner-{datetime.now():%Y%m%d}.log")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    queue_handler = QueueHandler(log_queue)
    queue_handler.setFormatter(fmt)
    logger.addHandler(queue_handler)

    return logger, log_file


class AlarmCleanerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.logger, self.log_file = setup_logger(self.log_queue)

        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.next_run_ts: float | None = None

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._poll_queue)
        self.root.after(1000, self._update_status)

        self.logger.info(f"日志文件：{self.log_file}")

    # ---------- UI ----------
    def _build_ui(self) -> None:
        self.root.title("报警自动处理")
        self.root.geometry("760x560")
        self.root.minsize(640, 460)

        self.user_var = tk.StringVar(value="")
        self.pwd_var = tk.StringVar(value="")
        self.interval_var = tk.StringVar(value=str(DEFAULT_INTERVAL_MIN))
        self.org_var = tk.StringVar(value="1")
        self.pagesize_var = tk.StringVar(value="50")
        self.dryrun_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="已停止")

        pad = {"padx": 6, "pady": 4}

        form = ttk.Frame(self.root)
        form.pack(fill="x", padx=12, pady=(12, 4))
        for col in (1, 3):
            form.columnconfigure(col, weight=1)

        ttk.Label(form, text="用户名").grid(row=0, column=0, sticky="w", **pad)
        self.user_entry = ttk.Entry(form, textvariable=self.user_var)
        self.user_entry.grid(row=0, column=1, sticky="ew", **pad)

        ttk.Label(form, text="密码").grid(row=0, column=2, sticky="w", **pad)
        self.pwd_entry = ttk.Entry(form, textvariable=self.pwd_var, show="*")
        self.pwd_entry.grid(row=0, column=3, sticky="ew", **pad)

        ttk.Label(form, text="间隔(分钟)").grid(row=1, column=0, sticky="w", **pad)
        self.interval_entry = ttk.Entry(form, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(form, text="组织ID").grid(row=1, column=2, sticky="w", **pad)
        self.org_entry = ttk.Entry(form, textvariable=self.org_var, width=10)
        self.org_entry.grid(row=1, column=3, sticky="w", **pad)

        ttk.Label(form, text="每页行数").grid(row=2, column=0, sticky="w", **pad)
        self.pagesize_entry = ttk.Entry(form, textvariable=self.pagesize_var, width=10)
        self.pagesize_entry.grid(row=2, column=1, sticky="w", **pad)

        self.dryrun_check = ttk.Checkbutton(
            form, text="干跑（只查询不提交）", variable=self.dryrun_var
        )
        self.dryrun_check.grid(row=2, column=2, columnspan=2, sticky="w", **pad)

        # 按钮 + 状态
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=12, pady=4)
        self.start_btn = ttk.Button(bar, text="开始", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="停止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        ttk.Label(bar, textvariable=self.status_var, foreground="#0a64c8").pack(
            side="right"
        )

        # 日志窗口
        log_frame = ttk.LabelFrame(self.root, text="运行日志")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap="word", state="disabled", font="TkFixedFont"
        )
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

    # ---------- 控制 ----------
    def start(self) -> None:
        username = self.user_var.get().strip()
        password = self.pwd_var.get()
        if not username or not password:
            messagebox.showwarning("提示", "请输入用户名和密码。")
            return
        try:
            interval = float(self.interval_var.get())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("提示", "间隔必须是大于 0 的数字（分钟）。")
            return
        org_id = self.org_var.get().strip() or "1"
        try:
            page_size = int(self.pagesize_var.get())
            if page_size <= 0:
                raise ValueError
        except ValueError:
            page_size = 50
            self.pagesize_var.set("50")
        dry_run = bool(self.dryrun_var.get())

        self.stop_event.clear()
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._worker,
            args=(username, password, org_id, page_size, interval, dry_run),
            daemon=True,
        )
        self.worker.start()

    def stop(self) -> None:
        if self.worker and self.worker.is_alive():
            self.logger.info("收到停止指令，正在结束当前等待 ...")
            self.stop_event.set()
            self.stop_btn.config(state="disabled")

    def on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askokcancel("退出", "任务正在运行，确定要退出吗？"):
                return
            self.stop_event.set()
        self.root.destroy()

    # ---------- 后台 worker ----------
    def _worker(
        self,
        username: str,
        password: str,
        org_id: str,
        page_size: int,
        interval: float,
        dry_run: bool,
    ) -> None:
        log = self.logger.info
        try:
            session = core.make_session()
            log(f"正在登录：{username} ...")
            core.login(session, username, password)
            log("登录成功。")
        except Exception as exc:  # noqa: BLE001 - 登录失败需展示给用户
            self.logger.error(f"登录失败：{exc}")
            self.root.after(0, self._on_worker_stopped)
            return

        cycle = 0
        while not self.stop_event.is_set():
            cycle += 1
            begin, end = core.today_time_window()
            log(f"===== 第 {cycle} 轮开始（{begin} ~ {end}）=====")
            try:
                done = core.process_once(
                    session,
                    begin_time=begin,
                    end_time=end,
                    org_id=org_id,
                    page_size=page_size,
                    dry_run=dry_run,
                    all_pages=True,
                    log=log,
                )
                log(f"第 {cycle} 轮完成，本轮处理 {done} 行。")
            except Exception as exc:  # noqa: BLE001 - 单轮失败不应中断循环
                self.logger.error(f"第 {cycle} 轮出错：{exc}")
                log("尝试重新登录 ...")
                try:
                    session = core.make_session()
                    core.login(session, username, password)
                    log("重新登录成功。")
                except Exception as exc2:  # noqa: BLE001
                    self.logger.error(f"重新登录失败：{exc2}")

            if self.stop_event.is_set():
                break

            self.next_run_ts = time.time() + interval * 60
            log(f"等待 {interval:g} 分钟后进行下一轮 ...")
            # stop_event.wait 在收到停止信号时立即返回，保证「停止」按钮响应及时。
            self.stop_event.wait(interval * 60)
            self.next_run_ts = None

        log("已停止运行。")
        self.root.after(0, self._on_worker_stopped)

    # ---------- 主线程回调 ----------
    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for widget in (
            self.user_entry,
            self.pwd_entry,
            self.interval_entry,
            self.org_entry,
            self.pagesize_entry,
            self.dryrun_check,
        ):
            widget.config(state=state)
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")

    def _on_worker_stopped(self) -> None:
        self.next_run_ts = None
        self._set_running(False)
        self.status_var.set("已停止")

    def _poll_queue(self) -> None:
        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _append_log(self, line: str) -> None:
        self.log_text.config(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _update_status(self) -> None:
        if self.worker and self.worker.is_alive():
            if self.next_run_ts:
                remain = int(self.next_run_ts - time.time())
                if remain > 0:
                    self.status_var.set(f"运行中 — 下一轮约 {remain // 60} 分 {remain % 60} 秒后")
                else:
                    self.status_var.set("运行中 — 处理中 ...")
            else:
                self.status_var.set("运行中 — 处理中 ...")
        self.root.after(1000, self._update_status)


def main() -> None:
    root = tk.Tk()
    AlarmCleanerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
