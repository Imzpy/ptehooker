"""
MultiSession - 同时管理一个包的所有进程 (main + :push/:remote/... 子进程)。

背景：Android app 经常 fork 多个进程（push service、WebView 沙箱、独立
运行的推送/定位/Wallet 等）。每个子进程有独立 linker、ART、ghost 内存，
hook 必须在每个进程分别装一份才能覆盖全部流量。

KPM 端的 uxn_hook_slot 已经按 (pid, target_addr) 存，底层原生支持多进程；
这个类只是把 Python `Session` 层的单 pid 绑定扩展成 fan-out 模式。

使用：
    import ptehook
    ms = ptehook.attach_all("com.target.app")   # main + 所有子进程
    print(f"attached {len(ms)} procs: {ms.processes()}")

    # fan-out 到每个 session；返回 list[InstalledHook]（与 ms.sessions 一一对应，
    # 每个元素是 None 代表该 session 未装上）
    hooks = ms.native_hook("libc.so", symbol="open",
                            on_call=lambda a: print(f"[open] fd={a[0]:x}"))
    ms.run()          # 单线程 poll 所有 session 的 log buffer
    ms.close()

限制：
- KPM 全局只有 16 个 UXN slots（跨进程共享）。N 进程 × M hook 会很快撞顶
  —— MultiSession 会在 install 前检查剩余 slots 并报错。
- 不自动跟踪 Zygote fork 出的新进程（需要 spawn-mode，下一步工作）。

"""
import os
import sys
import signal
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import kpm_client as K

from .session import Session, attach as _attach_one


UXN_HOOK_MAX = 16   # 要和 KPM 端 ptehook_planc_v2.c 的 UXN_HOOK_MAX 一致


def _slots_used() -> int:
    try:
        return len(K.uxn_list())
    except Exception:
        return 0


class MultiSession:
    """Fan-out 包装：一个 MultiSession = 多个 Session。"""

    def __init__(self, sessions: list):
        if not sessions:
            raise ValueError("MultiSession 至少要 1 个 Session")
        self.sessions = sessions
        self._stop = False
        self._closed = False

    # ------------------------------------------------------------------
    # 信息
    def __len__(self):
        return len(self.sessions)

    def processes(self) -> list:
        """返回 [(pid, package), ...]，按 attach 顺序。"""
        return [(s.pid, s.package) for s in self.sessions]

    def pids(self) -> list:
        return [s.pid for s in self.sessions]

    # ------------------------------------------------------------------
    # hook fan-out
    def _preflight_slots(self, want: int):
        used = _slots_used()
        if used + want > UXN_HOOK_MAX:
            raise RuntimeError(
                f"KPM UXN slots 不够：当前 used={used}, 需要新增 {want}, "
                f"上限 {UXN_HOOK_MAX}。\n"
                f"  要么减少 hook 数 / session 数，要么改 KPM 端 UXN_HOOK_MAX "
                f"重编 .kpm。")

    def native_hook(self, lib_name, symbol=None, offset=None, **kw) -> list:
        """fan-out native_hook 到每个 session。

        返回 list[InstalledHook|None]，和 self.sessions 索引一一对应。
        某个 session 失败（比如子进程没加载这个 lib）时返 None，不影响其他。
        """
        self._preflight_slots(len(self.sessions))
        results = []
        for s in self.sessions:
            try:
                h = s.native_hook(lib_name, symbol=symbol, offset=offset, **kw)
                results.append(h)
            except Exception as e:
                print(f"  [multi] pid={s.pid} ({s.package}) skip: {e}")
                results.append(None)
        ok = sum(1 for h in results if h)
        print(f"[multi] native_hook fan-out: {ok}/{len(self.sessions)} 成功")
        return results

    def java_hook(self, class_desc, method, sig, **kw) -> list:
        """fan-out java_hook。注意：每个 session 都要独立扫 ArtMethod（不同进程的
        ART 实例地址不同），比 native_hook 慢。"""
        self._preflight_slots(len(self.sessions))
        results = []
        for s in self.sessions:
            try:
                h = s.java_hook(class_desc, method, sig, **kw)
                results.append(h)
            except Exception as e:
                print(f"  [multi] pid={s.pid} ({s.package}) skip: {e}")
                results.append(None)
        ok = sum(1 for h in results if h)
        print(f"[multi] java_hook fan-out: {ok}/{len(self.sessions)} 成功")
        return results

    # ------------------------------------------------------------------
    # 事件循环：单线程合并 poll，保持和 Session.run() 一致的用户体验
    def run(self, poll_hz: float = 5):
        """合并 poll 所有 session 的 log buffer。Ctrl+C 停止（仅主线程）。"""
        if threading.current_thread() is threading.main_thread():
            def handler(*_):
                self._stop = True
            signal.signal(signal.SIGINT, handler)

        total_hooks = sum(len(s.hooks) for s in self.sessions)
        print(f"[multi] event loop @ {poll_hz}Hz, "
              f"{len(self.sessions)} session, {total_hooks} total hooks "
              f"(Ctrl+C 退出)")

        interval = 1.0 / poll_hz
        import re
        try:
            while not self._stop:
                for s in self.sessions:
                    for h in s.hooks:
                        if not h.action.needs_log:
                            continue
                        buf = h.meta.get("log_buf", 0)
                        if not buf:
                            continue
                        try:
                            need = 104 if h.action.__class__.__name__ in \
                                ("CallBackup", "CallBackupJava") else 80
                            out = K.ctl_raw(
                                f"ghost-read {s.pid} 0x{buf:x} {need}")
                            m = re.search(
                                r"\[OK\].*?bytes[^:]*:\s*([0-9a-fA-F]+)", out)
                            if not m:
                                continue
                            data = bytes.fromhex(m.group(1))
                        except Exception:
                            continue
                        event = h.action.parse_event(data)
                        if not event.get("valid"):
                            continue
                        # prepend pid 到 callback 以便用户区分来源
                        pid_tag = f"pid={s.pid}"
                        if event.get("new_calls", 0) > 0 \
                                and getattr(h.action, "on_call", None):
                            for _ in range(event["new_calls"]):
                                h.action.on_call(event["regs"])
                        if event.get("new_pre", 0) > 0 \
                                and getattr(h.action, "on_call", None):
                            for _ in range(event["new_pre"]):
                                h.action.on_call(event["pre_regs"])
                        if event.get("new_post", 0) > 0 \
                                and getattr(h.action, "on_return", None):
                            for _ in range(event["new_post"]):
                                h.action.on_return(
                                    event["pre_regs"],
                                    event["post_x0"], event["post_x1"])
                time.sleep(interval)
        finally:
            active = sum(len(s.hooks) for s in self.sessions)
            print(f"\n[multi] stopping; {active} hooks still installed across "
                  f"{len(self.sessions)} session")

    # ------------------------------------------------------------------
    def close(self):
        if self._closed:
            return
        self._closed = True
        errs = []
        for s in self.sessions:
            try:
                s.close()
            except Exception as e:
                errs.append(f"pid={s.pid}: {e}")
        if errs:
            raise RuntimeError(
                "MultiSession.close() 有部分失败：\n  " + "\n  ".join(errs))


def attach_all(package: str, *, include_subprocs: bool = True,
                require_min: int = 1) -> MultiSession:
    """
    Attach 到一个包的所有进程（main + 子进程）。

    include_subprocs=False 时只 attach main，退化为单 Session 包装（仍返 MultiSession，
    便于代码统一）。
    require_min: 若找到的进程数 < 这个值直接报错。
    """
    procs = K.get_pids(package, include_subprocs=include_subprocs)
    if len(procs) < require_min:
        raise RuntimeError(
            f"只找到 {len(procs)} 个 {package} 进程（要求 ≥ {require_min}）。"
            f"是否 app 还没启？ adb shell 'monkey -p {package} 1'")

    sessions = []
    for pid, cmdline in procs:
        try:
            # Session.__init__ 只要 (pid, package)；用 cmdline 作为 package 以便
            # 用户日志里能区分 main vs :push 等子进程。
            s = Session(pid, cmdline)
            sessions.append(s)
            print(f"[multi] attached pid={pid} ({cmdline})")
        except Exception as e:
            print(f"[multi] attach pid={pid} ({cmdline}) 失败: {e}")
    if not sessions:
        raise RuntimeError(f"没有任何 {package} 进程能 attach 成功")
    return MultiSession(sessions)
