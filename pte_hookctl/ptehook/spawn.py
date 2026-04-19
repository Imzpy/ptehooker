"""
Spawn-mode hook — 在目标 app 进程刚 fork 完成、还没跑到 SDK 自检 /
JNI_OnLoad 之前就暂停它，装完 hook 再 resume。

用途：
  attach-mode 装 hook 时 app 已经跑了几百 ms 到几秒，.init_array /
  System.loadLibrary / Application.onCreate 里的大多数 init 代码早就
  执行过了。想 hook：
    - Appdome 的 init_array_func4
    - libloader.so 的 get_bytes (解密密钥)
    - 同盾 libtongdun.so 的 JNI_OnLoad 里的 FindClass / RegisterNatives
    - 任何风控 SDK 的第一次设备指纹采集
  都要 spawn-mode。

原理：
  1) host 发 `adb shell monkey <pkg>` 冷启动
  2) host 在密集轮询里调 `pidof <pkg>`（persistent shell 约 10ms/iter）
  3) 一旦看到 pid，立即通过 KPM 发 SIGSTOP（kernel-side, 延迟 <1ms）
  4) host 装 hook（此时 app 处于 T(stopped) 状态，安全装）
  5) host 发 SIGCONT，app 带着 hook 恢复执行

race 窗口：
    从 fork 返回到 app 跑完 Application.onCreate() 通常要 500ms-2s。
    用户态 pidof 轮询 + KPM SIGSTOP 的总延迟一般在 10-100ms，**绝对赶得上**
    绝大多数 SDK 的 .init_array / JNI_OnLoad。

*** 重要：急早 SIGSTOP + LogArgs 的已知限制 ***

spawn 急早模式（不设 wait_lib）SIGSTOP 在 app maps 未完整阶段，_alloc_ghost
选的 large-gap 可能正是 linker 即将要 mmap 的区域。SIGCONT 后 linker 把该
区域 mmap 覆盖 → ghost 页被 shadow → shellcode 写 log_buf 失败 +
proc_read 读不到 → **LogArgs 的 on_call callback 不会 fire**（hits 本身
仍然累加，UXN fault 触发正常）。

解决：
  - LogArgs / CallBackup 这种依赖 log_buf 的 action：**必须配 wait_lib="..."**
    让 maps 稳定后再 SIGSTOP。代价：错过目标 SO 首次 JNI_OnLoad。
  - ReturnConst / Noop 这种不读 log_buf 的 action：**无此限制**，急早模式
    完全可用，适合"改返回值"式 hook（比如 bypass 某个 flag 检查）。

使用：
    def on_spawn(sess):
        sess.native_hook("libtongdun.so", offset=0x4208c, on_call=my_cb)

    ptehook.spawn("com.shopee.tw", on_spawn)
"""
import os
import sys
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import kpm_client as K

from .session import Session


def _pidof(package: str) -> int:
    """通过 persistent adb shell 查 pidof（~5-15ms/call）。返回 0 表示不存在。"""
    try:
        out = K._run(f"pidof {package}")
        s = out.strip()
        if s:
            return int(s.split()[0])
    except Exception:
        pass
    return 0


def _force_stop(package: str) -> None:
    """确保目标 package 不在跑。"""
    try:
        K._run(f"am force-stop {package}")
    except Exception:
        pass


def _launch(package: str) -> None:
    """冷启动。用 monkey 最快。"""
    # 不等返回（monkey 自己后台启 app）
    subprocess.Popen(
        ["adb", "-s", K.ADB_SERIAL, "shell", f"monkey -p {package} 1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_for_lib(pid: int, lib_name: str, timeout: float = 15.0,
                    poll_interval: float = 0.02) -> bool:
    """polling /proc/pid/maps 直到 lib_name 出现。返回 True 即找到。

    用于 spawn() 的"等目标 SO mapped 再 SIGSTOP"场景：
      - SIGSTOP 发生时 app 的地址空间已经稳定，ghost memory 分配不会和即将
        到来的 mmap 冲突
      - 代价：错过了 SO 的 JNI_OnLoad 第一次调用（若 JNI_OnLoad 同步执行）。
        对于周期性调用或 app 交互才触发的 hook 点无影响。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            maps = K.read_maps(pid)
            if any(lib_name in m[4] for m in maps):
                return True
        except Exception:
            pass
        time.sleep(poll_interval)
    return False


def spawn(package: str, on_spawn, *,
           wait_lib: str = None, wait_lib_timeout: float = 15.0,
           launch_timeout: float = 15.0, poll_interval_ms: int = 5,
           verbose: bool = True) -> Session:
    """
    Cold-start package 并在进程首次被调度前暂停，让调用者装 hook 后再恢复。

    参数：
      package          目标包名（如 "com.shopee.tw"）
      on_spawn(sess)   回调：装 hook 用。sess 处于暂停状态。
      wait_lib         可选：**先 polling /proc/pid/maps 等目标 SO mapped，
                       再 SIGSTOP**。这保证 ghost memory 分配时 app 地址空间
                       已稳定，避免 linker 后续 mmap 覆盖 ghost 页导致
                       `proc_read` 读 log_buf 失败。
                       代价：错过该 SO 的首次 JNI_OnLoad 调用（若 JNI_OnLoad
                       同步执行完）。对周期 API 调用或运行时触发的 hook 无影响。
                       不设即"最早 SIGSTOP"，但 ghost 分配可能冲突。
      wait_lib_timeout 等 SO 超时秒数
      launch_timeout   冷启动 pidof 超时
      poll_interval_ms pidof 轮询间隔（默认 5ms，tight loop）
      verbose          打印过程

    返回：
      Session 对象（可继续 .run() 或 .close()）。
    """
    def log(msg):
        if verbose:
            print(f"[spawn] {msg}", flush=True)

    # 1) 先杀掉已有实例
    _force_stop(package)
    time.sleep(0.3)

    # 2) 冷启动（异步）
    log(f"cold-start {package}")
    t_launch = time.monotonic()
    _launch(package)

    # 3) 紧循环 pidof（直到 pid 出现）
    pid = 0
    iters = 0
    deadline = t_launch + launch_timeout
    while time.monotonic() < deadline:
        iters += 1
        pid = _pidof(package)
        if pid:
            break
        time.sleep(poll_interval_ms / 1000.0)
    if not pid:
        raise TimeoutError(f"{package} pidof timeout after {launch_timeout}s")
    t_pid = time.monotonic()
    log(f"pid={pid} after {(t_pid-t_launch)*1000:.0f}ms ({iters} iters)")

    # 4) 可选：先等 SO mapped 再 SIGSTOP（推荐路径）
    #    这样 maps 已相对稳定，ghost memory 分配不会和即将到来的 mmap 冲突。
    #    不设 wait_lib 则立即 SIGSTOP，但 ghost 分配可能撞到 linker 即将 mmap
    #    的区域（导致 hook 后 proc_read log_buf 读不到正确数据）。
    if wait_lib:
        log(f"polling until {wait_lib} mapped ...")
        t0 = time.monotonic()
        if not _wait_for_lib(pid, wait_lib, timeout=wait_lib_timeout,
                              poll_interval=0.02):
            raise TimeoutError(
                f"{wait_lib} 未在 {wait_lib_timeout}s 内映射到 pid={pid}")
        log(f"{wait_lib} mapped after {(time.monotonic()-t0)*1000:.0f}ms")

    # 5) SIGSTOP
    K.spawn_stop(pid)
    t_stop = time.monotonic()
    log(f"SIGSTOP sent at +{(t_stop-t_launch)*1000:.0f}ms from launch")

    # 6) 让用户装 hook
    sess = Session(pid, package)
    log(f"calling on_spawn(sess)...")
    t_cb_start = time.monotonic()
    try:
        on_spawn(sess)
    except Exception as e:
        # hook 装失败也要 SIGCONT，不能留个僵尸 stopped
        log(f"on_spawn raised: {e}; 尝试 SIGCONT 让进程存活")
        try:
            K.spawn_cont(pid)
        except Exception:
            pass
        raise
    t_cb_end = time.monotonic()
    log(f"on_spawn done in {(t_cb_end-t_cb_start)*1000:.0f}ms, "
        f"{len(sess.hooks)} hooks installed")

    # 7) SIGCONT 恢复执行
    K.spawn_cont(pid)
    log(f"SIGCONT sent; total gate time {(time.monotonic()-t_stop)*1000:.0f}ms")

    return sess
