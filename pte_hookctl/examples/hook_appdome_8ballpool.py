#!/usr/bin/env python3
"""
使用 ptehook 复现看雪 thread-290866 里对 8 Ball Pool (Appdome 加固) 的 hook 点。

目标 APP: com.miniclip.eightballpool (v56.19.0)
文章链接: https://bbs.kanxue.com/thread-290866.htm

覆盖的 hook 点（完全按原文偏移）：

Phase 1 — SO 加载监控 (libc.so)：
    android_dlopen_ext       监控所有 SO 加载
    dlopen                   检测 libloader.so 加载时机
    remove                   阻止解密后 SO 被删除

Phase 2 — Appdome 主库 libloader.so：
    +0x243880  get_bytes()                 用于取加密密钥
    +0x124BA8  init_array_func4            初始化检测线程
    +0x10B810  mb_get_target_func()        拿到各检测线程主体地址
    +0x253938  pthread_func()              检测线程主体
    +0x268CB8  Frida 检测入口              内存 SHA256 比对
    +0x26952C  maps 解析                   /proc/pid/maps 扫可执行映射
    +0x26D158  文件完整性校验               比对内存段 vs 磁盘 SHA256
    +0x2E0B78  threatCode 上报             威胁事件码序列化
    +0x2E3AC8  threatEventsScore           威胁评分构造
    +0x48E3A0  sha1_transform1             底层 SHA1 检测点 1
    +0x48FE10  sha1_transform2             底层 SHA1 检测点 2
    +0x0A8AD4  decrypt_str()               字符串解密入口

Phase 3 — Java 层（混淆类名，来自错误堆栈）：
    qMivB4.tmY0B4.aU4no0.ujd3D0.setApplication
    qMivB4.tmY0B4.aU4no0.tETeU3.zd6ub6
    qMivB4.tmY0B4.aU4no0.o8PB13.uzzmc7

使用：
    # 先装 APK 并启动到主界面
    adb shell "pm install -r 8ballpool.apk"
    adb shell "monkey -p com.miniclip.eightballpool 1"

    # 等 app 起来（初始化会加载 libloader.so）后跑本脚本
    cd pte_hookctl
    ADB_SERIAL=<serial> python3 examples/hook_appdome_8ballpool.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ptehook
import kpm_client as K

TARGET_PKG = "com.miniclip.eightballpool"


# ---- Phase 1: SO 加载监控 ----------------------------------------------

def install_so_load_monitor(sess):
    """
    hook libc.so 里三个动态加载相关函数。libc 早就加载了，可以立刻装。
    """
    print("=== Phase 1: libc SO-load monitor ===")

    def on_dlopen_ext(regs):
        # int android_dlopen_ext(const char *filename, int flags,
        #                        const android_dlextinfo *extinfo)
        # X0 = filename ptr, X1 = flags, X2 = extinfo
        # filename 是 user-space 指针，要读出字符串 (我们拿不到内容，只拿指针)
        print(f"  [dlopen_ext] filename_ptr=0x{regs[0]:x} flags=0x{regs[1]:x}")

    def on_dlopen(regs):
        # void* dlopen(const char *filename, int mode)
        print(f"  [dlopen] filename_ptr=0x{regs[0]:x} mode=0x{regs[1]:x}")

    def on_remove(regs):
        # int remove(const char *path)
        # 要阻止删除的话：用 replace=0（返回成功但不真删）
        print(f"  [remove] path_ptr=0x{regs[0]:x}")

    # Android bionic: dlopen/android_dlopen_ext 导出在 libdl.so（stub，真实代码在 linker64），
    # libc.so 只是 U 引用；remove 在 libc.so 里。
    sess.native_hook("libdl.so", symbol="android_dlopen_ext", on_call=on_dlopen_ext)
    sess.native_hook("libdl.so", symbol="dlopen",             on_call=on_dlopen)
    sess.native_hook("libc.so",  symbol="remove",             replace=0)
    print("  ✓ 3 hooks installed (libdl + libc)")


# ---- Phase 2: libloader.so 函数 -----------------------------------------

# 原文反汇编得到的偏移（相对 libloader.so r-xp 基址）
LIBLOADER_OFFSETS = {
    0x243880: "get_bytes",
    0x124BA8: "init_array_func4",
    0x10B810: "mb_get_target_func",
    0x253938: "pthread_func",
    0x268CB8: "frida_detector_entry",
    0x26952C: "maps_parser",
    0x26D158: "file_integrity_check",
    0x2E0B78: "threatCode_reporter",
    0x2E3AC8: "threatEventsScore",
    0x48E3A0: "sha1_transform1",
    0x48FE10: "sha1_transform2",
    0x0A8AD4: "decrypt_str",
}

# 处理策略：
#   "log"      — 只打印 X0-X7，执行原函数（CallBackup）
#   "return0"  — 直接返回 0 绕过（ReturnConst）
#   "noop"     — 直接返回 0，等价空实现
STRATEGIES = {
    "get_bytes":              "log",        # 要观察它取哪段字节做密钥
    "init_array_func4":       "log",
    "mb_get_target_func":     "log",
    "pthread_func":           "log",
    "frida_detector_entry":   "return0",    # 绕 Frida 检测
    "maps_parser":            "log",
    "file_integrity_check":   "return0",    # 绕完整性校验
    "threatCode_reporter":    "log",        # 观察上报什么
    "threatEventsScore":      "return0",    # 绕评分
    "sha1_transform1":        "log",
    "sha1_transform2":        "log",
    "decrypt_str":            "log",        # 观察解密哪些字符串
}


def wait_for_libloader(pid, timeout=30):
    """轮询 /proc/pid/maps 直到 libloader.so 出现。"""
    print("  等 libloader.so 加载...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            maps = K.read_maps(pid)
            segs = [m for m in maps if "libloader.so" in m[4]]
            if segs:
                rx = next((m for m in segs if "r-xp" in m[2]), segs[0])
                linker_base = rx[0] - rx[3]
                print(f"  ✓ libloader.so @ linker_base=0x{linker_base:x}")
                return linker_base
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("libloader.so 未在超时前加载（app 可能没走到那步）")


def install_libloader_hooks(sess):
    print("\n=== Phase 2: libloader.so function hooks ===")
    linker_base = wait_for_libloader(sess.pid)

    for offset, name in sorted(LIBLOADER_OFFSETS.items()):
        strategy = STRATEGIES.get(name, "log")
        target_va = linker_base + offset

        # 构造回调带函数名的 closure
        def make_on_call(fn_name):
            def _cb(regs):
                # 常见 ARM64 AAPCS：X0..X7 是前 8 个整型参数
                args = " ".join(f"0x{r:x}" for r in regs[:4])
                print(f"  [libloader!{fn_name}] args={args}")
            return _cb

        try:
            if strategy == "return0":
                sess.native_hook("libloader.so", offset=offset, replace=0)
                print(f"  [{name:25s}] @ +0x{offset:07x} → ReturnConst(0)")
            elif strategy == "noop":
                sess.native_hook("libloader.so", offset=offset,
                                  action=ptehook.Noop())
                print(f"  [{name:25s}] @ +0x{offset:07x} → Noop")
            else:   # log
                sess.native_hook("libloader.so", offset=offset,
                                  on_call=make_on_call(name))
                print(f"  [{name:25s}] @ +0x{offset:07x} → LogArgs")
        except Exception as e:
            print(f"  [!] {name} 装失败: {e}")


# ---- Phase 3: Java 层 hooks ---------------------------------------------

JAVA_HOOKS = [
    # (class_desc, method, sig) — 本 APK 实际签名（从 classes12.dex 扫到的）。
    # 文章里给的签名是错误堆栈里的 setApplication / ()V，
    # 但实际这几个 Appdome 入口在 v56.19.0 里是 Context-taking。
    ("LqMivB4/tmY0B4/aU4no0/ujd3D0;", "e8ZUF1", "()V"),          # 疑似 setApplication 等价混淆名
    ("LqMivB4/tmY0B4/aU4no0/tETeU3;", "zd6ub6", "(Landroid/content/Context;)V"),
    ("LqMivB4/tmY0B4/aU4no0/o8PB13;", "uzzmc7", "(Landroid/content/ContentProvider;)V"),
]


def install_java_hooks(sess):
    print("\n=== Phase 3: Java obfuscated class hooks ===")
    for cls, method, sig in JAVA_HOOKS:
        def make_cb(class_name, method_name):
            def _cb(regs):
                # 实例方法: X0=ArtMethod*, X1=this, X2=arg0, X3=arg1 ...
                print(f"  [Java!{class_name.split('/')[-1][:-1]}.{method_name}] "
                      f"X1(this)=0x{regs[1]:x} X2=0x{regs[2]:x}")
            return _cb

        try:
            sess.java_hook(
                cls, method, sig,
                on_call=make_cb(cls, method),
                wait_jit=True,           # 让 ART 先 JIT，entry_point 走私有代码
                warmup_timeout=20.0,
                jit_watch=True,          # 自动应对 tier 升级
            )
            print(f"  [{cls}.{method}] hooked")
        except Exception as e:
            # 常见失败：方法没加载、ep 在 Nterp 等不可 JIT 方法
            print(f"  [!] 装 {cls}.{method} 失败: {e}")


# ---- 主流程 --------------------------------------------------------------

def main():
    try:
        sess = ptehook.attach(TARGET_PKG)
    except RuntimeError as e:
        print(f"[FATAL] attach 失败: {e}")
        print(f"        先启动 APP：")
        print(f"        adb shell 'monkey -p {TARGET_PKG} 1'")
        return 1

    # Phase 1 — 立即装 libc hook
    install_so_load_monitor(sess)

    # Phase 2 — 等 libloader.so 加载（app 走到 Appdome 初始化时）
    install_libloader_hooks(sess)

    # Phase 3 — Java 层 hooks
    install_java_hooks(sess)

    # KPM 状态打印
    print("\n=== 当前 KPM UXN slots ===")
    for r in K.uxn_list():
        print(f"  slot={r['slot']} target=0x{r['target']:x} "
              f"hits={r['hits']} pass3={r.get('pass3', 0)}")

    print(f"\n总计装了 {len(sess.hooks)} 个 hook。Ctrl+C 退出。")

    try:
        sess.run(poll_hz=10)
    except KeyboardInterrupt:
        print("\n清理中 ...")
    finally:
        sess.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
