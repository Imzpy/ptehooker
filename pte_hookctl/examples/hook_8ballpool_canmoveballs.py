#!/usr/bin/env python3
"""
复现看雪 thread-290866 `0x6 游戏功能分析`：

目标库：libgame-BPM-GooglePlay-Gold-Release-Module-3919.so
        （v56.19.0 里 versionCode=3919，对应的游戏逻辑主库）

Hook 点：canMoveBalls() @ libgame+0x2DC11E8
        AAPCS: bool → W0，ReturnConst(1) 让判定恒为 "可以动"

效果：任意球都能自由拖动到桌面任意位置（包括对手的球、8 号球）。

文章里的 Frida 等价物：
    Interceptor.attach(base.add(0x2DC11E8), {
        onLeave: function (retval) { retval.replace(1); }
    });

用 ptehook 的写法：
    sess.native_hook("libgame-...so", offset=0x2DC11E8, replace=1)

使用：
    adb shell "monkey -p com.miniclip.eightballpool 1"
    # 等进入对局界面
    ADB_SERIAL=<serial> python3 examples/hook_8ballpool_canmoveballs.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ptehook
import kpm_client as K

TARGET_PKG = "com.miniclip.eightballpool"
# Appdome 运行时把 APK 里的加密 payload 解密为临时文件再 mmap。
# 真正的游戏 SO 在 /proc/maps 里以这个文件名出现（带 (deleted) 标记，因为文件已删）：
#   lib/arm64/libgame-BPM-GooglePlay-Gold-Release-Module-3919.so ← APK 里的加密体
#   /data/data/.../8peQFPY8peRAVCWABhddi9W5QtKCqKuZAsUc0k9xOkoP69jApP ← 解密后的真 ELF
LIBGAME_DECRYPTED = "8peQFPY8peRAVCWABhddi9W5QtKCqKuZAsUc0k9xOkoP69jApP"
OFFSET_CAN_MOVE_BALLS = 0x2DC11E8


def wait_for_libgame(pid, timeout=120):
    """
    轮询 /proc/pid/maps 直到 Appdome 解密的游戏 SO 出现。
    返回 (linker_base, path) —— path 含 '(deleted)'，直接传给 native_hook 匹配。

    解密后 mapping 的 file-offset 是 0 → linker_base 就是第一个 r-xp 段的 VA。
    """
    print(f"  等 Appdome 解密 {LIBGAME_DECRYPTED[:20]}... (最多 {timeout}s)")
    print(f"  注：此库通常在 app 进入主界面/对局 时才被 libloader.so 解密加载")
    start = time.time()
    while time.time() - start < timeout:
        try:
            maps = K.read_maps(pid)
            segs = [m for m in maps if LIBGAME_DECRYPTED in m[4]]
            if segs:
                # file-offset==0 的那一段就是 linker_base
                base_seg = next((m for m in segs if m[3] == 0), segs[0])
                linker_base = base_seg[0] - base_seg[3]
                path = base_seg[4]
                rx_segs = [m for m in segs if "r-xp" in m[2]]
                print(f"  ✓ 找到解密后的 libgame ELF")
                print(f"    path = {path}")
                print(f"    linker_base = 0x{linker_base:x}")
                print(f"    r-xp 段数: {len(rx_segs)}, 最大段 size {max(m[1]-m[0] for m in rx_segs):#x}")
                return linker_base, path
        except Exception as e:
            print(f"    read_maps err: {e}")
        time.sleep(1.0)
    raise RuntimeError(f"解密后的 libgame 在 {timeout}s 内未出现。请手动在 app 里点 Play 进入对局。")


def main():
    print(f"=== 8 Ball Pool canMoveBalls() bypass ===")
    print(f"目标: {TARGET_PKG}")
    print(f"库:  (Appdome 解密体) {LIBGAME_DECRYPTED[:24]}...")
    print(f"偏移: +0x{OFFSET_CAN_MOVE_BALLS:x}")
    print()

    try:
        sess = ptehook.attach(TARGET_PKG)
    except RuntimeError as e:
        print(f"[FATAL] attach 失败: {e}")
        print(f"  先启动 app: adb shell 'monkey -p {TARGET_PKG} 1'")
        return 1

    try:
        linker_base, lib_path = wait_for_libgame(sess.pid, timeout=120)
    except RuntimeError as e:
        print(f"[FATAL] {e}")
        sess.close()
        return 1

    target_va = linker_base + OFFSET_CAN_MOVE_BALLS
    print(f"\n→ hook target VA = 0x{target_va:x}")

    # native_hook 内部按 lib_name 子串匹配 /proc/maps，LIBGAME_DECRYPTED 够唯一。
    try:
        sess.native_hook(LIBGAME_DECRYPTED,
                          offset=OFFSET_CAN_MOVE_BALLS,
                          replace=1)
    except Exception as e:
        print(f"[FATAL] install hook 失败: {e}")
        sess.close()
        return 1

    print(f"\n✓ canMoveBalls() @ +0x{OFFSET_CAN_MOVE_BALLS:x} → ReturnConst(1)")
    print(f"  现在回到游戏，对局中应该可以自由拖动任意球")
    print(f"  （包括对手的球、8 号球、落袋位置）\n")

    print("=== KPM slot 状态 ===")
    for r in K.uxn_list():
        print(f"  slot={r['slot']} target=0x{r['target']:x} hits={r['hits']} pass3={r.get('pass3', 0)}")

    print(f"\nCtrl+C 退出（退出时 hook 会自动 unhook）。")

    try:
        # 每 2 秒打印一次 hit 变化
        last_hits = {}
        while True:
            time.sleep(2.0)
            rs = K.uxn_list()
            for r in rs:
                slot = r['slot']
                h = r['hits']
                if h != last_hits.get(slot, 0):
                    delta = h - last_hits.get(slot, 0)
                    print(f"  [hit+{delta}] slot={slot} total_hits={h} pass3={r.get('pass3',0)}")
                    last_hits[slot] = h
    except KeyboardInterrupt:
        print("\n清理 hook ...")
    finally:
        sess.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
