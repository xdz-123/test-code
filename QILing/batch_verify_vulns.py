#!/usr/bin/env python3
import json
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from hooks.crash_monitor import CrashMonitor

ROOTFS = "/root/qiling/rootfs_tenda/rootfs_ubifs"
HTTPD = ROOTFS + "/bin/httpd"
PAYLOAD = b"B" * 500

# libc 函数黑名单（与 IDA 脚本一致）
LIBC_BLACKLIST = {
    "memset", "strlen", "strcpy", "strncpy", "sprintf", "snprintf",
    "memcpy", "memmove", "malloc", "free", "realloc", "calloc",
    "sscanf", "__isoc99_sscanf", "printf", "puts", "atoi", "strcmp",
    "strncmp", "strchr", "strrchr", "strstr", "memcmp",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "ioctl", "fcntl", "select", "poll",
}

def setup_bypass(ql):
    # 基础绕过
    def close_hook(ql, fd, retval):
        if retval == -9 and fd > 1024:
            return 0
        return retval
    ql.os.set_syscall('close', close_hook, QL_INTERCEPT.EXIT)

    def sysconf_hook(ql, name):
        if name == 4:
            return (1024, ())
        return None
    ql.os.set_syscall('sysconf', sysconf_hook, QL_INTERCEPT.ENTER)

    def getrlimit_hook(ql, resource, rlim_ptr):
        if resource == 7:
            ql.mem.write(rlim_ptr, (1024).to_bytes(4, 'little'))
            ql.mem.write(rlim_ptr+4, (4096).to_bytes(4, 'little'))
            return (0, ())
        return None
    ql.os.set_syscall('getrlimit', getrlimit_hook, QL_INTERCEPT.ENTER)

    # 网络/进程通配钩子
    def ignore_syscall(ql, *args):
        return (0, ())
    for name in ('socketcall', 'connect', 'socket', 'clone', 'fork', 'vfork'):
        ql.os.set_syscall(name, ignore_syscall, QL_INTERCEPT.ENTER)

def test_one(vuln_info):
    fname = vuln_info['func_name']
    func_addr = vuln_info['func_addr']
    websGetVar_calls = vuln_info['websGetVar_calls']
    external_calls = vuln_info['external_calls']

    print(f"[*] Testing {fname} ({func_addr:#x}) ...", end=" ")

    ql = Qiling([HTTPD], ROOTFS, verbose=QL_VERBOSE.OFF)
    setup_bypass(ql)

    # --- 1. 模拟 websGetVar 调用 ---
    payload_ptr = ql.mem.map_anywhere(len(PAYLOAD) + 1)
    ql.mem.write(payload_ptr, PAYLOAD + b'\x00')

    for call_addr, next_addr in websGetVar_calls:
        def make_websGetVar_sim(next_addr, payload_ptr):
            def hook(ql):
                ql.arch.regs.r0 = payload_ptr
                ql.arch.regs.pc = next_addr
            return hook
        ql.hook_address(make_websGetVar_sim(next_addr, payload_ptr), call_addr)

    # --- 2. 挂钩外部函数（非 libc 黑名单） ---
    hooked_targets = set()
    for ec in external_calls:
        target_addr = ec['target_addr']
        target_name = ec['target_name']
        # 跳过 libc 函数
        if target_name in LIBC_BLACKLIST:
            continue
        # 跳过 websGetVar 自身（已处理）
        if target_name == 'websGetVar' or 'websGetVar' in target_name:
            continue
        if target_addr not in hooked_targets:
            def make_return_success():
                def hook(ql):
                    ql.arch.regs.r0 = 0
                    ql.arch.regs.pc = ql.arch.regs.lr
                return hook
            ql.hook_address(make_return_success(), target_addr)
            hooked_targets.add(target_addr)

    # --- 3. 设置参数并跳转 ---
    wp = ql.mem.map_anywhere(0x200)
    ql.mem.write(wp, b'\x00' * 0x200)

    path_ptr = ql.mem.map_anywhere(256)
    ql.mem.write(path_ptr, b"\x00")
    query_ptr = ql.mem.map_anywhere(256)
    ql.mem.write(query_ptr, b"\x00")

    def jump(ql):
        ql.arch.regs.pc = func_addr
        ql.arch.regs.r0 = wp
        ql.arch.regs.r1 = path_ptr
        ql.arch.regs.r2 = query_ptr
    ql.hook_address(jump, ql.loader.elf_entry)

    # --- 4. 运行并检测 ---
    result = {'crash': None}
    CrashMonitor(ql, result)
    try:
        ql.run()
    except:
        pass

    crashed = False
    if result.get('crash'):
        crash_pc = result['crash']['pc']
        crash_type = result['crash']['type']
        print(f"[!] CRASH at {crash_pc} ({crash_type})")
        # 简单启发：若寄存器 R2 或 R3 包含 0x42424242，则视为溢出成功
        # (也可检查崩溃地址是否在预期范围内)
        r2 = ql.arch.regs.r2
        r3 = ql.arch.regs.r3
        if r2 == 0x42424242 or r3 == 0x42424242:
            print("  -> Payload detected in registers, overflow confirmed!")
            crashed = True
        else:
            print("  -> Crash occurred, but no payload evidence.")
            crashed = True
    else:
        print("[✗] No crash")

    return fname, crashed

def main():
    with open("vuln_targets.json") as f:
        all_vulns = json.load(f)

    results = []
    for v in all_vulns:
        name, passed = test_one(v)
        results.append((name, passed))
        print(f"  -> {name}: {'VULNERABLE' if passed else 'NOT DETECTED'}")

    print("\n===== SUMMARY =====")
    for name, passed in results:
        print(f"{name}: {'VULNERABLE' if passed else 'NOT DETECTED'}")

if __name__ == "__main__":
    main()
