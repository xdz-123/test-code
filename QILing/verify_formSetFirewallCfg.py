#!/usr/bin/env python3
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from hooks.crash_monitor import CrashMonitor

ROOTFS = "/root/qiling/rootfs_tenda/rootfs_ubifs"
HTTPD = ROOTFS + "/bin/httpd"
FUNC_ADDR = 0x50048
PAYLOAD = b"B" * 500

# 已提取的外部函数入口地址
GET_VALUE_ADDR   = 0x15A88   # GetValue (PLT)
SET_VALUE_ADDR   = 0x15AF4   # SetValue (PLT)
DOSYSTEMCMD_ADDR = 0x15A1C   # doSystemCmd (PLT)
COMMITCFM_ADDR   = 0x15830   # CommitCfm (PLT)
WEBSWRITE_ADDR   = 0x24C44   # websWrite (实际函数)
WEBSDONE_ADDR    = 0x253D4   # websDone (实际函数)

def setup_bypass(ql):
    # close 循环
    def close_hook(ql, fd, retval):
        if retval == -9 and fd > 1024:
            return 0
        return retval
    ql.os.set_syscall('close', close_hook, QL_INTERCEPT.EXIT)

    # 资源限制
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
    ql.os.set_syscall('socketcall', ignore_syscall, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('connect', ignore_syscall, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('socket', ignore_syscall, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('clone', ignore_syscall, QL_INTERCEPT.ENTER)

def main():
    ql = Qiling([HTTPD], ROOTFS, verbose=QL_VERBOSE.OFF)
    setup_bypass(ql)

    wp = ql.mem.map_anywhere(0x200)
    ql.mem.write(wp, b'\x00' * 0x200)

    # ------ 1. 在汇编级模拟 websGetVar ------
    def simulate_websGetVar(ql):
        payload_ptr = ql.mem.map_anywhere(len(PAYLOAD) + 1)
        ql.mem.write(payload_ptr, PAYLOAD + b'\x00')
        ql.arch.regs.r0 = payload_ptr
        ql.arch.regs.pc = 0x500A8   # BL websGetVar 的下一条指令
    ql.hook_address(simulate_websGetVar, 0x500A4)

    # ------ 2. 挂钩所有外部函数，使其直接返回成功 ------
    def make_return_success(ql):
        # 设置 R0 = 0 (成功), 然后跳转回 LR 指向的返回地址
        ql.arch.regs.r0 = 0
        ql.arch.regs.pc = ql.arch.regs.lr

    ql.hook_address(make_return_success, GET_VALUE_ADDR)
    ql.hook_address(make_return_success, SET_VALUE_ADDR)
    ql.hook_address(make_return_success, DOSYSTEMCMD_ADDR)
    ql.hook_address(make_return_success, COMMITCFM_ADDR)
    ql.hook_address(make_return_success, WEBSWRITE_ADDR)
    ql.hook_address(make_return_success, WEBSDONE_ADDR)

    # ------ 3. 跳转到 formSetFirewallCfg ------
    path_ptr = ql.mem.map_anywhere(256)
    ql.mem.write(path_ptr, b"\x00")
    query_ptr = ql.mem.map_anywhere(256)
    ql.mem.write(query_ptr, b"\x00")

    def jump(ql):
        ql.arch.regs.pc = FUNC_ADDR
        ql.arch.regs.r0 = wp
        ql.arch.regs.r1 = path_ptr
        ql.arch.regs.r2 = query_ptr
    ql.hook_address(jump, ql.loader.elf_entry)

    result = {'crash': None}
    CrashMonitor(ql, result)
    try:
        ql.run()
    except:
        pass

    if result.get('crash'):
        crash_pc = result['crash']['pc']
        crash_type = result['crash']['type']
        print(f"[!] CRASH at 0x{int(crash_pc,16):x} ({crash_type})")
        if FUNC_ADDR <= int(crash_pc,16) < FUNC_ADDR + 0x1000:
            print("[+] REAL BUFFER OVERFLOW DETECTED!")
        else:
            print("[-] Crash outside function (env issue)")
    else:
        print("[✗] No crash detected.")

if __name__ == "__main__":
    main()
