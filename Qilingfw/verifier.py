# qilingfw/verifier.py
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE
from .hooks import CrashMonitor, enable_bypass_hooks
from .utils import ensure_tmp_dir

class OverflowVerifier:
    """定向栈溢出漏洞验证器"""

    def __init__(self, rootfs: str, verbose: bool = False):
        self.rootfs = rootfs
        self.verbose = verbose
        self.httpd_path = None
        # 尝试自动查找 httpd 路径
        for candidate in ['/sbin/httpd', '/bin/httpd', '/usr/sbin/httpd']:
            full = os.path.join(rootfs, candidate.lstrip('/'))
            if os.path.isfile(full):
                self.httpd_path = full
                break
        ensure_tmp_dir(rootfs)

    def verify(self, func_name: str, func_addr: int,
               websGetVar_calls: list, external_calls: list,
               payload: bytes = None) -> bool:
        """执行验证，返回是否成功触发溢出"""
        if self.httpd_path is None:
            print("[!] httpd binary not found in rootfs")
            return False

        if payload is None:
            payload = b'B' * 500

        ql = Qiling([self.httpd_path], self.rootfs, verbose=QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF)
        enable_bypass_hooks(ql)

        # 模拟 websGetVar 返回超长 payload
        payload_ptr = ql.mem.map_anywhere(len(payload) + 1)
        ql.mem.write(payload_ptr, payload + b'\x00')
        for call_addr, next_addr in websGetVar_calls:
            def make_sim(next_a, p_ptr):
                def hook(ql):
                    ql.arch.regs.r0 = p_ptr
                    ql.arch.regs.pc = next_a
                return hook
            ql.hook_address(make_sim(next_addr, payload_ptr), call_addr)

        # 挂钩外部函数（跳过黑名单）
        libc_blacklist = {
            'memset', 'strlen', 'strcpy', 'strncpy', 'sprintf', 'snprintf',
            'memcpy', 'memmove', 'malloc', 'free', 'realloc', 'calloc',
            'sscanf', '__isoc99_sscanf', 'printf', 'puts',
        }
        hooked_targets = set()
        for ec in external_calls:
            target = ec['target_addr']
            name = ec.get('target_name', '')
            if name in libc_blacklist:
                continue
            if name == 'websGetVar' or 'websGetVar' in name:
                continue
            if target not in hooked_targets:
                ql.hook_address(self._return_success, target)
                hooked_targets.add(target)

        # 设置参数并跳转到漏洞函数
        wp = ql.mem.map_anywhere(0x200)
        ql.mem.write(wp, b'\x00' * 0x200)
        path_ptr = ql.mem.map_anywhere(256)
        ql.mem.write(path_ptr, b'\x00')
        query_ptr = ql.mem.map_anywhere(256)
        ql.mem.write(query_ptr, b'\x00')

        def jump(ql):
            ql.arch.regs.pc = func_addr
            ql.arch.regs.r0 = wp
            ql.arch.regs.r1 = path_ptr
            ql.arch.regs.r2 = query_ptr
        ql.hook_address(jump, ql.loader.elf_entry)

        result = {'crash': None}
        CrashMonitor(ql, result)
        try:
            ql.run()
        except Exception:
            pass

        if result.get('crash'):
            # 检查寄存器是否被 payload 污染
            r2 = ql.arch.regs.r2
            r3 = ql.arch.regs.r3
            if r2 == 0x42424242 or r3 == 0x42424242:
                print(f"[+] {func_name}: Overflow confirmed (payload in registers)")
                return True
            else:
                print(f"[!] {func_name}: Crash but no payload evidence")
        return False

    @staticmethod
    def _return_success(ql):
        ql.arch.regs.r0 = 0
        ql.arch.regs.pc = ql.arch.regs.lr