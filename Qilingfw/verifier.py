# qilingfw/verifier.py
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from .hooks import CrashMonitor, enable_bypass_hooks
from .utils import ensure_tmp_dir

HEAP_ERROR_SIGNATURES = [
    b'free(): invalid next size',
    b'free(): invalid pointer',
    b'malloc(): memory corruption',
    b'corrupted double-linked list',
    b'double free or corruption',
    b'Aborted',
]

MIPS_REGS = [
    'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
    't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra',
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
    'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17',
    'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25',
    'r26', 'r27', 'r28', 'r29', 'r30', 'r31', 'lr',
]
ARM_FLOAT_REGS = [f'd{i}' for i in range(16)]

class OverflowVerifier:
    def __init__(self, rootfs: str, verbose: bool = False):
        self.rootfs = rootfs
        self.verbose = verbose
        self.httpd_path = None
        for candidate in ['/sbin/httpd', '/bin/httpd', '/usr/sbin/httpd']:
            full = os.path.join(rootfs, candidate.lstrip('/'))
            if os.path.isfile(full):
                self.httpd_path = full
                break
        ensure_tmp_dir(rootfs)

    def verify(self, func_name: str, func_addr: int,
               websGetVar_calls: list, external_calls: list,
               payload: bytes = None,
               payload_callback: callable = None,
               check_callback: callable = None,
               detect_heap: bool = True) -> bool:
        if self.httpd_path is None:
            print("[!] httpd binary not found in rootfs")
            return False

        ql = Qiling([self.httpd_path], self.rootfs,
                    verbose=QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF)
        enable_bypass_hooks(ql)

        captured_errors = []

        def write_hook(ql: Qiling, fd: int, buf: int, count: int):
            if fd == 2:
                try:
                    data = ql.mem.read(buf, count)
                    captured_errors.append(data)
                except:
                    pass
                return (count, ())
            return None
        ql.os.set_syscall('write', write_hook, QL_INTERCEPT.ENTER)

        def fprintf_hook(ql: Qiling, *args):
            if len(args) >= 1:
                fmt_ptr = args[1] if len(args) > 1 else 0
                if fmt_ptr:
                    try:
                        fmt = ql.mem.string(fmt_ptr)
                        captured_errors.append(f"fprintf: {fmt}".encode())
                    except:
                        pass
            return None
        try:
            ql.os.set_api('fprintf', fprintf_hook, QL_INTERCEPT.ENTER)
            ql.os.set_api('dprintf', fprintf_hook, QL_INTERCEPT.ENTER)
        except:
            pass

        # ---- 输入注入 ----
        if websGetVar_calls:
            if payload_callback:
                def make_dynamic_hook(next_addr):
                    def hook(ql):
                        data = payload_callback(ql, [])
                        ptr = ql.mem.map_anywhere(len(data) + 1)
                        ql.mem.write(ptr, data + b'\x00')
                        ql.arch.regs.r0 = ptr
                        ql.arch.regs.pc = next_addr
                    return hook
                for call_addr, next_addr in websGetVar_calls:
                    ql.hook_address(make_dynamic_hook(next_addr), call_addr)
            else:
                if payload is None:
                    payload = b'B' * 500
                payload_ptr = ql.mem.map_anywhere(len(payload) + 1)
                ql.mem.write(payload_ptr, payload + b'\x00')
                for call_addr, next_addr in websGetVar_calls:
                    def make_sim(next_a, p_ptr):
                        def hook(ql):
                            ql.arch.regs.r0 = p_ptr
                            ql.arch.regs.pc = next_a
                        return hook
                    ql.hook_address(make_sim(next_addr, payload_ptr), call_addr)
        else:
            if payload_callback:
                self._payload_callback = payload_callback
            else:
                if payload is None:
                    payload = b'B' * 500
                payload_ptr = ql.mem.map_anywhere(len(payload) + 1)
                ql.mem.write(payload_ptr, payload + b'\x00')
                self._query_ptr_override = payload_ptr

        # ---- 挂钩外部函数 ----
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

        # ---- 设置参数并跳转 ----
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
            if hasattr(self, '_query_ptr_override') and self._query_ptr_override:
                ql.arch.regs.r2 = self._query_ptr_override
            elif hasattr(self, '_payload_callback') and self._payload_callback:
                data = self._payload_callback(ql, [])
                ptr = ql.mem.map_anywhere(len(data) + 1)
                ql.mem.write(ptr, data + b'\x00')
                ql.arch.regs.r2 = ptr
            else:
                ql.arch.regs.r2 = query_ptr
        ql.hook_address(jump, ql.loader.elf_entry)

        result = {'crash': None}
        CrashMonitor(ql, result)
        try:
            ql.run()
        except Exception:
            pass

        if not result.get('crash'):
            return False

        if check_callback:
            return check_callback(ql, result)

        # --- 检测 1：寄存器污染 ---
        for reg in MIPS_REGS:
            try:
                val = ql.arch.regs.read(reg)
                if (val & 0xFFFFFFFF) == 0x42424242 or (val & 0xFFFFFF00) == 0x42424200:
                    return True
            except:
                pass

        for reg in ARM_FLOAT_REGS:
            try:
                dval = ql.arch.regs.read(reg)
                if dval == 0x4242424242424242:
                    return True
            except:
                pass

        # --- 检测 2：unreachable PC ---
        if detect_heap:
            pc = ql.arch.regs.pc
            try:
                ql.mem.read(pc, 1)
            except:
                if pc != 0x432af4:
                    return True

        # --- 检测 3：控制流劫持（PC 不在任何可执行段内） ---
        if detect_heap and self._is_control_flow_hijack(ql):
            return True

        # --- 检测 4：堆错误 ---
        if detect_heap:
            for blob in captured_errors:
                for sig in HEAP_ERROR_SIGNATURES:
                    if sig in blob:
                        return True
            if self._is_libc_crash(ql):
                return True

        return False

    def _is_libc_crash(self, ql: Qiling) -> bool:
        try:
            pc = ql.arch.regs.pc
            for img in ql.loader.images:
                path = img.path.lower()
                if 'libc' in path and ('so' in path or 'so.6' in path):
                    base = img.base
                    for m in ql.mem.maps:
                        if m[0] == base:
                            size = m[1]
                            if base <= pc < base + size:
                                return True
                            break
            if 0x12000000 <= pc <= 0x14000000:
                return True
        except Exception:
            pass
        return False

    def _is_control_flow_hijack(self, ql: Qiling) -> bool:
        """检查 PC 是否不在任何可执行内存段内"""
        try:
            pc = ql.arch.regs.pc
            for m in ql.mem.maps:
                if len(m) >= 3:
                    start, end, perms = m[0], m[1], m[2]
                    if 'x' in perms:
                        if start <= pc < end:
                            return False
            return True
        except Exception:
            return False

    @staticmethod
    def _return_success(ql):
        ql.arch.regs.r0 = 0
        ql.arch.regs.pc = ql.arch.regs.lr
