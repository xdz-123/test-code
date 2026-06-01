# qilingfw/hooks/crash.py
from qiling import Qiling

class CrashMonitor:
    """监控内存违规并记录崩溃信息"""

    def __init__(self, ql: Qiling, result_dict: dict):
        self.ql = ql
        self.result = result_dict
        self._register()

    def _register(self):
        self.ql.hook_mem_invalid(self._on_mem_invalid)

    def _on_mem_invalid(self, ql: Qiling, access: int, addr: int, size: int, value: int):
        self.result['crash'] = {
            'type': 'memory_invalid',
            'access': access,
            'addr': hex(addr),
            'pc': hex(ql.arch.regs.pc),
            'size': size
        }
        ql.emu_stop()
        return False