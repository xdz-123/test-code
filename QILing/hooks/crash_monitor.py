from qiling import Qiling

class CrashMonitor:
    def __init__(self, ql: Qiling, result_dict: dict):
        self.ql = ql
        self.result = result_dict
        self._register_hooks()

    def _register_hooks(self):
        self.ql.hook_code(self._on_code)
        self.ql.hook_mem_invalid(self._on_mem_invalid)

    def _on_code(self, ql: Qiling, addr: int, size: int):
        pass

    def _on_mem_invalid(self, ql: Qiling, access_type: int, addr: int, size: int, value: int):
        crash_info = {
            'type': 'memory_invalid',
            'access': access_type,
            'address': hex(addr),
            'pc': hex(ql.arch.regs.pc),
            'size': size
        }
        self.result['crash'] = crash_info
        self.result['status'] = 'crash'
        ql.emu_stop()
        return False
