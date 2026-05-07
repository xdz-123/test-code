from qiling import Qiling

class SyscallTracer:
    def __init__(self, ql: Qiling, result_dict: dict, max_calls: int = 1000):
        self.ql = ql
        self.result = result_dict
        self.max_calls = max_calls
        self.call_count = 0
        self._register_hook()

    def _register_hook(self):
        self.ql.hook_syscall(self._on_syscall)

    def _on_syscall(self, ql: Qiling, intno: int, *args):
        if self.call_count >= self.max_calls:
            return
        syscall_name = ql.os.syscall_map.get(intno, f"unknown_{intno}")
        entry = {
            'name': syscall_name,
            'number': intno,
            'args': [hex(a) if isinstance(a, int) else str(a) for a in args[:6]]
        }
        self.result['syscalls'].append(entry)
        self.call_count += 1
