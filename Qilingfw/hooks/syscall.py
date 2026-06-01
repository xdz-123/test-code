# qilingfw/hooks/syscall.py
from qiling import Qiling
from qiling.const import QL_INTERCEPT

class SyscallTracer:
    """记录系统调用名称和参数（前6个）"""

    def __init__(self, ql: Qiling, result_dict: dict, max_calls: int = 1000):
        self.ql = ql
        self.result = result_dict
        self.max_calls = max_calls
        self.call_count = 0
        self._register()

    def _register(self):
        common_syscalls = [
            'open', 'read', 'write', 'close', 'lseek', 'stat', 'fstat',
            'mmap', 'munmap', 'mprotect', 'brk',
            'execve', 'exit', 'exit_group', 'fork', 'clone',
            'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
            'ioctl', 'fcntl', 'select', 'poll',
            'sysconf', 'getrlimit', 'prlimit64',
        ]
        for name in common_syscalls:
            try:
                self.ql.os.set_syscall(name, self._make_callback(name), QL_INTERCEPT.ENTER)
            except Exception:
                pass

    def _make_callback(self, syscall_name: str):
        def callback(ql: Qiling, *args):
            if self.call_count >= self.max_calls:
                return None
            entry = {
                'name': syscall_name,
                'args': [hex(a) if isinstance(a, int) else str(a) for a in args[:6]]
            }
            self.result['syscalls'].append(entry)
            self.call_count += 1
            return None
        return callback