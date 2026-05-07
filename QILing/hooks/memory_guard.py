from qiling import Qiling

class MemoryGuard:
    def __init__(self, ql: Qiling, result_dict: dict):
        self.ql = ql
        self.result = result_dict
        self._register_hooks()

    def _register_hooks(self):
        self.ql.hook_mem_read(self._on_mem_read)
        self.ql.hook_mem_write(self._on_mem_write)

    def _on_mem_read(self, ql: Qiling, addr: int, size: int):
        pass

    def _on_mem_write(self, ql: Qiling, addr: int, size: int, value: int):
        pass
