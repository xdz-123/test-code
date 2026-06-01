# qilingfw/fuzzer.py
import os
import random
from qiling import Qiling
from qiling.const import QL_VERBOSE
from .hooks import CrashMonitor
from .utils import ensure_tmp_dir

class FuzzEngine:
    def __init__(self, binary: str, rootfs: str, output_dir: str,
                 seeds: list = None, max_iter: int = 500, payload_size: int = 500):
        self.binary = binary
        self.rootfs = rootfs
        self.output_dir = output_dir
        self.max_iter = max_iter
        self.payload_size = payload_size
        self.seeds = seeds if seeds else [b"test\n"]
        self.crash_count = 0
        ensure_tmp_dir(rootfs)
        os.makedirs(output_dir, exist_ok=True)

    def _mutate(self, data: bytes) -> bytes:
        data = bytearray(data)
        if random.random() < 0.1 and len(data) < self.payload_size * 2:
            data.insert(random.randint(0, len(data)), random.randrange(0, 256))
        if random.random() < 0.1 and len(data) > 1:
            del data[random.randint(0, len(data) - 1)]
        for _ in range(random.randint(1, 3)):
            if len(data) > 0:
                data[random.randint(0, len(data) - 1)] = random.randrange(0, 256)
        return bytes(data)

    def run(self) -> int:
        pool = list(self.seeds)
        for i in range(self.max_iter):
            parent = random.choice(pool)
            inp = self._mutate(parent)

            fname = f'fuzz_{i}.bin'
            host_path = os.path.join(self.rootfs, 'tmp', fname)
            with open(host_path, 'wb') as f:
                f.write(inp)

            result = {'crash': None}
            try:
                ql = Qiling([self.binary, "cat", f"/tmp/{fname}"], self.rootfs,
                            verbose=QL_VERBOSE.OFF)
                CrashMonitor(ql, result)
                ql.run()
            except Exception:
                pass
            finally:
                try:
                    os.remove(host_path)
                except:
                    pass

            if result.get('crash'):
                self.crash_count += 1
                crash_path = os.path.join(self.output_dir, f"crash_{self.crash_count:04d}_iter{i}.bin")
                with open(crash_path, 'wb') as f:
                    f.write(inp)
                print(f"[!] Crash #{self.crash_count} at iteration {i}: {result['crash']}")
                pool.append(inp)  # 简单种子扩展

            if (i + 1) % 50 == 0:
                print(f"[*] Iteration {i+1}, crashes so far: {self.crash_count}")

        return self.crash_count