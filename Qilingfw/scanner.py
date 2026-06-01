# qilingfw/scanner.py
import os
import json
import time
import signal
import glob
import traceback
from datetime import datetime
from typing import List, Dict, Any
from qiling import Qiling
from qiling.const import QL_VERBOSE
from .hooks import CrashMonitor, SyscallTracer
from .utils import ensure_tmp_dir

class ScanResult:
    """扫描结果容器"""
    def __init__(self, total: int, results: List[Dict]):
        self.total = total
        self.results = results
        self.success = sum(1 for r in results if r['status'] == 'success')
        self.timeout = sum(1 for r in results if r['status'] == 'timeout')
        self.error = sum(1 for r in results if r['status'] == 'error')
        self.crash = sum(1 for r in results if r.get('crash'))

    def summary(self) -> dict:
        return {
            "total": self.total,
            "success": self.success,
            "timeout": self.timeout,
            "error": self.error,
            "crash": self.crash
        }

    def save(self, path: str):
        with open(path, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'total': self.total,
                'success': self.success,
                'timeout': self.timeout,
                'error': self.error,
                'crash': self.crash,
                'results': self.results
            }, f, indent=2)

class BatchScanner:
    """批量二进制扫描器"""

    def __init__(self, rootfs: str, arch: str = None, timeout: int = 10, verbose: bool = False):
        self.rootfs = rootfs
        self.arch = arch
        self.timeout = timeout
        self.verbose = verbose
        self.hook_names = []
        ensure_tmp_dir(rootfs)

    def enable_hooks(self, hook_names: list):
        """启用指定钩子"""
        self.hook_names = hook_names

    def run(self, targets: list, output_dir: str = "./results") -> ScanResult:
        """运行扫描，返回结果对象"""
        expanded_targets = self._expand_targets(targets)
        os.makedirs(output_dir, exist_ok=True)

        all_results = []
        for i, t in enumerate(expanded_targets, 1):
            binary = t['binary']
            args = t.get('args', [])
            print(f"[{i}/{len(expanded_targets)}] Scanning {binary} {args}")
            result = self._analyze_one(binary, args)
            all_results.append(result)

        scan_result = ScanResult(len(all_results), all_results)
        scan_result.save(os.path.join(output_dir, f"summary_{int(time.time())}.json"))
        return scan_result

    def _expand_targets(self, targets: list) -> list:
        """展开通配符，返回具体的 binary 字典列表"""
        expanded = []
        for t in targets:
            if 'binary' in t:
                # 检查文件是否存在
                host_path = os.path.join(self.rootfs, t['binary'].lstrip('/'))
                if os.path.isfile(host_path):
                    expanded.append(t)
            elif 'pattern' in t:
                pattern = os.path.join(self.rootfs, t['pattern'].lstrip('/'))
                exclude = set(t.get('exclude', []))
                for f in glob.glob(pattern):
                    if not os.path.isfile(f):
                        continue
                    virt_path = '/' + os.path.relpath(f, self.rootfs)
                    if virt_path in exclude:
                        continue
                    if not self._is_elf(f):
                        continue
                    expanded.append({
                        'binary': virt_path,
                        'args': t.get('args', [])
                    })
        return expanded

    def _is_elf(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                return f.read(4) == b'\x7fELF'
        except:
            return False

    def _analyze_one(self, binary: str, args: list) -> dict:
        """分析单个二进制"""
        result = {
            'binary': binary,
            'args': args,
            'timestamp': datetime.now().isoformat(),
            'status': 'unknown',
            'crash': None,
            'syscalls': [],
            'error': None,
            'duration': 0
        }

        host_binary = os.path.join(self.rootfs, binary.lstrip('/'))
        if not os.path.exists(host_binary):
            result['status'] = 'error'
            result['error'] = f"Binary not found: {host_binary}"
            return result

        try:
            signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(TimeoutError()))
            signal.alarm(self.timeout)

            start = time.time()
            ql = Qiling([host_binary] + args, self.rootfs,
                        verbose=QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF)
            self._init_hooks(ql, result)
            ql.run()

            signal.alarm(0)
            result['status'] = 'success'
            result['duration'] = time.time() - start
        except TimeoutError:
            result['status'] = 'timeout'
            result['error'] = f"Timeout after {self.timeout}s"
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            result['traceback'] = traceback.format_exc()
        finally:
            signal.alarm(0)

        return result

    def _init_hooks(self, ql: Qiling, result: dict):
        if 'crash' in self.hook_names:
            CrashMonitor(ql, result)
        if 'syscall' in self.hook_names:
            SyscallTracer(ql, result)