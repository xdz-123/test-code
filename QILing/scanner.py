#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import signal
import traceback
import argparse
import yaml
import glob
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from qiling import Qiling
from qiling.const import QL_VERBOSE

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from hooks.crash_monitor import CrashMonitor
from hooks.syscall_tracer import SyscallTracer
from hooks.memory_guard import MemoryGuard

class QilingScanner:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.rootfs = self.config['global']['rootfs']
        self.timeout = self.config['global'].get('timeout', 30)
        self.verbose = self.config['global'].get('verbose', False)

        self.output_dir = Path(self.config['output'].get('path', './results'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.current_result = {}

    def _get_abs_binary(self, binary: str) -> str:
        if binary.startswith('/'):
            binary = binary[1:]
        host_path = os.path.join(self.rootfs, binary)
        if not os.path.exists(host_path):
            raise FileNotFoundError(f"Binary not found: {host_path}")
        return host_path

    def _expand_targets(self) -> List[Dict[str, Any]]:
        targets = []
        for t in self.config.get('targets', []):
            if 'binary' in t:
                targets.append(t)
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
                    targets.append({
                        'binary': virt_path,
                        'args': t.get('args', [])
                    })
        return targets

    def _is_elf(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                return f.read(4) == b'\x7fELF'
        except:
            return False

    def _init_hooks(self, ql: Qiling):
        hooks_cfg = self.config.get('hooks', {})
        enabled = hooks_cfg.get('enabled', [])

        if 'crash_monitor' in enabled:
            CrashMonitor(ql, self.current_result)
        if 'syscall_tracer' in enabled:
            max_calls = hooks_cfg.get('syscall_tracer', {}).get('max_calls', 1000)
            SyscallTracer(ql, self.current_result, max_calls)
        if 'memory_guard' in enabled:
            MemoryGuard(ql, self.current_result)

    def _timeout_handler(self, signum, frame):
        raise TimeoutError(f"Execution timeout ({self.timeout}s)")

    def analyze_one(self, binary: str, args: List[str]) -> Dict[str, Any]:
        result = {
            'binary': binary,
            'args': args,
            'timestamp': datetime.now().isoformat(),
            'status': 'unknown',
            'crash': None,
            'syscalls': [],
            'memory_errors': [],
            'error': None,
            'duration': 0
        }
        self.current_result = result

        host_binary = self._get_abs_binary(binary)

        try:
            signal.signal(signal.SIGALRM, self._timeout_handler)
            signal.alarm(self.timeout)

            start_time = time.time()
            ql = Qiling([host_binary] + args, self.rootfs,
                        verbose=QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF)

            self._init_hooks(ql)

            ql.run()

            signal.alarm(0)
            result['duration'] = time.time() - start_time
            result['status'] = 'success'

        except TimeoutError as e:
            result['status'] = 'timeout'
            result['error'] = str(e)
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            result['traceback'] = traceback.format_exc()

        finally:
            signal.alarm(0)

        return result

    def run(self):
        targets = self._expand_targets()
        print(f"[*] Total targets to analyze: {len(targets)}")

        all_results = []
        for i, t in enumerate(targets, 1):
            binary = t['binary']
            args = t.get('args', [])
            print(f"[{i}/{len(targets)}] Analyzing {binary} {args}")

            result = self.analyze_one(binary, args)
            all_results.append(result)

            if result['status'] == 'crash' or result['status'] == 'error':
                self._save_result(result, f"crash_{i}_{os.path.basename(binary)}.json")

        self._save_summary(all_results)

    def _save_result(self, result: Dict, filename: str):
        out_path = self.output_dir / filename
        with open(out_path, 'w') as f:
            json.dump(result, f, indent=2)

    def _save_summary(self, all_results: List[Dict]):
        summary = {
            'scan_time': datetime.now().isoformat(),
            'total': len(all_results),
            'success': sum(1 for r in all_results if r['status'] == 'success'),
            'timeout': sum(1 for r in all_results if r['status'] == 'timeout'),
            'error': sum(1 for r in all_results if r['status'] == 'error'),
            'crash': sum(1 for r in all_results if r.get('crash')),
            'results': all_results
        }
        out_path = self.output_dir / f"summary_{int(time.time())}.json"
        with open(out_path, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Summary saved to {out_path}")

def main():
    parser = argparse.ArgumentParser(description='Qiling Firmware Binary Scanner')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()

    scanner = QilingScanner(args.config)
    scanner.run()

if __name__ == '__main__':
    main()
