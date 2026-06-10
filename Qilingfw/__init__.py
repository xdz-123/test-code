# qilingfw/__init__.py
from .scanner import ScanResult, BatchScanner
from .fuzzer import FuzzEngine
from .verifier import OverflowVerifier
from .utils import ensure_tmp_dir, load_vuln_targets

class FirmwareAnalyzer:
    def __init__(self, rootfs: str, arch: str = None, verbose: bool = False):
        self.rootfs = rootfs
        self.arch = arch
        self.verbose = verbose

    def scan(self, targets: list, hooks: list = None, timeout: int = 10,
             output_dir: str = "./results") -> 'ScanResult':
        scanner = BatchScanner(self.rootfs, self.arch, timeout, self.verbose)
        if hooks is None:
            hooks = ['crash']
        scanner.enable_hooks(hooks)
        return scanner.run(targets, output_dir)

    def fuzz(self, binary: str, args: list = None, seeds: list = None,
             max_iter: int = 500, payload_size: int = 500,
             output_dir: str = "./fuzz_results") -> int:
        if args is None:
            args = ["cat", "@@"]
        engine = FuzzEngine(binary, self.rootfs, output_dir, seeds, max_iter, payload_size)
        return engine.run()

    def verify_overflow(self, func_name: str, func_addr: int,
                        websGetVar_calls: list, external_calls: list,
                        payload: bytes = None,
                        payload_callback: callable = None,
                        check_callback: callable = None,
                        detect_heap: bool = True) -> bool:
        verifier = OverflowVerifier(self.rootfs, self.verbose)
        return verifier.verify(func_name, func_addr, websGetVar_calls, external_calls,
                               payload=payload,
                               payload_callback=payload_callback,
                               check_callback=check_callback,
                               detect_heap=detect_heap)

    @staticmethod
    def load_vuln_targets(json_input):
        return load_vuln_targets(json_input)
