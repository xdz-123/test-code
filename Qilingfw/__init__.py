# qilingfw/__init__.py
from .scanner import ScanResult, BatchScanner
from .fuzzer import FuzzEngine
from .verifier import OverflowVerifier
from .utils import ensure_tmp_dir, load_vuln_targets

class FirmwareAnalyzer:
    """固件分析器统一入口"""

    def __init__(self, rootfs: str, arch: str = None, verbose: bool = False):
        """
        Args:
            rootfs: 固件根文件系统路径（宿主机绝对路径）
            arch: 目标架构（如 'arm', 'mips'），默认自动检测
            verbose: 是否输出详细调试信息
        """
        self.rootfs = rootfs
        self.arch = arch
        self.verbose = verbose

    def scan(self, targets: list, hooks: list = None, timeout: int = 10,
             output_dir: str = "./results") -> 'ScanResult':
        """
        批量扫描二进制文件
        Args:
            targets: 目标列表，支持通配符（如 ['/bin/*', '/sbin/*']）
            hooks: 启用的钩子列表，可选 'crash', 'syscall'，默认 ['crash']
            timeout: 单个二进制超时时间（秒）
            output_dir: 结果输出目录
        Returns:
            ScanResult 对象，包含统计和详细结果
        """
        scanner = BatchScanner(self.rootfs, self.arch, timeout, self.verbose)
        if hooks is None:
            hooks = ['crash']
        scanner.enable_hooks(hooks)
        return scanner.run(targets, output_dir)

    def fuzz(self, binary: str, args: list = None, seeds: list = None,
             max_iter: int = 500, payload_size: int = 500,
             output_dir: str = "./fuzz_results") -> int:
        """
        模糊测试
        Args:
            binary: 目标二进制在宿主机上的绝对路径
            args: 命令行参数列表，'@@' 将被替换为输入文件路径
            seeds: 初始种子列表（bytes 列表），默认 [b"test\\n"]
            max_iter: 最大测试次数
            payload_size: 变异输入长度上限
            output_dir: 崩溃输出目录
        Returns:
            发现的崩溃次数
        """
        if args is None:
            args = ["cat", "@@"]  # 默认以 cat 方式读取输入
        engine = FuzzEngine(binary, self.rootfs, output_dir, seeds, max_iter, payload_size)
        return engine.run()

    def verify_overflow(self, func_name: str, func_addr: int,
                        websGetVar_calls: list, external_calls: list,
                        payload: bytes = None) -> bool:
        """
        验证栈缓冲区溢出漏洞（需从 IDA 提取调用信息）
        Args:
            func_name: 函数名
            func_addr: 函数入口地址
            websGetVar_calls: [(call_addr, next_addr), ...] websGetVar 调用点信息
            external_calls: 外部函数调用列表 [{'call_addr':..., 'target_addr':..., 'target_name':...}, ...]
            payload: 注入的超长字符串，默认 b'B'*500
        Returns:
            True 表示成功触发溢出（内存违规且寄存器含 payload 特征）
        """
        verifier = OverflowVerifier(self.rootfs, self.verbose)
        return verifier.verify(func_name, func_addr, websGetVar_calls, external_calls, payload)

    @staticmethod
    def load_vuln_targets(json_file: str) -> list:
        """加载 IDA 提取的漏洞目标 JSON 文件"""
        return load_vuln_targets(json_file)