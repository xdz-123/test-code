    def __init__(self, objdump_path: str = None):
        # objdump_path 参数保留兼容性，但不再使用
        pass

    def analyze(self, binary_file: str, vuln_paths_file: str, output_file: str) -> bool:
        """分析二进制文件并生成asm_code.json"""
        logger.info(f"Starting angr analysis: {binary_file}")

        try:
            # 加载二进制
            logger.info("Loading binary with angr...")
            proj = angr.Project(binary_file, auto_load_libs=False)
            path_engine = PathCompletionEngine(proj)
            disassembler = AngrDisassembler(proj)

            # 读取漏洞路径
            with open(vuln_paths_file, 'r', encoding='utf-8') as f:
                vuln_data = json.load(f)

            # 获取架构信息
            arch = proj.arch.name
            logger.info(f"Architecture: {arch}")

            # 构建输出数据
            output_data = {
                "binary_file": vuln_data.get("binary_file", ""),
                "architecture": arch,
                "vulnerabilities": []
