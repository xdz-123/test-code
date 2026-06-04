from qilingfw import FirmwareAnalyzer

# 初始化分析器
analyzer = FirmwareAnalyzer(
    rootfs="/path/to/firmware_rootfs",
    arch="arm",          # 可选，不指定则自动检测
    verbose=False        # 开启详细输出
)

# 1. 批量扫描二进制
result = analyzer.scan(
    targets=["/bin/busybox", "/bin/ls"],  # 支持通配符 "/bin/*"
    hooks=["crash"],                      # 可选 'crash' 或 'syscall'
    timeout=10,
    output_dir="./results"
)
print(result.summary())  # {'total': 2, 'success': 2, 'timeout': 0, ...}

# 2. 模糊测试
crash_count = analyzer.fuzz(
    binary="/path/to/binary",
    args=["cat", "@@"],          # '@@' 会被替换为临时文件
    seeds=[b"test\n"],           # 初始种子
    max_iter=500,
    output_dir="./fuzz_results"
)

# 3. 定向漏洞验证（需 IDA 提取的 JSON）
targets = analyzer.load_vuln_targets("vuln_targets.json")
for t in targets:
    overflow = analyzer.verify_overflow(
        func_name=t["func_name"],
        func_addr=t["func_addr"],
        websGetVar_calls=t.get("websGetVar_calls", []),
        external_calls=t.get("external_calls", []),
        payload=b"B" * 500
    )
    print(f"{t['func_name']}: {'溢出' if overflow else '未触发'}")
