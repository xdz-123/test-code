# 📘 QilingFW API 使用文档
QilingFW 是一个基于 Qiling 框架的固件安全分析模块，提供简洁的 Python API，用于批量扫描、模糊测试和定向漏洞验证。
本模块封装了在用户态仿真环境中分析嵌入式二进制文件的核心能力，特别适合容器化或受限环境。
## 🛠 安装与依赖
### 环境要求
- Python 3.8+
- Qiling 框架 ≥ 1.4.8
- 操作系统：Linux（推荐 Ubuntu 20.04+）
-（可选）pyelftools、capstone 用于地址提取

### 安装步骤
1. 将 qilingfw 目录复制到你的项目根目录下（如 /root/qiling-framework/）。
2. 安装 Qiling 框架（如果未安装）：

   `pip3 install --user qiling`

3. 安装附加依赖：

   `pip3 install --user pyyaml pyelftools capstone`

4. 导入模块：

   `from qilingfw import FirmwareAnalyzer`
## 📁 模块目录结构
```plaintext
qilingfw/
├── __init__.py          # 暴露 FirmwareAnalyzer 入口
├── scanner.py           # 批量扫描引擎
├── fuzzer.py            # 模糊测试引擎
├── verifier.py          # 定向漏洞验证器
├── utils.py             # 工具函数（根文件系统修复、JSON加载）
└── hooks/
    ├── __init__.py
    ├── crash.py         # 内存违规监控
    ├── syscall.py       # 系统调用追踪
    └── bypass.py        # 通用绕过钩子（close 循环等）
```
## 🚀 快速开始
脚本start_quick.py，在Qilingfw中

## 📖 API 详细说明
### FirmwareAnalyzer 类

`analyzer = FirmwareAnalyzer(rootfs, arch=None, verbose=False)`

| 参数    | 类型   | 说明                                                         |
| ------- | ------ | ------------------------------------------------------------ |
| rootfs  | str    | 固件根文件系统的宿主机绝对路径。                             |
| arch    | str    | 目标架构（'arm', 'mips', 'x86'），默认自动检测。             |
| verbose | bool   | 是否输出 Qiling 调试信息。                                   |

### 1. scan(targets, hooks=['crash'], timeout=10, output_dir='./results')
批量执行二进制文件并收集运行结果。

| 参数        | 类型     | 说明                                                           |
| ----------- | -------- | -------------------------------------------------------------- |
| targets     | list     | 待扫描目标列表。可以是精确路径（'/bin/busybox'）或通配符（'/bin/*'）。 |
| hooks       | list     | 启用的钩子，可选 'crash'、'syscall'。                          |
| timeout     | int      | 每个程序超时时间（秒）。                                       |
| output_dir  | str      | 结果 JSON 输出目录。                                           |

返回值：ScanResult 对象，包含：
- summary() → 字典 {'total', 'success', 'timeout', 'error', 'crash'}
- results → 列表，每个元素为包含 binary, status, crash, syscalls 的字典。

示例：
```
result = analyzer.scan(["/bin/busybox"], hooks=["crash", "syscall"], timeout=5)
print(result.summary()['success'])  
```

### 2.fuzz(binary, args=['cat', '@@'], seeds=None, max_iter=500, payload_size=500, output_dir='./fuzz_results')
轻量级模糊测试，随机变异输入并捕获崩溃.

| 参数          | 类型          | 说明                                 |
| ------------- | ------------- | ------------------------------------ |
| binary        | str           | 目标二进制宿主机绝对路径。           |
| args          | list          | 命令行参数，'@@' 会被替换为临时文件。 |
| seeds         | list[bytes]   | 初始种子列表，默认 [b"test\n"]。     |
| max_iter      | int           | 最大测试次数。                       |
| payload_size  | int           | 变异输入长度上限。                   |
| output_dir    | str           | 崩溃样本输出目录。                   |

返回值：int — 发现的崩溃次数。

示例：
`crashes = analyzer.fuzz("/root/qiling/rootfs/bin/busybox", args=["cat", "@@"])`

### 3.verify_overflow(func_name, func_addr, websGetVar_calls, external_calls, payload=b'B'*500)
定向验证栈缓冲区溢出漏洞（需配合 IDA 提取的调用信息）。

| 参数             | 类型   | 说明                                                                 |
| ---------------- | ------ | -------------------------------------------------------------------- |
| func_name        | str    | 函数名（仅用于日志）。                                               |
| func_addr        | int    | 函数入口地址。                                                       |
| websGetVar_calls | list   | [(call_addr, next_addr), ...] 每个元素为 websGetVar 调用指令地址和下一条指令地址。 |
| external_calls   | list   | 外部函数调用列表，每项包含 target_addr、target_name。                |
| payload          | bytes  | 超长注入字符串。                                                     |

返回值：bool — 是否成功触发溢出（内存违规且寄存器出现 0x42424242）。

示例：
```
overflow = analyzer.verify_overflow(
    "formSetFirewallCfg", 0x50048,
    [(0x500A4, 0x500A8)],
    [{'target_addr': 0x15A88, 'target_name': 'GetValue'}, ...]
)
```

### 4. load_vuln_targets(json_file)
静态方法，加载 IDA 提取的漏洞目标 JSON。

`targets = FirmwareAnalyzer.load_vuln_targets("vuln_targets.json")`

## 🧪 自带钩子说明
模块内置常用钩子，在漏洞验证时自动启用绕过以下行为：
| 钩子               | 功能                                               |
| ------------------ | -------------------------------------------------- |
| close 循环         | 跳过嵌入式守护进程的无限 close 循环。              |
| sysconf / getrlimit| 限制文件描述符上限，避免死循环。                   |
| socketcall         | 拦截所有 ARM 网络调用，返回成功。                  |
| clone / fork       | 模拟子进程创建，返回合法 PID。                     |

这些钩子确保 httpd 等守护进程能够顺利初始化，并执行到用户可控的代码路径。

## 📂 结果文件结构
扫描结果保存在指定 output_dir 下，文件格式：
```
{
  "scan_time": "2025-06-01T12:00:00",
  "total": 5,
  "success": 4,
  "timeout": 0,
  "error": 1,
  "crash": 0,
  "results": [
    {
      "binary": "/bin/busybox",
      "args": ["--help"],
      "status": "success",
      "crash": null,
      "syscalls": [],
      "duration": 0.12
    }
  ]
}
```

模糊测试崩溃文件为 crash_0001_iter234.bin 格式。

## 🔧 常见问题
### 1. 扫描结果总为 0
- 检查 rootfs 路径是否正确，是否存在对应二进制。
- 确认二进制是 ELF 文件（file 命令检查）。
- 使用通配符时确保路径与 rootfs 正确拼接，例如 "/bin/*" 会映射到 <rootfs>/bin/*。

### 2. 程序输出大量 connect 或 syscall not implemented 错误
- 嵌入式程序依赖硬件或守护进程，是预期行为。
- 可通过 hooks 参数启用 syscall 追踪，或使用 verbose=False 关闭输出。
### 3. 模糊测试无崩溃
- 大多数基础工具健壮性高，属于正常现象。
- 可尝试更换目标（如网络服务）或增加迭代次数。
### 4. 漏洞验证未触发溢出
- 确保 websGetVar_calls 和 external_calls 从 IDA 正确提取。
- 检查 payload 长度是否足够覆盖栈缓冲区（通常 500 字节足够）。
- 若仍失败，可能需额外模拟环境变量或 NVRAM 值。

## 📚 示例项目
完整测试脚本 test_api.py 包含扫描、模糊测试和漏洞验证的示例，可参考.

# 补充
json文件格式参考上传的vuln_targets.json，已经对verifier.py进行了功能扩展.
