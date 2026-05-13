
# Stage 2: 二进制分析引擎 – 使用说明

## 概述
Stage 2 负责使用 IDA Pro 在 Headless 模式下分析 ARM 二进制文件 (`httpd`)，根据 Stage 1 输出的 `vuln_paths.json` 定位漏洞函数，提取关键汇编代码和危险函数交叉引用，生成结构化的 `asm_code.json` 供 Stage 3 使用。

## 文件说明
- **ida_controller.py** – 启动器，负责调用 IDA 并传入正确参数。
- **ida_extract.py** – IDAPython 插件，在 IDA 内部执行分析逻辑。
- **httpd** – 待分析的 ARM ELF 目标文件。
- **vuln_paths.json** – Stage 1 输出的漏洞路径描述文件。

## 环境要求
- Linux 服务器（x86_64 或 aarch64）
- **IDA Pro 9.3** 已安装并配置许可证（确保可以命令行调用）
- Python 3.6+
- 依赖库：`json`, `subprocess`, `os`（均为标准库）

## 配置 IDA 路径（重要！）
打开 `ida_controller.py`，找到以下行：
```python
ida_path = r"D:\IDA Pro 9.3\idat.exe"   # 示例为 Windows 路径
