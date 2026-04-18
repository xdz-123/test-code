# 漏洞分析系统 - 项目上下文

## 项目概述
基于LLM的二进制漏洞分析与利用生成系统。从Excel提取漏洞路径 → IDA提取汇编 → LLM分析生成攻击指令。

## 文件结构
```
test-code/
├── vuln_analyzer.py    # 主控脚本，三阶段工作流
├── ida_extract.py      # IDA Python脚本（headless模式执行）
├── config.json         # 配置：DeepSeek API key、IDA路径、文件路径
├── requirements.txt    # openai, openpyxl, pydantic, python-dotenv
├── targets.xlsx        # 输入：漏洞路径信息（格式不固定）
├── httpd               # 输入：ARM 32-bit ELF可执行文件（1.6MB）
├── vuln_paths.json     # 中间产物：LLM从Excel提取的结构化漏洞路径
├── asm_code.json       # 中间产物：IDA提取的汇编代码
└── exploit_result.json # 最终输出：可利用性判断和攻击指令
```

## 工作流（三阶段）
1. **Stage 1** `ExcelParser` → LLM读取targets.xlsx → 输出vuln_paths.json
2. **Stage 2** `IDAController` → subprocess调用IDA headless → ida_extract.py读vuln_paths.json → 输出asm_code.json
3. **Stage 3** `VulnAnalyzer` → LLM读asm_code.json → 输出exploit_result.json

## 关键类（vuln_analyzer.py）
- `LLMClient` - DeepSeek API封装，openai SDK + base_url="https://api.deepseek.com"
- `ExcelParser` - openpyxl读Excel转文本，LLM提取结构化信息
- `IDAController` - subprocess调用 `idat.exe -A -S"ida_extract.py" httpd`
- `VulnAnalyzer` - LLM分析汇编，判断可利用性，生成exploit
- `WorkflowOrchestrator` - 协调三阶段，统一错误处理
- Pydantic模型：`VulnPaths`, `AsmCode`, `ExploitResults` 用于JSON验证

## IDA脚本（ida_extract.py）
- 由IDA内部Python环境执行，不能用外部包
- `idaapi.auto_wait()` 等待分析完成
- 通过函数名或地址查找函数，提取汇编+交叉引用
- 工作目录从 `idc.get_idb_path()` 推断
- 结束时调用 `idc.qexit(0)`

## JSON格式
- **vuln_paths.json**: binary_file, vulnerabilities[]{vuln_id, vuln_type, call_path[]{function,address,note}, trigger_conditions, input_vector}
- **asm_code.json**: binary_file, architecture, vulnerabilities[]{vuln_id, functions[]{name, start_address, assembly[]{address,instruction,bytes}, xrefs_to[]}}
- **exploit_result.json**: binary_file, timestamp, results[]{vuln_id, exploitable, confidence, analysis, exploit{method,payload,command,prerequisites[]}, reason}

## 注意事项
- IDA路径在config.json的 `ida.path` 字段，默认 `idat.exe`（32位二进制用idat，64位用idat64）
- httpd是ARM 32-bit，用idat.exe而非idat64.exe
- LLM输出JSON时会提取markdown代码块（```json...```）
- 每个漏洞分析独立调用LLM，失败不影响其他漏洞
