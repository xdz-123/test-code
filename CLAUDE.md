# 漏洞分析系统 - 项目上下文

## 项目概述
基于LLM的二进制漏洞分析与利用生成系统。从Excel提取漏洞路径 → angr提取汇编 → LLM分析生成攻击指令。

## 文件结构
```
test-code/
├── vuln_analyzer.py    # 主控脚本，三阶段工作流（使用angr）
├── ida_extract.py      # IDA Python脚本（已弃用，保留备用）
├── path_vuln_analyzer.py # 参考实现（angr路径补全+动态验证）
├── config.json         # 配置：DeepSeek API key、angr设置、文件路径
├── requirements.txt    # openai, openpyxl, pydantic, python-dotenv, angr
├── targets.xlsx        # 输入：漏洞路径信息（格式不固定）
├── httpd               # 输入：ARM 32-bit ELF可执行文件（1.6MB）
├── vuln_paths.json     # 中间产物：LLM从Excel提取的结构化漏洞路径
├── asm_code.json       # 中间产物：IDA提取的汇编代码
└── exploit_result.json # 最终输出：可利用性判断和攻击指令
```

## 工作流（三阶段）
1. **Stage 1** `ExcelParser` → LLM读取targets.xlsx → 输出vuln_paths.json
2. **Stage 2** `AngrController` → angr加载二进制+CFG分析 → 提取汇编 → 输出asm_code.json
3. **Stage 3** `VulnAnalyzer` → LLM读asm_code.json → 输出exploit_result.json

## 关键类（vuln_analyzer.py）
- `LLMClient` - DeepSeek API封装，openai SDK + base_url="https://api.deepseek.com"
- `ExcelParser` - openpyxl读Excel转文本，LLM提取结构化信息
- `PathCompletionEngine` - angr CFG路径补全，填充漏洞路径中间基本块
- `AngrDisassembler` - angr+capstone提取函数汇编指令和危险函数调用
- `AngrController` - 调用PathCompletionEngine和AngrDisassembler，生成asm_code.json
- `IDAController` - 已弃用，保留备用（subprocess调用idat.exe）
- `VulnAnalyzer` - LLM分析汇编，判断可利用性，生成exploit
- `WorkflowOrchestrator` - 协调三阶段，统一错误处理
- Pydantic模型：`VulnPaths`, `AsmCode`, `ExploitResults` 用于JSON验证

## IDA脚本（ida_extract.py）- 已弃用
- 由IDA内部Python环境执行，不能用外部包
- `idaapi.auto_wait()` 等待分析完成
- 通过函数名或地址查找函数，提取汇编+交叉引用
- 工作目录从 `idc.get_idb_path()` 推断
- 结束时调用 `idc.qexit(0)`
- **问题**：headless模式不稳定，工作目录推断失败，函数名匹配困难
- **替代方案**：已用angr替代，无需IDA

## JSON格式
- **vuln_paths.json**: binary_file, vulnerabilities[]{vuln_id, vuln_type, call_path[]{function,address,note}, trigger_conditions, input_vector}
- **asm_code.json**: binary_file, architecture, vulnerabilities[]{vuln_id, functions[]{name, start_address, assembly[]{address,instruction,bytes}, xrefs_to[]}}
- **exploit_result.json**: binary_file, timestamp, results[]{vuln_id, exploitable, confidence, analysis, exploit{method,payload,command,prerequisites[]}, reason}

## 注意事项
- angr自动识别架构（ARM/x86/x64），无需手动指定
- angr使用capstone反汇编，支持多架构（ARM、x86、MIPS等）
- PathCompletionEngine补全CFG路径，解决Excel中地址不连续问题
- AngrDisassembler检测危险函数调用（strcpy、printf、system等）
- LLM输出JSON时会提取markdown代码块（```json...```）
- 每个漏洞分析独立调用LLM，失败不影响其他漏洞
- IDA相关代码已弃用但保留，可通过config.json切换（未实现）

## 已知问题与修复记录

### Stage 3 JSON解析失败（已修复）
**问题**：LLM在生成exploit payload时输出大量填充字符（如AAAA...），导致响应超过max_tokens限制被截断，JSON不完整无法解析

**修复方案**：
1. 在prompt中添加明确指令：要求LLM不输出实际字节序列，只用文字描述payload结构（如"200字节的'A'填充 + 0xdeadbeef返回地址"）
2. 在`_analyze_single_vuln`中添加try/except错误处理，解析失败时返回失败结果而不是崩溃
3. 减少每个函数的汇编指令数量限制（从50条减少到30条）
4. 增加max_tokens从4096到8192
5. 添加详细日志输出LLM原始响应用于调试

### LLM API超时（已修复）
**问题**：LLMClient.call()无timeout参数，API响应慢时无限等待

**修复**：在openai API调用中添加`timeout=120`参数

### 配置文件路径问题
**注意**：必须在项目目录（test-code/）下运行程序，否则找不到config.json
