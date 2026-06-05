# 漏洞分析系统

## 项目概述

IoT 固件二进制漏洞分析平台，针对 ARM-32 架构的 `httpd` 二进制文件。

**核心流程**：Excel 解析 → IDA Pro 静态提取汇编 → LLM 分析可利用性

**当前状态**：Stage 1-3 已完成，Stage 4（Qiling 动态验证）暂不使用，但 Stage 3 会生成 Stage 4 所需的 JSON 文件。

---

## 快速开始

### 环境准备

1. **Python 环境**：Python 3.8+
2. **依赖安装**：
   ```bash
   pip install openai
   ```
3. **IDA Pro 9.3**：需要安装在 Windows，路径配置在 `config.json`
4. **LLM API Key**：DeepSeek / Grok，配置在 `config.json`

### 完整运行流程

```bash
# Stage 1: Excel → JSON 预处理
python stage1_parse_excel.py

# Stage 2: IDA Pro 提取汇编（需要 IDA Pro 环境）
python stage2_ida_controller.py

# Stage 3: 预处理 + LLM 分析（生成 stage4_targets.json）
python stage3_vuln_analyzer.py

# 查看结果
cat exploit_result.json
cat exploit_result_report.md
cat stage4_targets.json
```

### 分阶段运行

```bash
# 仅预处理（生成 enriched_analysis.json 和 stage4_targets.json）
python stage3_vuln_analyzer.py --stage 1

# 仅 LLM 分析（需要 enriched_analysis.json）
python stage3_vuln_analyzer.py --stage 2
```

---

## 目录结构

```
test/
├── stage1_parse_excel.py      # Stage 1: Excel 解析脚本
├── stage2_ida_controller.py   # Stage 2: IDA 调度脚本
├── stage2_ida_extract.py      # Stage 2: IDA 插件（在 IDA 内运行）
├── stage3_vuln_analyzer.py    # Stage 3: 预处理 + LLM 分析
├── config.json                # 配置文件（LLM API + IDA 路径）
├── targets.xlsx               # 输入：漏洞审计 Excel 表
├── httpd                      # 输入：ARM-32 目标二进制
│
├── vuln_paths.json            # 中间产物：Stage 1 输出，漏洞路径
├── asm_code.json              # 中间产物：Stage 2 输出，汇编代码
├── enriched_analysis.json     # 中间产物：Stage 3 预处理输出
├── stage4_targets.json        # 中间产物：Stage 4 拦截目标（Qiling 用）
│
├── exploit_result.json        # 最终输出：LLM 分析结果（结构化）
├── exploit_result_report.md   # 最终输出：LLM 分析报告（人类阅读）
└── vuln_analyzer.log          # 运行日志
```

---

## 三阶段详解

### Stage 1: Excel 解析

**脚本**：`stage1_parse_excel.py`

**输入**：`targets.xlsx`（审计结果表）

**输出**：`vuln_paths.json`

**功能**：
- 读取 Excel 审计结果（设备名、二进制名、触发路径、敏感函数、审计结果）
- 自动推断漏洞类型（buffer_overflow / format_string / command_injection）
- 生成结构化 JSON，供 Stage 2 使用

**运行**：
```bash
python stage1_parse_excel.py
```

---

### Stage 2: IDA Pro 汇编提取

**调度脚本**：`stage2_ida_controller.py`

**IDA 插件**：`stage2_ida_extract.py`（由 IDA Pro 内部 Python 执行）

**输入**：`vuln_paths.json` + `httpd` 二进制

**输出**：`asm_code.json`

**功能**：
- 调用 `idat.exe -A -B` 自动模式运行 IDA Pro
- 提取每个漏洞相关函数的汇编代码（最多 40 条指令）
- 提取危险函数交叉引用（`strcpy`, `sprintf`, `system` 等）
- 提取所有外部函数调用（`external_calls`，包含调用地址和目标地址）

**运行**：
```bash
python stage2_ida_controller.py
```

**注意**：
- 需要 Windows + IDA Pro 9.3 环境
- `config.json` 中配置 IDA 路径：`"ida": {"path": "C:\\Program Files\\IDA Professional 9.3\\idat.exe"}`
- 如果 IDA 路径错误，需手动修改 `config.json`

---

### Stage 3: 预处理 + LLM 分析

**脚本**：`stage3_vuln_analyzer.py`

**输入**：`asm_code.json` + `vuln_paths.json`

**输出**：
- `enriched_analysis.json`：富化后的分析数据
- `stage4_targets.json`：Stage 4 所需的拦截目标列表（**必须生成**）
- `exploit_result.json`：LLM 分析结果（结构化 JSON）
- `exploit_result_report.md`：LLM 分析报告（Markdown 格式）

**子阶段**：

#### Stage 3.1: 汇编预处理

```bash
python stage3_vuln_analyzer.py --stage 1
```

**功能**：
- 正则解析 ARM 汇编，提取：
  - `BL` 调用点（调用地址、目标函数名、是否为 `websGetVar`）
  - 栈帧大小（`SUB SP, SP, #N`）
  - 字符串引用
- 合并 `vuln_paths.json` 的元数据（漏洞类型、触发条件、输入向量）
- **生成 `stage4_targets.json`**：扁平数组格式，供 Qiling 动态验证使用

**`stage4_targets.json` 格式**（示例）：
```json
[
  {"call_addr": 389288, "target_addr": 88088, "target_name": "strcpy"},
  {"call_addr": 389300, "target_addr": 316384, "target_name": "set_wl_guest_qos_list"},
  {"call_addr": 389304, "target_addr": 88112, "target_name": "CommitCfm"}
]
```

**字段说明**：
- `call_addr`: `BL` 调用指令的地址（十进制整数）
- `target_addr`: 被调用函数的实际地址（十进制整数）
- `target_name`: 函数名

**注意**：即使不运行 Stage 4（Qiling），也必须生成此文件，供后续扩展使用。

#### Stage 3.2: LLM 分析

```bash
python stage3_vuln_analyzer.py --stage 2
```

**功能**：
- 逐个漏洞调用 LLM 分析可利用性
- LLM 输出 JSON（根因分析、数据流、利用方法、Payload 结构、修复建议）
- Python 渲染 Markdown 报告（分析/排版分离）

**LLM 配置**（`config.json`）：
```json
{
  "llm": {
    "api_key": "your-api-key",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-chat",
    "max_tokens": 16384,
    "temperature": 0.1
  }
}
```

**支持的 LLM**：
- DeepSeek（推荐，性价比高）
- Grok（xAI）
- 任何 OpenAI SDK 兼容的 API

---

## 数据流图

```
targets.xlsx
    │  stage1_parse_excel.py
    ▼
vuln_paths.json
    │  stage2_ida_controller.py + stage2_ida_extract.py
    ▼
asm_code.json
    │  stage3_vuln_analyzer.py --stage 1
    ▼
enriched_analysis.json + stage4_targets.json
    │  stage3_vuln_analyzer.py --stage 2
    ▼
exploit_result.json + exploit_result_report.md
```

---

## 配置文件

**文件**：`config.json`

```json
{
  "llm": {
    "api_key": "sk-xxxxx",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-chat",
    "max_tokens": 16384,
    "temperature": 0.1
  },
  "ida": {
    "path": "C:\\Program Files\\IDA Professional 9.3\\idat.exe",
    "timeout": 300
  },
  "paths": {
    "excel_file": "targets.xlsx",
    "binary_file": "httpd"
  }
}
```

**必填项**：
- `llm.api_key`: LLM API Key
- `ida.path`: IDA Pro 安装路径（Windows）

---

## 常见问题

### Q: Stage 2 运行失败，提示找不到 IDA

**A**: 检查 `config.json` 中的 `ida.path` 是否正确，需指向 `idat.exe` 的完整路径。

### Q: LLM 分析失败，JSON 解析错误

**A**: 
1. 增加 `config.json` 中的 `max_tokens`（如 16384）
2. 检查 LLM API 是否正常
3. 查看 `vuln_analyzer.log` 中的错误详情

### Q: `stage4_targets.json` 格式不对

**A**: 确保运行了 `stage3_vuln_analyzer.py --stage 1`，该阶段会生成正确的扁平数组格式。

### Q: 不想运行 Stage 4（Qiling），还要生成 `stage4_targets.json` 吗？

**A**: 是的。Stage 3.1 必须生成此文件，即使暂不使用 Stage 4，后续扩展时也需要此文件作为输入。

### Q: 如何只分析单个漏洞？

**A**: 当前不支持。所有漏洞会批量分析，失败的漏洞会在 `exploit_result.json` 中标记为 `"exploitability": "error"`。

---

## 开发说明

### 代码风格

- 所有脚本使用 Python 3.8+
- 中文注释和日志
- 错误处理：失败不中断，记录日志继续
- JSON 输出：`ensure_ascii=False, indent=2`

### 扩展 Stage 4（Qiling 动态验证）

当需要启用 Stage 4 时：

1. 准备 ARM 固件 rootfs（包含 `httpd` 及依赖库）
2. 安装 Qiling Framework：`pip install qiling`
3. 实现 `Qilingfw/` 模块（`scanner.py`, `verifier.py` 等）
4. 运行 `stage4_qiling_verify.py --rootfs /path/to/rootfs`

`stage4_targets.json` 格式已与 Qiling hook 需求兼容。

---

## 联系与贡献

如有问题，请查看：
- `vuln_analyzer.log`: 运行日志
- `exploit_result.json`: LLM 分析结果（含错误信息）

修改代码后，请确保：
- Stage 1-3 流程完整运行无报错
- `stage4_targets.json` 格式正确（扁平数组 + 十进制地址）
- LLM 分析结果结构完整（`exploit_result.json`）