# 漏洞分析系统

## 项目概述

IoT 固件二进制漏洞分析平台，针对 ARM-32 架构的 `httpd` 二进制文件。分三个阶段：Excel 解析 → IDA Pro 静态提取汇编 → LLM 分析可利用性。

## 目录结构

```
├── stage1_parse_excel.py      # Stage 1: Excel → JSON 预处理
├── stage2_ida_controller.py   # Stage 2: 调度 IDA Pro 自动运行
├── stage2_ida_extract.py      # Stage 2: IDA Pro 插件（提取汇编+xrefs）
├── stage3_vuln_analyzer.py    # Stage 3: 汇编预处理 + LLM 分析 + 报告渲染
├── app.py                     # Streamlit Web 界面（前端，暂不使用）
├── config.json                # LLM + IDA + 路径配置
├── Qilingfw/                  # 动态仿真分析库（后续使用）
│   ├── scanner.py             #   批量扫描 ELF 二进制
│   ├── fuzzer.py              #   轻量级模糊测试
│   ├── verifier.py            #   定向栈溢出验证
│   └── hooks/                 #   仿真钩子（crash/syscall/bypass）
│
├── targets.xlsx               # 输入：漏洞审计数据
├── httpd                      # 输入：ARM-32 ELF 目标二进制
│
├── vuln_paths.json            # 中间产物：Stage2 输入，漏洞调用路径
├── asm_code.json              # 中间产物：Stage2 输出，汇编代码
├── enriched_analysis.json     # 中间产物：Stage3 预处理输出
│
├── exploit_result.json        # 最终输出：LLM 分析结果（结构化）
├── analysis_report.md         # 最终输出：LLM 分析报告（人类阅读）
└── vuln_analyzer.log          # 运行时日志
```

## 数据流

```
targets.xlsx
    │  stage1_parse_excel.py
    ▼
vuln_paths.json
    │  stage2_ida_controller.py + stage2_ida_extract.py (需要 IDA Pro)
    ▼
asm_code.json
    │  stage3_vuln_analyzer.py --stage 1   (预处理：正则提取调用点/栈帧/字符串)
    │  stage3_vuln_analyzer.py --stage 2   (LLM分析：逐个漏洞调LLM出报告)
    ▼
exploit_result.json + analysis_report.md
```

## 各阶段说明

### Stage 1: Excel 解析
- **脚本**: `stage1_parse_excel.py`
- **输入**: `targets.xlsx`（审计结果表，列：设备名、二进制名、触发路径、敏感函数、审计结果）
- **输出**: `vulnerabilities_compact.json` / `vulnerabilities_full.json`
- **说明**: 将 Excel 转为结构化 JSON，自动推断漏洞类型（buffer_overflow/format_string 等），生成精简版以节省 LLM token

### Stage 2: IDA Pro 汇编提取
- **调度脚本**: `stage2_ida_controller.py`
- **IDA 插件**: `stage2_ida_extract.py`（由 IDA Pro 内部 Python 执行）
- **输入**: `vuln_paths.json` + `httpd`
- **输出**: `asm_code.json`（函数汇编最多40条 + 危险函数引用 xrefs_to）
- **说明**: 调用 `idat.exe -A -B` 自动模式运行，通过环境变量传递输入输出路径。危险函数集：`strcpy, strcat, sprintf, system, execve, memcpy`

### Stage 3: LLM 分析
- **脚本**: `stage3_vuln_analyzer.py`
- **子阶段1 (预处理)**: 正则解析 ARM 汇编，提取 BL 调用点、栈帧大小、字符串引用，合并 vuln_paths 元数据 → `enriched_analysis.json`
- **子阶段2 (LLM 分析)**: 渐进加载 Prompt，每个漏洞独立调 LLM（分而治之），LLM 出 JSON、Python 渲染 Markdown（分析/排版分离）

```bash
python stage3_vuln_analyzer.py              # 全流程
python stage3_vuln_analyzer.py --stage 1    # 仅预处理
python stage3_vuln_analyzer.py --stage 2    # 仅 LLM 分析
```

## 技术栈

- **LLM**: DeepSeek / Grok (xAI)，openai SDK 兼容调用，配置在 `config.json`
- **静态分析**: IDA Pro 9.3（idat.exe 自动模式 + Python 插件）
- **动态仿真**: Qiling Framework（后续使用，当前未接入）
- **架构**: 目标 ARM-32，开发 Windows/Linux 均可

## JSON 文件格式规范

### vuln_paths.json（Stage 2 输入）

```json
{
  "binary_file": "httpd",
  "vulnerabilities": [
    {
      "vuln_id": "VULN-01",                    // string, 唯一标识
      "vuln_type": "Stack Overflow",           // string, 漏洞类型
      "call_path": [                           // array, 调用路径
        {"function": "GetParentControlInfo",   //   string, 函数名
         "address": "0x466F4"}                 //   string, 地址 (可空)
      ],
      "trigger_conditions": "...",             // string, 触发条件
      "input_vector": "HTTP Header: ..."       // string, 输入来源
    }
  ]
}
```

### asm_code.json（Stage 2 输出 → Stage 3 输入）

```json
{
  "binary_file": "httpd",
  "architecture": "ARM-32",
  "vulnerabilities": [
    {
      "vuln_id": "VULN-01",
      "functions": [
        {
          "name": "GetParentControlInfo",      // string, 函数名
          "start_address": "0x466F4",          // string, 入口地址 (十六进制)
          "assembly": [                        // array, 最多40条指令
            {
              "address": "0x466F4",            //   string, 指令地址
              "instruction": "PUSH {R4-R11,LR}",//  string, IDA 反汇编文本
              "bytes": "F04F2DE9"              //   string, 原始机器码 (hex)
            }
          ],
          "xrefs_to": ["strcpy", "sprintf"]    // array, 函数内调用的危险函数名
        }
      ]
    }
  ]
}
```

### enriched_analysis.json（Stage 3 预处理输出）

在 `asm_code.json` 基础上，Stage 3 正则解析汇编新增以下字段：

```json
{
  "function": {
    "stack_frame_size": 60,         // int, SUB SP,SP,#N 提取 (0=未匹配)
    "total_instructions": 20,       // int, 实际指令数
    "truncated": false,             // bool, 是否触发40条截断上限
    "external_calls": [             // array, 所有 BL 调用点
      {
        "call_addr": "0x46740",    //   string, 调用指令地址
        "next_addr": "0x46744",    //   string, 返回地址 (下一条指令或call_addr+4)
        "target_name": "websGetVar",//  string, 被调用函数名
        "is_websGetVar": true      //   bool, 是否为攻击面入口
      }
    ],
    "websGetVar_calls": [          // array, external_calls 的子集
      {"call_addr": "0x46740", "next_addr": "0x46744"}
    ],
    "indirect_calls": [            // array, BLX Rn 等间接调用
      {"call_addr": "0x...", "instruction": "BLX R3"}
    ],
    "string_refs": [               // array, 注释中的字符串常量
      {"address": "0x46710", "string": "mac"}
    ]
  }
}
```

顶层还合并了 `vuln_paths.json` 的元数据（`vuln_type`, `trigger_conditions`, `input_vector`, `call_path`）。

### exploit_result.json（Stage 3 最终输出）

```json
{
  "binary_file": "httpd",
  "architecture": "ARM-32",
  "analysis_metadata": {
    "generated_at": "2026-06-04T13:14:46",
    "total_analyzed": 1,
    "exploitable": 1,
    "uncertain": 0,
    "not_exploitable": 0,
    "error": 0
  },
  "results": [
    {
      "vuln_id": "VULN-01",
      "exploitability": "exploitable",   // exploitable | not-exploitable | uncertain | error
      "confidence": 0.85,                // float, 0.0 ~ 1.0
      "root_cause": "...",               // string, 中文根因分析 (引用汇编地址)
      "data_flow": "...",                // string, 输入→危险函数的数据流
      "exploit_method": "...",           // string, 利用方法 (仅文字, 不输出字节)
      "payload_structure": "...",        // string, Payload 结构描述
      "requirements": "...",             // string, 利用前提条件
      "mitigation": "...",               // string, 修复建议
      "_raw_response": "..."             // string (调试用), LLM 原始响应
    }
  ]
}
```

---

## 配置（config.json）

```json
{
  "llm": { "api_key": "", "base_url": "", "model": "", "max_tokens": 8192, "temperature": 0.1 },
  "ida": { "path": "C:\\Program Files\\IDA Professional 9.3\\idat.exe", "timeout": 300 },
  "paths": { "excel_file": "targets.xlsx", "binary_file": "httpd" }
}
```

## 设计策略

借鉴 Claude Code 三条核心策略：

1. **分而治之**: Stage 3 每个漏洞独立调 LLM，上下文短、分析深、失败不传染
2. **渐进加载**: Prompt 分概要区（调用清单+栈帧+危险函数）和细节区（完整汇编），LLM 先定位攻击面再逐条验证
3. **分析/排版分离**: LLM 输出纯 JSON（确定性高），Python 脚本渲染 Markdown（格式可控），解析失败有降级策略

## 注意事项

- 脚本需在项目根目录运行
- IDA headless 模式不稳定，函数名匹配偶尔失败
- 汇编截断上限 40 条，Stage 3 会检测并警告
- LLM API 超时 120s，失败自动重试 1 次
- 每个漏洞独立调 LLM，单个失败不影响其他
- Prompt 要求 LLM 不输出实际字节序列，只文字描述 payload 结构
- Stage 3 当前未计算 PUSH 寄存器保存区，栈偏移可能不准（已知问题）
