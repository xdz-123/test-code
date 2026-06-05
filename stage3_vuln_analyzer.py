#!/usr/bin/env python3
"""
IoT 固件漏洞分析器 — 第三阶段主脚本。
Stage 1: 汇编预处理（正则提取调用点、栈帧、字符串）
Stage 2: LLM 逐个分析漏洞 → 输出 JSON + Markdown 报告
"""

import json
import os
import re
import sys
import time
import argparse
import traceback
from datetime import datetime
from typing import Optional

# ============================================================
# DualLogger: 同时写 stdout（flush）和日志文件
# ============================================================
class DualLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.file_handle = open(log_path, 'w', encoding='utf-8')

    def log(self, message: str):
        print(message, flush=True)
        self.file_handle.write(message + '\n')
        self.file_handle.flush()

    def close(self):
        self.file_handle.close()


# ============================================================
# Stage 1: 汇编预处理
# ============================================================
class Stage1Parser:
    """解析 asm_code.json + vuln_paths.json，提取结构化信息"""

    # ARM 调用指令: BL/BLX target_name (含条件变体: BLEQ, BLNE...)
    RE_BL_CALL = re.compile(
        r'^\s*BL(?:EQ|NE|CS|CC|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE)?\s+(\w+)\s*$',
        re.IGNORECASE
    )
    # ARM 间接调用: BLX Rn
    RE_BLX_REG = re.compile(r'^\s*BLX\s+(R\d+|LR)\s*$', re.IGNORECASE)
    # 栈帧分配: SUB SP, SP, #imm
    RE_STACK_SUB = re.compile(
        r'^\s*SUB\s+SP\s*,\s*SP\s*,\s*#(0x[0-9a-fA-F]+|\d+)\s*$',
        re.IGNORECASE
    )
    # 注释中的字符串: ; "string"
    RE_STRING = re.compile(r';\s*"([^"]*)"')

    def __init__(self, asm_path: str, paths_path: str, logger: DualLogger):
        self.asm_path = asm_path
        self.paths_path = paths_path
        self.logger = logger

    def run(self) -> dict:
        self.logger.log("[Stage 1] 开始汇编预处理...")

        if not os.path.exists(self.asm_path):
            raise FileNotFoundError(f"asm_code.json 不存在: {self.asm_path}")
        if not os.path.exists(self.paths_path):
            raise FileNotFoundError(f"vuln_paths.json 不存在: {self.paths_path}")

        with open(self.asm_path, 'r', encoding='utf-8') as f:
            asm_data = json.load(f)
        with open(self.paths_path, 'r', encoding='utf-8') as f:
            paths_data = json.load(f)

        # 按 vuln_id 建立 paths 索引
        path_map = {}
        for p in paths_data.get("vulnerabilities", []):
            path_map[p.get("vuln_id", "")] = p

        enriched_vulns = []
        for vuln_asm in asm_data.get("vulnerabilities", []):
            vid = vuln_asm.get("vuln_id", "?")
            path = path_map.get(vid)
            if path is None:
                self.logger.log(f"  [WARN] {vid}: 在 vuln_paths.json 中未找到，使用默认元数据")
                path = {}

            try:
                enriched = self._enrich_one(vuln_asm, path)
                enriched_vulns.append(enriched)
                self.logger.log(f"  [{vid}] 预处理完成 ({len(vuln_asm.get('functions',[]))} 个函数)")
            except Exception as e:
                self.logger.log(f"  [ERROR] {vid}: 预处理失败 - {e}")
                enriched_vulns.append({
                    "vuln_id": vid,
                    "error": str(e),
                    "functions": []
                })

        result = {
            "binary_file": asm_data.get("binary_file", ""),
            "architecture": asm_data.get("architecture", "ARM-32"),
            "analysis_metadata": {
                "generated_at": datetime.now().isoformat(),
                "source_files": [self.asm_path, self.paths_path],
                "total_vulnerabilities": len(enriched_vulns),
                "schema_version": "1.0"
            },
            "vulnerabilities": enriched_vulns
        }

        self.logger.log(f"[Stage 1] 完成: {len(enriched_vulns)} 个漏洞已富化")
        return result

    def _enrich_one(self, vuln_asm: dict, vuln_path: dict) -> dict:
        enriched_funcs = []
        for func in vuln_asm.get("functions", []):
            ef = self._parse_function(func)
            enriched_funcs.append(ef)

        return {
            "vuln_id": vuln_asm.get("vuln_id", ""),
            "vuln_type": vuln_path.get("vuln_type", "Unknown"),
            "trigger_conditions": vuln_path.get("trigger_conditions", ""),
            "input_vector": vuln_path.get("input_vector", ""),
            "call_path": vuln_path.get("call_path", []),
            "functions": enriched_funcs
        }

    def _parse_function(self, func: dict) -> dict:
        asmlines = func.get("assembly", [])
        stack_frame = self._extract_stack_frame(asmlines)
        string_refs = self._extract_string_refs(asmlines)
        total = len(asmlines)
        truncated = (total == 40)

        # 优先使用 Stage 2 IDA 提取的 external_calls（带 target_addr）
        if func.get("external_calls"):
            ext_calls = func["external_calls"]
            # 转换为 Stage 3 内部格式（添加 is_websGetVar 标记）
            for ec in ext_calls:
                ec["is_websGetVar"] = (ec.get("target_name") == "websGetVar")
            webs_calls = [{"call_addr": ec["call_addr"], "next_addr": ""} for ec in ext_calls if ec.get("target_name") == "websGetVar"]
            indirect_calls = []
        else:
            # 回退：通过正则解析汇编
            call_sites = self._extract_call_sites(asmlines)
            ext_calls = call_sites["external_calls"]
            webs_calls = call_sites["websGetVar_calls"]
            indirect_calls = call_sites["indirect_calls"]

        return {
            "name": func.get("name", ""),
            "start_address": func.get("start_address", ""),
            "stack_frame_size": stack_frame,
            "total_instructions": total,
            "truncated": truncated,
            "assembly": asmlines,
            "external_calls": ext_calls,
            "websGetVar_calls": webs_calls,
            "indirect_calls": indirect_calls,
            "dangerous_xrefs": func.get("xrefs_to", []),
            "string_refs": string_refs
        }

    # ---- 调用点提取 ----
    def _extract_call_sites(self, asmlines: list) -> dict:
        external = []
        websGetVar = []
        indirect = []

        for i, line in enumerate(asmlines):
            instr = line.get("instruction", "")
            call_addr = line.get("address", "")

            m = self.RE_BL_CALL.match(instr)
            if m:
                target = m.group(1)
                next_addr = self._next_addr(asmlines, i, call_addr)
                entry = {
                    "call_addr": call_addr,
                    "next_addr": next_addr,
                    "target_name": target,
                    "is_websGetVar": (target == "websGetVar")
                }
                external.append(entry)
                if target == "websGetVar":
                    websGetVar.append({"call_addr": call_addr, "next_addr": next_addr})
                continue

            m = self.RE_BLX_REG.match(instr)
            if m:
                indirect.append({"call_addr": call_addr, "instruction": instr.strip()})

        return {
            "external_calls": external,
            "websGetVar_calls": websGetVar,
            "indirect_calls": indirect
        }

    @staticmethod
    def _next_addr(asmlines: list, i: int, call_addr: str) -> str:
        if i + 1 < len(asmlines):
            return asmlines[i + 1].get("address", "")
        try:
            return hex(int(call_addr, 16) + 4)
        except (ValueError, TypeError):
            return ""

    # ---- 栈帧提取 ----
    @staticmethod
    def _extract_stack_frame(asmlines: list) -> int:
        for line in asmlines[:5]:
            instr = line.get("instruction", "")
            m = Stage1Parser.RE_STACK_SUB.search(instr)
            if m:
                raw = m.group(1)
                return int(raw, 16) if raw.startswith("0x") else int(raw)
        return 0

    # ---- 字符串引用提取 ----
    @staticmethod
    def _extract_string_refs(asmlines: list) -> list:
        refs = []
        for line in asmlines:
            instr = line.get("instruction", "")
            m = Stage1Parser.RE_STRING.search(instr)
            if m:
                refs.append({
                    "address": line.get("address", ""),
                    "string": m.group(1)
                })
        return refs

    @staticmethod
    def save(data: dict, output_path: str):
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ============================================================
# Stage 2: LLM 分析 + 报告渲染
# ============================================================
class Stage2Analyzer:
    """逐个漏洞调 LLM 分析，生成 JSON 结果 + Markdown 报告"""

    def __init__(self, enriched_path: str, config: dict, logger: DualLogger):
        self.enriched_path = enriched_path
        self.config = config
        self.logger = logger
        self.client = None
        self.model = ""
        self.max_tokens = 8192
        self.temperature = 0.1

    def run(self) -> list:
        self.logger.log("[Stage 2] 开始 LLM 分析...")

        if not os.path.exists(self.enriched_path):
            raise FileNotFoundError(f"enriched_analysis.json 不存在: {self.enriched_path}")

        with open(self.enriched_path, 'r', encoding='utf-8') as f:
            self.enriched_data = json.load(f)

        self._init_llm_client()

        vulns = self.enriched_data.get("vulnerabilities", [])
        results = []
        total = len(vulns)

        for i, vuln in enumerate(vulns, 1):
            vid = vuln.get("vuln_id", f"#{i}")
            self.logger.log(f"  [{i}/{total}] 分析 {vid} ...")
            result = self._analyze_one(vuln)
            results.append(result)
            self.logger.log(f"  [{i}/{total}] {vid}: {result.get('exploitability', '?')} "
                            f"(置信度 {result.get('confidence', 0)})")

        self.logger.log(f"[Stage 2] 完成: {total} 个漏洞已分析")
        return results

    def _init_llm_client(self):
        from openai import OpenAI
        llm_cfg = self.config.get("llm", {})
        self.client = OpenAI(
            api_key=llm_cfg.get("api_key", ""),
            base_url=llm_cfg.get("base_url", "https://api.openai.com/v1")
        )
        self.model = llm_cfg.get("model", "gpt-4")
        self.max_tokens = llm_cfg.get("max_tokens", 8192)
        self.temperature = llm_cfg.get("temperature", 0.1)
        self.logger.log(f"  使用 LLM: {self.model} @ {llm_cfg.get('base_url', '')}")

    def _analyze_one(self, vuln: dict) -> dict:
        vid = vuln.get("vuln_id", "unknown")

        for attempt in range(2):
            try:
                prompt = self._build_prompt(vuln)
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    timeout=120
                )
                content = response.choices[0].message.content
                parsed = self._parse_json_response(content)
                parsed["vuln_id"] = vid
                parsed["_raw_response"] = content
                return parsed

            except Exception as e:
                error_str = str(e)
                if "timeout" in error_str.lower() or "timed out" in error_str.lower():
                    self.logger.log(f"    [{vid}] API 超时 (尝试 {attempt+1}/2)")
                    if attempt == 0:
                        time.sleep(3)
                        continue
                elif attempt == 0:
                    self.logger.log(f"    [{vid}] 调用失败: {e}，重试一次...")
                    time.sleep(2)
                    continue

                self.logger.log(f"    [{vid}] 最终失败: {e}")
                return {
                    "vuln_id": vid,
                    "exploitability": "error",
                    "confidence": 0.0,
                    "root_cause": f"LLM 分析失败: {error_str}",
                    "data_flow": "",
                    "exploit_method": "",
                    "payload_structure": "",
                    "requirements": "",
                    "mitigation": "",
                    "error": error_str
                }

    def _build_prompt(self, vuln: dict) -> str:
        """构建渐进加载式 Prompt"""
        parts = []

        # 角色设定
        parts.append("你是一位资深 IoT 固件安全研究员，专精 ARM-32 二进制漏洞分析与利用。")

        # Header
        parts.append("=" * 60)
        parts.append("第一层：函数概要（攻击面定位）")
        parts.append("=" * 60)

        # 漏洞基本信息
        call_path_str = " -> ".join(
            cp.get("function", "") for cp in vuln.get("call_path", [])
        ) or "未知"
        parts.append(f"- 漏洞ID: {vuln.get('vuln_id', '?')}")
        parts.append(f"- 漏洞类型: {vuln.get('vuln_type', 'Unknown')}")
        parts.append(f"- 触发条件: {vuln.get('trigger_conditions', '未知')}")
        parts.append(f"- 输入向量: {vuln.get('input_vector', '未知')}")
        parts.append(f"- 调用路径: {call_path_str}")

        # 逐函数分析
        for func in vuln.get("functions", []):
            parts.append("")
            parts.append(f"## 函数: {func.get('name', '?')}")
            parts.append(f"- 入口地址: {func.get('start_address', '?')}")
            sf = func.get("stack_frame_size", 0)
            if sf > 0:
                parts.append(f"- 栈帧大小: {sf} 字节（局部变量空间；若溢出，返回地址在偏移 {sf+4} 处）")
            else:
                parts.append(f"- 栈帧大小: 未知（未匹配到 SUB SP 指令）")

            total = func.get("total_instructions", 0)
            truncated = func.get("truncated", False)
            warn = " ⚠️ 已触发40条截断上限，后续调用点可能缺失！" if truncated else ""
            parts.append(f"- 总指令数: {total} 条{warn}")

            # 外部调用清单（攻击面标注）
            ext_calls = func.get("external_calls", [])
            if ext_calls:
                parts.append("")
                parts.append("### 外部函数调用清单（攻击面标注）")
                parts.append("| 调用地址  | 目标函数           | 角色          |")
                parts.append("|-----------|--------------------|---------------|")
                for ec in ext_calls:
                    role = ""
                    if ec.get("is_websGetVar"):
                        role = "⚠️ 攻击面入口"
                    elif ec.get("target_name") in ("strcpy", "strcat", "sprintf",
                                                    "memcpy", "system", "execve",
                                                    "gets", "scanf", "sscanf"):
                        role = "🔴 危险函数"
                    elif ec.get("target_name") in ("memset", "memmove", "strlen",
                                                    "strncpy", "snprintf", "malloc",
                                                    "free", "printf"):
                        role = "安全/工具"
                    else:
                        role = "工具函数"
                    parts.append(
                        f"| {ec['call_addr']} | {ec['target_name']} | {role} |"
                    )

            # 危险函数 xrefs
            xrefs = func.get("dangerous_xrefs", [])
            if xrefs:
                parts.append(f"\n### IDA 交叉引用到的危险函数: {', '.join(xrefs)}")

            # 字符串引用
            srefs = func.get("string_refs", [])
            if srefs:
                parts.append(f"\n### 字符串引用: {', '.join(s['string'] for s in srefs)}")

            # 间接调用
            indirects = func.get("indirect_calls", [])
            if indirects:
                parts.append(f"\n### 间接调用（寄存器跳转）: "
                             f"{', '.join(c['call_addr'] for c in indirects)}")

        # 第二层: 完整汇编
        parts.append("")
        parts.append("=" * 60)
        parts.append("第二层：完整汇编代码（逐条验证数据流）")
        parts.append("=" * 60)

        for func in vuln.get("functions", []):
            parts.append(f"\n### {func.get('name', '?')} ({func.get('start_address', '?')})")
            for a in func.get("assembly", []):
                parts.append(f"  {a['address']}: {a['instruction']}")

        # 输出要求
        parts.append("")
        parts.append("=" * 60)
        parts.append("## 分析要求（输出纯 JSON，不要包含 ```json 标记，控制总长度在 1500 字以内）")
        parts.append("=" * 60)
        parts.append("""
{
  "vuln_id": "VULN-01",
  "exploitability": "exploitable / not-exploitable / uncertain",
  "confidence": 0.85,
  "root_cause": "简明描述根因（200字内），引用关键地址",
  "data_flow": "简要数据流（150字内）",
  "exploit_method": "简要利用方法（150字内）",
  "payload_structure": "Payload 结构（100字内）",
  "requirements": "前置条件（100字内）",
  "mitigation": "修复建议（100字内）"
}""")

        return '\n'.join(parts)

    def _parse_json_response(self, text: str) -> dict:
        """解析 LLM 响应的 JSON，带降级策略（支持被截断的响应）"""
        if not text:
            raise ValueError("LLM 返回空响应")

        text = text.strip()

        # 尝试1: 直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 尝试2: 去除 ```json ... ``` 包装
        if text.startswith("```"):
            lines = text.split('\n')
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() in ("```", "```json"):
                lines = lines[:-1]
            try:
                return json.loads('\n'.join(lines))
            except json.JSONDecodeError:
                pass

        # 尝试3: 正则提取第一个 JSON 对象（支持不完整 JSON）
        m = re.search(r'\{[\s\S]*', text)
        if m:
            candidate = m.group(0)
            # 尝试修复被截断的 JSON：补全缺失的引号和括号
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # 尝试修复：如果以未闭合的字符串结束，补全它
                fixed = self._fix_truncated_json(candidate)
                if fixed:
                    try:
                        return json.loads(fixed)
                    except json.JSONDecodeError:
                        pass

        raise ValueError(f"无法从 LLM 响应中解析 JSON: {text[:300]}...")

    @staticmethod
    def _fix_truncated_json(text: str) -> Optional[str]:
        """尝试修复被截断的 JSON 字符串"""
        # 统计未闭合的引号
        quote_count = text.count('"') - text.count('\\"')
        # 如果引号数量为奇数，说明字符串被截断
        if quote_count % 2 == 1:
            text += '"'

        # 统计未闭合的括号
        open_braces = text.count('{')
        close_braces = text.count('}')
        open_brackets = text.count('[')
        close_brackets = text.count(']')

        # 补全缺失的闭合符号
        text += ']' * (open_brackets - close_brackets)
        text += '}' * (open_braces - close_braces)

        return text

    @staticmethod
    def render_report(results: list, binary_file: str, arch: str) -> str:
        """将 LLM 分析结果渲染为 Markdown 报告"""
        lines = []
        lines.append(f"# 🔍 漏洞分析报告")
        lines.append(f"")
        lines.append(f"**二进制文件**: `{binary_file}`  ")
        lines.append(f"**架构**: `{arch}`  ")
        lines.append(f"**分析时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**分析数量**: {len(results)} 个漏洞")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 概览表
        lines.append("## 📊 概览")
        lines.append("")
        lines.append("| # | 漏洞ID | 可利用性 | 置信度 |")
        lines.append("|---|--------|----------|--------|")
        for i, r in enumerate(results, 1):
            expl = r.get("exploitability", "?")
            conf = r.get("confidence", 0)
            emoji = "🔴" if expl == "exploitable" else ("🟡" if expl == "uncertain" else "🟢")
            lines.append(f"| {i} | {r.get('vuln_id', '?')} | {emoji} {expl} | {conf:.0%} |")
        lines.append("")

        # 详细分析
        lines.append("---")
        lines.append("")
        lines.append("## 📋 详细分析")
        lines.append("")

        for i, r in enumerate(results, 1):
            vid = r.get("vuln_id", f"#{i}")
            expl = r.get("exploitability", "?")

            if expl == "error":
                lines.append(f"### {i}. {vid} ⚠️ 分析失败")
                lines.append(f"> **错误**: {r.get('root_cause', '未知错误')}")
                lines.append("")
                continue

            emoji = "🔴" if expl == "exploitable" else ("🟡" if expl == "uncertain" else "🟢")
            lines.append(f"### {i}. {vid} {emoji} {expl}")
            lines.append("")

            lines.append(f"| 属性 | 值 |")
            lines.append(f"|------|-----|")
            lines.append(f"| **可利用性** | {expl} |")
            lines.append(f"| **置信度** | {r.get('confidence', 0):.0%} |")
            lines.append("")

            if r.get("root_cause"):
                lines.append(f"#### 🔬 根因分析")
                lines.append(r["root_cause"])
                lines.append("")

            if r.get("data_flow"):
                lines.append(f"#### 🔄 数据流")
                lines.append(r["data_flow"])
                lines.append("")

            if r.get("exploit_method"):
                lines.append(f"#### 💥 利用方法")
                lines.append(r["exploit_method"])
                lines.append("")

            if r.get("payload_structure"):
                lines.append(f"#### 🧱 Payload 结构")
                lines.append(r["payload_structure"])
                lines.append("")

            if r.get("requirements"):
                lines.append(f"#### ⚙️ 利用前提")
                lines.append(r["requirements"])
                lines.append("")

            if r.get("mitigation"):
                lines.append(f"#### 🛡️ 修复建议")
                lines.append(r["mitigation"])
                lines.append("")

            lines.append("---")
            lines.append("")

        lines.append("")
        lines.append("*报告由 vuln_analyzer.py 自动生成*")

        return '\n'.join(lines)

    @staticmethod
    def save_results(results: list, enriched_data: dict, output_path: str):
        """保存 exploit_result.json"""
        data = {
            "binary_file": enriched_data.get("binary_file", ""),
            "architecture": enriched_data.get("architecture", "ARM-32"),
            "analysis_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_analyzed": len(results),
                "exploitable": sum(1 for r in results if r.get("exploitability") == "exploitable"),
                "uncertain": sum(1 for r in results if r.get("exploitability") == "uncertain"),
                "not_exploitable": sum(1 for r in results if r.get("exploitability") == "not-exploitable"),
                "error": sum(1 for r in results if r.get("exploitability") == "error")
            },
            "results": results
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ============================================================
# Orchestrator
# ============================================================
class VulnAnalyzerOrchestrator:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.logger = DualLogger(args.log_file)
        self.config = self._load_config(args.config)

    def _load_config(self, path: str) -> dict:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        self.logger.log(f"[WARN] 配置文件 {path} 不存在，使用空配置")
        return {}

    @staticmethod
    def _extract_stage4_targets(enriched_data: dict) -> list:
        """
        从 enriched 数据中提取 Stage 4 所需的拦截目标列表（Qiling hook 表）

        输出格式（扁平数组）:
        [
            {"call_addr": 389288, "target_addr": 88088, "target_name": "strcpy"},
            {"call_addr": 389300, "target_addr": 316384, "target_name": "set_wl_guest_qos_list"},
            ...
        ]

        说明:
        - call_addr: BL 调用指令的地址（十进制整数）
        - target_addr: 被调用函数的实际地址（十进制整数）
        - target_name: 函数名
        """
        def to_int(val):
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                return int(val, 16) if val.startswith("0x") else int(val)
            return 0

        targets = []
        for vuln in enriched_data.get("vulnerabilities", []):
            for func in vuln.get("functions", []):
                for ec in func.get("external_calls", []):
                    try:
                        call_addr = to_int(ec.get("call_addr", 0))
                        target_addr = to_int(ec.get("target_addr", 0))
                        target_name = ec.get("target_name", "unknown")
                        targets.append({
                            "call_addr": call_addr,
                            "target_addr": target_addr,
                            "target_name": target_name
                        })
                    except (ValueError, TypeError):
                        continue
        return targets

    def run(self):
        stage = self.args.stage
        enriched_path = self.args.enriched_input

        # Stage 1: 预处理
        if stage in (0, 1):
            try:
                parser = Stage1Parser(self.args.asm_input, self.args.path_input, self.logger)
                enriched = parser.run()
                Stage1Parser.save(enriched, enriched_path)
                self.logger.log(f"[Stage 1] 富化数据已保存 → {enriched_path}")

                # 生成 Stage 4 简化目标文件
                stage4_targets = self._extract_stage4_targets(enriched)
                stage4_path = self.args.stage4_targets
                with open(stage4_path, 'w', encoding='utf-8') as f:
                    json.dump(stage4_targets, f, indent=2, ensure_ascii=False)
                self.logger.log(f"[Stage 1] Stage 4 目标文件已保存 → {stage4_path}")
            except Exception as e:
                self.logger.log(f"[Stage 1] 失败: {e}")
                self.logger.log(traceback.format_exc())
                if stage == 1:
                    self.logger.close()
                    return

        # Stage 2: LLM 分析
        if stage in (0, 2):
            try:
                analyzer = Stage2Analyzer(enriched_path, self.config, self.logger)
                results = analyzer.run()

                # 需要 enriched_data 来生成报告
                with open(enriched_path, 'r', encoding='utf-8') as f:
                    enriched_data = json.load(f)

                # 保存 JSON
                Stage2Analyzer.save_results(results, enriched_data, self.args.result_output)
                self.logger.log(f"[Stage 2] 结构化结果 → {self.args.result_output}")

                # 渲染并保存 Markdown 报告
                report = Stage2Analyzer.render_report(
                    results,
                    enriched_data.get("binary_file", ""),
                    enriched_data.get("architecture", "")
                )
                report_path = self.args.result_output.replace('.json', '_report.md')
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                self.logger.log(f"[Stage 2] Markdown 报告 → {report_path}")

                # 统计
                expl = sum(1 for r in results if r.get("exploitability") == "exploitable")
                total = len(results)
                self.logger.log(f"[Stage 2] {expl}/{total} 个漏洞可被利用")

            except Exception as e:
                self.logger.log(f"[Stage 2] 失败: {e}")
                self.logger.log(traceback.format_exc())

        self.logger.log("完成。")
        self.logger.close()


# ============================================================
# CLI 入口
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IoT 固件漏洞分析器 — 汇编预处理 + LLM 分析")
    parser.add_argument("--stage", type=int, choices=[1, 2], default=0,
                        help="运行指定阶段 (0=全部, 1=预处理, 2=LLM分析)")
    parser.add_argument("--asm-input", default="asm_code.json",
                        help="IDA 提取的汇编 JSON")
    parser.add_argument("--path-input", default="vuln_paths.json",
                        help="漏洞路径 JSON")
    parser.add_argument("--enriched-input", default="enriched_analysis.json",
                        help="预处理后的中间 JSON")
    parser.add_argument("--result-output", default="exploit_result.json",
                        help="LLM 分析结果 JSON")
    parser.add_argument("--log-file", default="vuln_analyzer.log",
                        help="日志文件路径")
    parser.add_argument("--config", default="config.json",
                        help="LLM 配置文件")
    parser.add_argument("--stage4-targets", default="stage4_targets.json",
                        help="Stage 4 简化目标文件（函数名+地址+调用点）")
    args = parser.parse_args()

    orchestrator = VulnAnalyzerOrchestrator(args)
    orchestrator.run()
