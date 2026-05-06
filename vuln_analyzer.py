#!/usr/bin/env python3
"""
漏洞分析主控脚本
使用LLM从Excel提取漏洞信息，调用angr+objdump分析二进制，再用LLM分析汇编生成攻击指令
"""
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import angr
from openai import OpenAI
from openpyxl import load_workbook
from pydantic import BaseModel, Field


# ============ Pydantic模型定义 ============

class CallPathItem(BaseModel):
    function: str
    address: Optional[str] = None
    note: Optional[str] = None


class Vulnerability(BaseModel):
    vuln_id: str
    vuln_type: str
    description: str
    call_path: List[CallPathItem]
    trigger_conditions: str
    input_vector: str


class VulnPaths(BaseModel):
    binary_file: str
    vulnerabilities: List[Vulnerability]


class AssemblyInstruction(BaseModel):
    address: str
    instruction: str
    bytes: str


class FunctionAssembly(BaseModel):
    name: str
    start_address: str
    assembly: List[AssemblyInstruction]
    xrefs_to: List[str]


class VulnAssembly(BaseModel):
    vuln_id: str
    functions: List[FunctionAssembly]


class AsmCode(BaseModel):
    binary_file: str
    architecture: str
    vulnerabilities: List[VulnAssembly]


class ExploitInfo(BaseModel):
    method: str
    payload: str
    command: str
    prerequisites: List[str]


class ExploitResult(BaseModel):
    vuln_id: str
    exploitable: bool
    confidence: str
    analysis: str
    exploit: Optional[ExploitInfo] = None
    reason: Optional[str] = None


class ExploitResults(BaseModel):
    binary_file: str
    timestamp: str
    results: List[ExploitResult]


# ============ 日志配置 ============

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('vuln_analyzer.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ============ LLM客户端 ============

class LLMClient:
    """封装DeepSeek API调用"""

    def __init__(self, api_key: str, base_url: str, model: str, max_tokens: int = 4096, temperature: float = 0.1):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    def call(self, prompt: str, max_retries: int = 3) -> str:
        """调用LLM API，带重试机制"""
        for attempt in range(max_retries):
            try:
                logger.info(f"Calling LLM API (attempt {attempt + 1}/{max_retries}, prompt: {len(prompt)} chars)")
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    timeout=120
                )
                result = response.choices[0].message.content.strip()
                logger.info(f"LLM response received ({len(result)} chars)")
                return result
            except Exception as e:
                logger.error(f"LLM API call failed: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise


# ============ Excel解析器 ============

class ExcelParser:
    """解析Excel文件并使用LLM提取漏洞信息"""

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def read_excel(self, file_path: str) -> str:
        """读取Excel内容转为文本"""
        logger.info(f"Reading Excel file: {file_path}")
        wb = load_workbook(file_path, data_only=True)

        content_parts = []
        for sheet_name in wb.sheetnames:
            sheet = wb[sheet_name]
            content_parts.append(f"=== Sheet: {sheet_name} ===")

            for row in sheet.iter_rows(values_only=True):
                row_text = "\t".join(str(cell) if cell is not None else "" for cell in row)
                if row_text.strip():
                    content_parts.append(row_text)

        content = "\n".join(content_parts)
        logger.info(f"Excel content extracted ({len(content)} chars)")
        return content

    def extract_vuln_paths(self, excel_content: str, binary_file: str) -> VulnPaths:
        """使用LLM从Excel内容中提取漏洞路径"""
        schema = VulnPaths.model_json_schema()

        prompt = f"""你是漏洞分析专家。从以下Excel内容中提取漏洞路径信息。

Excel内容：
{excel_content}

请严格按照以下JSON schema输出，不要添加任何其他文字：
{json.dumps(schema, indent=2, ensure_ascii=False)}

注意：
1. binary_file字段填写: {binary_file}
2. 提取所有漏洞相关信息
3. call_path是漏洞触发的函数调用路径
4. 如果Excel中有函数地址，请提取到address字段
5. 输出必须是有效的JSON格式"""

        response = self.llm_client.call(prompt)

        # 尝试提取JSON（可能LLM会添加markdown代码块）
        json_str = response
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0].strip()
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0].strip()

        logger.info("Parsing LLM response as JSON")
        data = json.loads(json_str)
        return VulnPaths(**data)


# ============ angr路径补全引擎 ============

class PathCompletionEngine:
    """使用angr CFG补全漏洞路径中的中间块"""

    def __init__(self, proj: angr.Project):
        self.proj = proj
        self.cfg = proj.analyses.CFGFast()

    def complete_path_robust(self, partial_path: List[int]) -> List[int]:
        """补全路径，填充中间缺失的基本块"""
        if not partial_path:
            return partial_path
        full_path = [partial_path[0]]
        for i in range(len(partial_path) - 1):
            start = partial_path[i]
            end = partial_path[i + 1]
            if self._has_direct_edge(start, end):
                full_path.append(end)
                continue
            inter_blocks = self._get_blocks_between(start, end)
            if inter_blocks:
                full_path.extend(inter_blocks[1:])
            else:
                full_path.append(end)
        return full_path

    def _has_direct_edge(self, src: int, dst: int) -> bool:
        """检查两个地址间是否有直接边"""
        src_node = self.cfg.model.get_any_node(src)
        if src_node is None:
            return False
        return any(succ.addr == dst for succ in src_node.successors)

    def _get_blocks_between(self, start: int, end: int) -> Optional[List[int]]:
        """获取两个地址间的路径"""
        func = self.cfg.kb.functions.function(addr=start)
        if func is None or end not in [b.addr for b in func.blocks]:
            return None
        edges = {}
        for block in func.blocks:
            node = self.cfg.model.get_any_node(block.addr)
            if node:
                edges[block.addr] = [succ.addr for succ in node.successors
                                    if succ.addr in [b.addr for b in func.blocks]]
            else:
                edges[block.addr] = []
        queue = [(start, [start])]
        visited = set()
        while queue:
            cur, path = queue.pop(0)
            if cur == end:
                return path
            if cur in visited:
                continue
            visited.add(cur)
            for succ in edges.get(cur, []):
                if succ not in path:
                    queue.append((succ, path + [succ]))
        return None


# ============ angr反汇编提取器 ============

class AngrDisassembler:
    """使用angr提取汇编代码"""

    DANGEROUS_FUNCS = {
        'strcpy', 'strcat', 'gets', 'memcpy', 'free',
        'printf', 'fprintf', 'sprintf', 'snprintf', 'system'
    }

    def __init__(self, proj: angr.Project):
        self.proj = proj

    def extract_function_asm(self, func: angr.knowledge_plugins.Function) -> Tuple[List[AssemblyInstruction], List[str]]:
        """提取函数的汇编指令"""
        assembly = []
        xrefs = []

        try:
            # 遍历函数的所有基本块
            for block in func.blocks:
                # 使用 angr 的反汇编
                block_obj = self.proj.factory.block(block.addr, size=block.size)

                for insn in block_obj.capstone.insns:
                    # 格式化字节码
                    bytes_hex = ' '.join(f'{b:02x}' for b in insn.bytes)

                    # 格式化指令
                    instruction = f"{insn.mnemonic} {insn.op_str}"

                    assembly.append(AssemblyInstruction(
                        address=f"0x{insn.address:08x}",
                        instruction=instruction,
                        bytes=bytes_hex
                    ))

                    # 检测危险函数调用（ARM: bl, blx; x86: call）
                    if insn.mnemonic in ('bl', 'blx', 'call'):
                        # 尝试解析目标地址
                        target_addr = None
                        if insn.op_str.startswith('0x'):
                            target_addr = int(insn.op_str, 16)
                        elif insn.op_str.startswith('#'):
                            # ARM 立即数
                            try:
                                target_addr = int(insn.op_str[1:], 0)
                            except:
                                pass

                        if target_addr:
                            # 查找目标函数名
                            target_func = self.proj.kb.functions.floor_func(target_addr)
                            if target_func and target_func.name in self.DANGEROUS_FUNCS:
                                xrefs.append(f"{target_func.name}@0x{insn.address:08x}")

        except Exception as e:
            # 某些块可能无法反汇编，跳过
            pass

        return assembly, xrefs


# ============ angr控制器 ============

class AngrController:
    """使用angr进行二进制分析"""

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
            }

            # 处理每个漏洞
            for vuln in vuln_data.get("vulnerabilities", []):
                vuln_id = vuln.get("vuln_id", "UNKNOWN")
                logger.info(f"Processing vulnerability: {vuln_id}")

                vuln_result = {
                    "vuln_id": vuln_id,
                    "functions": []
                }

                # 提取调用路径中的地址
                addresses = []
                for path_item in vuln.get("call_path", []):
                    addr_str = path_item.get("address")
                    if addr_str:
                        try:
                            addr = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
                            addresses.append(addr)
                        except:
                            pass

                # 如果有地址，补全路径
                if addresses:
                    completed_path = path_engine.complete_path_robust(addresses)
                    logger.info(f"Path: {[hex(a) for a in completed_path]}")
                else:
                    completed_path = []

                # 提取每个地址对应的函数汇编
                processed_funcs = set()
                for addr in completed_path:
                    func = proj.kb.functions.floor_func(addr)
                    if func and func.addr not in processed_funcs:
                        processed_funcs.add(func.addr)

                        # 提取汇编
                        assembly, xrefs = disassembler.extract_function_asm(func)

                        if assembly:
                            func_result = {
                                "name": func.name,
                                "start_address": f"0x{func.addr:08x}",
                                "assembly": [a.model_dump() for a in assembly],
                                "xrefs_to": xrefs
                            }
                            vuln_result["functions"].append(func_result)
                            logger.info(f"Extracted {len(assembly)} instructions from {func.name}")

                output_data["vulnerabilities"].append(vuln_result)

            # 写入输出文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Analysis complete: {output_file}")
            return True

        except Exception as e:
            logger.error(f"angr analysis failed: {e}", exc_info=True)
            return False


# ============ IDA控制器 ============

class IDAController:
    """控制IDA Pro执行分析"""

    def __init__(self, ida_path: str, timeout: int = 300):
        self.ida_path = ida_path
        self.timeout = timeout

    def analyze(self, binary_file: str, script_path: str) -> bool:
        """调用IDA headless模式分析二进制文件"""
        logger.info(f"Starting IDA analysis: {binary_file}")

        cmd = [
            self.ida_path,
            "-A",  # 自动分析
            f'-S{script_path}',  # 执行脚本
            binary_file
        ]

        logger.info(f"IDA command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                timeout=self.timeout,
                capture_output=True,
                text=True
            )

            logger.info(f"IDA stdout:\n{result.stdout}")
            if result.stderr:
                logger.warning(f"IDA stderr:\n{result.stderr}")

            if result.returncode == 0:
                logger.info("IDA analysis completed successfully")
                return True
            else:
                logger.error(f"IDA analysis failed with code {result.returncode}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"IDA analysis timed out after {self.timeout} seconds")
            return False
        except Exception as e:
            logger.error(f"IDA analysis error: {e}")
            return False


# ============ 漏洞分析器 ============

class VulnAnalyzer:
    """使用LLM分析汇编代码并生成攻击指令"""

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def analyze(self, vuln_paths: VulnPaths, asm_code: AsmCode) -> ExploitResults:
        """分析汇编代码生成攻击指令"""
        logger.info("Starting vulnerability analysis")

        results = []

        for vuln in vuln_paths.vulnerabilities:
            logger.info(f"Analyzing vulnerability: {vuln.vuln_id}")

            # 找到对应的汇编代码
            asm_vuln = next((v for v in asm_code.vulnerabilities if v.vuln_id == vuln.vuln_id), None)
            if not asm_vuln:
                logger.warning(f"No assembly code found for {vuln.vuln_id}")
                results.append(ExploitResult(
                    vuln_id=vuln.vuln_id,
                    exploitable=False,
                    confidence="low",
                    analysis="未找到对应的汇编代码",
                    reason="IDA未能提取到相关函数的汇编代码"
                ))
                continue

            # 构建分析prompt
            result = self._analyze_single_vuln(vuln, asm_vuln, asm_code.architecture)
            results.append(result)

        return ExploitResults(
            binary_file=vuln_paths.binary_file,
            timestamp=datetime.utcnow().isoformat() + "Z",
            results=results
        )

    def _analyze_single_vuln(self, vuln: Vulnerability, asm_vuln: VulnAssembly, arch: str) -> ExploitResult:
        """分析单个漏洞"""
        schema = ExploitResult.model_json_schema()

        # 构建汇编代码摘要
        asm_summary = []
        for func in asm_vuln.functions:
            asm_summary.append(f"\n函数: {func.name} @ {func.start_address}")
            asm_summary.append(f"交叉引用: {', '.join(func.xrefs_to) if func.xrefs_to else '无'}")
            asm_summary.append("汇编代码:")
            for inst in func.assembly[:30]:  # 限制指令数量，减少prompt大小
                asm_summary.append(f"  {inst.address}: {inst.instruction}")
            if len(func.assembly) > 30:
                asm_summary.append(f"  ... (共{len(func.assembly)}条指令，已省略)")

        prompt = f"""你是二进制安全专家，分析{arch}汇编代码判断漏洞是否可触发。

漏洞信息：
- ID: {vuln.vuln_id}
- 类型: {vuln.vuln_type}
- 描述: {vuln.description}
- 触发条件: {vuln.trigger_conditions}
- 输入向量: {vuln.input_vector}
- 调用路径: {' -> '.join(p.function for p in vuln.call_path)}

汇编代码：
{''.join(asm_summary)}

分析要点：
1. 漏洞路径是否在汇编中存在
2. 是否有边界检查/安全机制（如canary、ASLR、NX）
3. 是否可构造输入触发漏洞
4. 如可触发，给出具体攻击载荷和命令

请严格按照以下JSON schema输出，不要添加任何其他文字：
{json.dumps(schema, indent=2, ensure_ascii=False)}

注意：
- exploitable: true表示可利用，false表示不可利用
- confidence: high/medium/low
- 如果exploitable为true，必须填写exploit字段
- 如果exploitable为false，必须填写reason字段
- **重要**：payload字段不要输出实际的字节序列（如大量的AAAA...），只需要用文字描述payload的结构和长度，例如"200字节的'A'填充 + 0xdeadbeef返回地址"，保持简洁"""

        response = self.llm_client.call(prompt)

        # 打印完整的原始响应用于调试
        logger.info(f"=== LLM Raw Response for {vuln.vuln_id} ===")
        logger.info(f"Response length: {len(response)} chars")
        logger.info(f"Full response:\n{response}")
        logger.info(f"=== End of Raw Response ===")

        # 提取JSON
        json_str = response
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0].strip()
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(json_str)
            return ExploitResult(**data)
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Failed to parse LLM response for {vuln.vuln_id}: {e}")
            logger.error(f"Extracted json_str length: {len(json_str)} chars")
            logger.error(f"Extracted json_str:\n{json_str}")
            # 返回失败结果而不是崩溃
            return ExploitResult(
                vuln_id=vuln.vuln_id,
                exploitable=False,
                confidence="low",
                analysis="LLM响应解析失败",
                reason=f"无法解析LLM输出: {str(e)}"
            )


# ============ 工作流协调器 ============

class WorkflowOrchestrator:
    """协调整个分析流程"""

    def __init__(self, config: Dict):
        self.config = config
        self.llm_client = LLMClient(
            api_key=config['llm']['api_key'],
            base_url=config['llm']['base_url'],
            model=config['llm']['model'],
            max_tokens=config['llm']['max_tokens'],
            temperature=config['llm']['temperature']
        )
        self.excel_parser = ExcelParser(self.llm_client)

        # 使用angr替代IDA
        objdump_path = config.get('angr', {}).get('objdump_path', 'objdump')
        self.angr_controller = AngrController(objdump_path=objdump_path)

        self.vuln_analyzer = VulnAnalyzer(self.llm_client)

    def run(self):
        """执行完整工作流"""
        logger.info("=" * 60)
        logger.info("Starting Vulnerability Analysis Workflow")
        logger.info("=" * 60)

        try:
            # 阶段1: 从Excel提取漏洞路径
            logger.info("\n[Stage 1] Extracting vulnerability paths from Excel")
            excel_file = self.config['paths']['excel_file']
            binary_file = self.config['paths']['binary_file']

            excel_content = self.excel_parser.read_excel(excel_file)
            vuln_paths = self.excel_parser.extract_vuln_paths(excel_content, binary_file)

            vuln_paths_file = "vuln_paths.json"
            with open(vuln_paths_file, 'w', encoding='utf-8') as f:
                json.dump(vuln_paths.model_dump(), f, indent=2, ensure_ascii=False)
            logger.info(f"Saved: {vuln_paths_file}")
            logger.info(f"Found {len(vuln_paths.vulnerabilities)} vulnerabilities")

            # 阶段2: angr分析提取汇编代码
            logger.info("\n[Stage 2] Extracting assembly code with angr+objdump")
            asm_code_file = "asm_code.json"
            success = self.angr_controller.analyze(binary_file, vuln_paths_file, asm_code_file)

            if not success:
                logger.error("angr analysis failed")
                return False

            if not os.path.exists(asm_code_file):
                logger.error(f"angr output file not found: {asm_code_file}")
                return False

            with open(asm_code_file, 'r', encoding='utf-8') as f:
                asm_code = AsmCode(**json.load(f))
            logger.info(f"Loaded: {asm_code_file}")

            # 阶段3: LLM分析汇编生成攻击指令
            logger.info("\n[Stage 3] Analyzing assembly and generating exploits")
            exploit_results = self.vuln_analyzer.analyze(vuln_paths, asm_code)

            exploit_result_file = "exploit_result.json"
            with open(exploit_result_file, 'w', encoding='utf-8') as f:
                json.dump(exploit_results.model_dump(), f, indent=2, ensure_ascii=False)
            logger.info(f"Saved: {exploit_result_file}")

            # 输出摘要
            logger.info("\n" + "=" * 60)
            logger.info("Analysis Summary")
            logger.info("=" * 60)
            for result in exploit_results.results:
                status = "✓ EXPLOITABLE" if result.exploitable else "✗ NOT EXPLOITABLE"
                logger.info(f"{result.vuln_id}: {status} (confidence: {result.confidence})")

            logger.info("\n" + "=" * 60)
            logger.info("Workflow completed successfully")
            logger.info("=" * 60)
            return True

        except Exception as e:
            logger.error(f"Workflow failed: {e}", exc_info=True)
            return False


# ============ 主函数 ============

def main():
    """主入口"""
    print('hello nigger!')
    # 加载配置
    config_file = "config.json"
    if not os.path.exists(config_file):
        logger.error(f"Config file not found: {config_file}")
        sys.exit(1)

    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 检查API key
    if config['llm']['api_key'] == "YOUR_DEEPSEEK_API_KEY":
        logger.error("Please set your DeepSeek API key in config.json")
        sys.exit(1)

    # 运行工作流
    orchestrator = WorkflowOrchestrator(config)
    success = orchestrator.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

#违反了卡复合管WEKAJFbE》啦啦啦开始大量是

# 啊时代就开始离婚的事的活动