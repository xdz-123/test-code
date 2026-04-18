#!/usr/bin/env python3
"""
漏洞分析主控脚本
使用LLM从Excel提取漏洞信息，调用IDA分析二进制，再用LLM分析汇编生成攻击指令
"""
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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
                logger.info(f"Calling LLM API (attempt {attempt + 1}/{max_retries})")
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature
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
            for inst in func.assembly[:50]:  # 限制指令数量
                asm_summary.append(f"  {inst.address}: {inst.instruction}")
            if len(func.assembly) > 50:
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
- 如果exploitable为false，必须填写reason字段"""

        response = self.llm_client.call(prompt)

        # 提取JSON
        json_str = response
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0].strip()
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0].strip()

        data = json.loads(json_str)
        return ExploitResult(**data)


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
        self.ida_controller = IDAController(
            ida_path=config['ida']['path'],
            timeout=config['ida']['timeout']
        )
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

            # 阶段2: IDA分析提取汇编代码
            logger.info("\n[Stage 2] Extracting assembly code with IDA")
            script_path = os.path.abspath("ida_extract.py")
            success = self.ida_controller.analyze(binary_file, script_path)

            if not success:
                logger.error("IDA analysis failed")
                return False

            asm_code_file = "asm_code.json"
            if not os.path.exists(asm_code_file):
                logger.error(f"IDA output file not found: {asm_code_file}")
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
