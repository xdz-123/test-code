import pandas as pd
import json
import sys
import os
import argparse
from typing import List, Dict, Any


def parse_trigger_path(path_str: str) -> List[str]:
    """解析 [func1,func2,func3] 为列表"""
    if isinstance(path_str, str):
        path_str = path_str.strip()
        if path_str.startswith('[') and path_str.endswith(']'):
            items = path_str[1:-1].split(',')
            return [item.strip() for item in items if item.strip()]
    return []


def infer_vulnerability_type(sensitive_func: str, audit_result: str) -> str:
    """简单推断漏洞类型（LLM 分析时非常有用）"""
    sensitive = sensitive_func.lower()
    result = audit_result.lower() if isinstance(audit_result, str) else ""
    if 'strcpy' in sensitive or 'buffer' in result or '溢出' in result:
        return "buffer_overflow"
    if 'sscanf' in sensitive or '格式字符串' in result:
        return "format_string"
    if 'sprintf' in sensitive:
        return "format_string_or_buffer_overflow"
    if 'password' in result or 'mac' in result:
        return "input_validation"
    return "other"


def create_short_summary(audit_text: str, max_len: int = 280) -> str:
    """生成简短摘要，极大减少 token 占用"""
    if not isinstance(audit_text, str) or not audit_text.strip():
        return "无详细描述"
    text = audit_text.strip()
    if len(text) <= max_len:
        return text
    # 优先保留第一段（中文通常以句号分段）
    sentences = text.split('。')
    summary = sentences[0]
    for s in sentences[1:]:
        if len(summary) + len(s) + 1 > max_len:
            break
        summary += '。' + s
    return summary + '...' if len(text) > len(summary) else summary


def excel_to_vuln_json(excel_path: str, output_dir: str = '.', mode: str = 'compact'):
    """主解析函数"""
    if not os.path.exists(excel_path):
        print(f"❌ 文件不存在: {excel_path}")
        print("💡 请将 Excel 文件重命名为 targets.xlsx 并放在当前目录")
        return

    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_excel(excel_path, sheet_name='Sheet1')
    df.columns = [col.strip() for col in df.columns]

    vulnerabilities: List[Dict[str, Any]] = []

    for idx, row in df.iterrows():
        device = str(row.get('设备名', '')).strip()
        if not device or device.lower() in ('nan', ''):
            continue

        audit_result = str(row.get('审计结果', '')).strip()

        vuln = {
            "vuln_id": idx + 1,
            "device_name": device,
            "binary_name": str(row.get('二进制名', '')).strip(),
            "trigger_path": parse_trigger_path(str(row.get('触发路径', ''))),
            "sensitive_function": str(row.get('敏感函数', '')).strip(),
            "vulnerability_type": infer_vulnerability_type(
                str(row.get('敏感函数', '')), audit_result
            ),
            "full_description": audit_result,  # 完整版保留
            "short_summary": create_short_summary(audit_result),  # compact 模式使用
            "affected_parameter": ""  # 可后续手动补充或从描述中提取
        }
        vulnerabilities.append(vuln)

    # 公共元数据
    metadata = {
        "total_vulns": len(vulnerabilities),
        "source_file": os.path.basename(excel_path),
        "generated_at": "auto"
    }

    # 生成两种格式
    full_data = {"metadata": metadata, "vulnerabilities": vulnerabilities}
    compact_data = {"metadata": metadata, "vulnerabilities": [
        {k: v for k, v in v.items() if k != "full_description"} for v in vulnerabilities
    ]}

    # 写入文件
    full_path = os.path.join(output_dir, 'vulnerabilities_full.json')
    compact_path = os.path.join(output_dir, 'vulnerabilities_compact.json')

    with open(full_path, 'w', encoding='utf-8') as f:
        json.dump(full_data, f, ensure_ascii=False, indent=2)

    with open(compact_path, 'w', encoding='utf-8') as f:
        json.dump(compact_data, f, ensure_ascii=False, indent=2)

    print(f"\n🎉 处理完成！共 {len(vulnerabilities)} 条漏洞")
    print(f"   📁 完整版  → {full_path}   （详细描述，token 较多）")
    print(f"   📁 精简版  → {compact_path} （推荐给 LLM，token 大幅减少）")
    print(f"   💡 建议：直接使用 compact 版本喂给 LLM，可节省 60-80% token")

    # 推荐的 LLM 提示词模板（直接复制使用）
    print("\n🔥 推荐 LLM 提示词模板（复制后直接用）：")
    print("=" * 60)
    print("""你是一位资深 IoT 固件安全研究员。
以下是设备漏洞路径的结构化 JSON 数据：

<JSON>
{paste your compact json here}
</JSON>

请按以下要求分析：
1. 按 vulnerability_type 分组统计漏洞数量和严重程度
2. 列出最严重的 Top 3 漏洞（给出 vuln_id、设备、触发路径、root cause）
3. 为每个漏洞给出修复建议（优先使用安全函数替代）
4. 输出 Markdown 格式报告""")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Excel → LLM 友好 JSON 转换工具")
    parser.add_argument('--input', default='targets.xlsx', help='输入 Excel 文件路径')
    parser.add_argument('--output', default='.', help='输出目录')
    parser.add_argument('--mode', choices=['full', 'compact'], default='compact',
                        help='输出模式：full=完整版，compact=精简版（默认）')
    args = parser.parse_args()

    excel_to_vuln_json(args.input, args.output, args.mode)