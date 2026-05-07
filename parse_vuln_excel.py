import pandas as pd
import json
import sys
import os
from typing import List, Dict, Any


def parse_trigger_path(path_str: str) -> List[str]:
    """把 '[func1,func2,func3]' 解析成列表"""
    if isinstance(path_str, str):
        path_str = path_str.strip()
        if path_str.startswith('[') and path_str.endswith(']'):
            items = path_str[1:-1].split(',')
            return [item.strip() for item in items if item.strip()]
    return []


def excel_to_vuln_json(excel_path: str, output_path: str = 'vulnerabilities.json', sheet_name: str = 'Sheet1') -> Dict[
    str, Any]:
    """解析 Excel 并生成 JSON"""
    if not os.path.exists(excel_path):
        print(f"❌ 错误：文件 {excel_path} 不存在！")
        print("💡 请确保文件名为 targets.xlsx 并放在当前目录")
        return {}

    # 读取 Excel
    df = pd.read_excel(excel_path, sheet_name=sheet_name)

    # 清理列名
    df.columns = [col.strip() for col in df.columns]

    vulnerabilities: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        device = str(row.get('设备名', '')).strip()
        if not device or device.lower() in ('nan', ''):
            continue

        vuln = {
            "设备名": device,
            "二进制名": str(row.get('二进制名', '')).strip(),
            "触发路径": parse_trigger_path(str(row.get('触发路径', ''))),
            "敏感函数": str(row.get('敏感函数', '')).strip(),
            "审计结果": str(row.get('审计结果', '')).strip()
        }
        vulnerabilities.append(vuln)

    # 最终 JSON 结构
    result = {
        "vulnerabilities": vulnerabilities,
        "total_count": len(vulnerabilities),
        "source_file": os.path.basename(excel_path)
    }

    # 写入 JSON 文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"✅ 成功！已生成 {output_path}")
    print(f"   共处理 {len(vulnerabilities)} 条漏洞记录")
    print(f"   来源文件：{os.path.basename(excel_path)}")
    return result


# 主程序入口
if __name__ == "__main__":
    # 默认使用 targets.xlsx，支持命令行指定其他文件
    excel_file = sys.argv[1] if len(sys.argv) > 1 else "targets.xlsx"
    excel_to_vuln_json(excel_file)