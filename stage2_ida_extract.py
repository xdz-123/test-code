#!/usr/bin/env python3
import idaapi
import idc
import idautils
import ida_auto          # 必须导入，用于 auto_wait()
import json
import os

# ---------- 从环境变量获取输入/输出路径（绝对路径）----------
INPUT_JSON  = os.environ.get('ASM_INPUT_FILE',  '/abs/path/to/vuln_paths.json')
OUTPUT_JSON = os.environ.get('ASM_OUTPUT_FILE', '/abs/path/to/asm_code.json')
BINARY_NAME = os.environ.get('BINARY_NAME', 'httpd')

# ---------- 危险函数列表（可根据需要扩充）----------
DANGEROUS_FUNCS = {'strcpy', 'strcat', 'sprintf', 'system', 'execve', 'memcpy'}

# ---------- 等待自动分析完成 ----------
ida_auto.auto_wait()

# ---------- 工具函数：根据地址或函数名定位函数 ----------
def get_function(addr_or_name):
    """
    输入可以是地址字符串（0x...）或函数名。
    如果给出地址，直接使用；否则按名称搜索符号。
    """
    if addr_or_name.startswith('0x') or addr_or_name.startswith('0X'):
        ea = int(addr_or_name, 16)
        return idaapi.get_func(ea)
    else:
        ea = idc.get_name_ea_simple(addr_or_name)
        if ea == idc.BADADDR:
            return None
        return idaapi.get_func(ea)

# ---------- 提取关键汇编（不超过40行）----------
def extract_critical_asm(func_ea, trigger_address=None):
    """
    从函数中提取最多40行汇编。
    如果函数总行数<=40，则全取；否则，尽量围绕trigger_address取关键块。
    """
    func = idaapi.get_func(func_ea)
    if not func:
        return []

    all_heads = list(idautils.Heads(func.start_ea, func.end_ea))
    code_lines = []
    for head in all_heads:
        if idaapi.is_code(idaapi.get_flags(head)):
            disasm = idc.GetDisasm(head)
            code_lines.append({
                "address": f"0x{head:X}",
                "instruction": disasm,
                "bytes": idaapi.get_bytes(head, idaapi.get_item_size(head)).hex().upper()
            })

    if len(code_lines) <= 40:
        return code_lines

    # 截取关键部分：以 trigger_address 所在的块为中心，前后各补一些行
    if trigger_address:
        try:
            center = int(trigger_address, 16)
        except ValueError:
            center = func.start_ea
    else:
        center = func.start_ea  # 默认取函数开头

    # 找到 center 在 code_lines 中的索引
    idx = 0
    for i, line in enumerate(code_lines):
        if int(line['address'], 16) <= center:
            idx = i
    start = max(0, idx - 20)
    end = min(len(code_lines), idx + 20)
    return code_lines[start:end]

# ---------- 获取函数内对危险函数的交叉引用 ----------
def get_dangerous_xrefs(func_ea):
    func = idaapi.get_func(func_ea)
    if not func:
        return []
    xrefs = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idaapi.is_code(idaapi.get_flags(head)):
            # 检查指令是否调用其他函数
            for xref in idautils.XrefsFrom(head, idaapi.XREF_FAR):
                callee_name = idc.get_func_name(xref.to)
                if callee_name in DANGEROUS_FUNCS:
                    xrefs.add(callee_name)
    return list(xrefs)


# ---------- 提取函数内的所有外部调用（带目标地址） ----------
def extract_external_calls(func_ea):
    """
    提取函数内所有 BL/BLX 调用指令，返回:
    [{"call_addr": 0x..., "target_addr": 0x..., "target_name": "..."}, ...]
    """
    func = idaapi.get_func(func_ea)
    if not func:
        return []

    calls = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if not idaapi.is_code(idaapi.get_flags(head)):
            continue
        mnem = idc.print_insn_mnem(head)
        if mnem not in ("BL", "BLX"):
            continue
        # 获取操作数（被调用函数）
        for xref in idautils.XrefsFrom(head, idaapi.XREF_FAR):
            if xref.type in (idaapi.fl_CN, idaapi.fl_CF):  # 代码近程/远程调用
                target_ea = xref.to
                target_name = idc.get_func_name(target_ea) or f"sub_{target_ea:X}"
                calls.append({
                    "call_addr": head,
                    "target_addr": target_ea,
                    "target_name": target_name
                })
                break  # 一个 BL 通常只有一个目标
    return calls

# ---------- 主处理逻辑 ----------
with open(INPUT_JSON, 'r', encoding='utf-8') as f:
    vuln_data = json.load(f)

output = {
    "binary_file": BINARY_NAME,
    "architecture": "ARM-32",  # 或从 idaapi.get_inf_structure() 动态获取
    "vulnerabilities": []
}

for vuln in vuln_data["vulnerabilities"]:
    vuln_entry = {"vuln_id": vuln["vuln_id"], "functions": []}
    for func_info in vuln["call_path"]:
        # 优先使用非空的 address，否则使用 function 名称
        addr_or_name = func_info.get("address") or func_info["function"]
        func = get_function(addr_or_name)
        if not func:
            # 若找不到函数，跳过并继续下一个
            continue

        trigger_addr = func_info.get("address")  # 可能为空
        asm_lines = extract_critical_asm(func.start_ea, trigger_addr)
        xrefs = get_dangerous_xrefs(func.start_ea)
        ext_calls = extract_external_calls(func.start_ea)
        vuln_entry["functions"].append({
            "name": func_info["function"],
            "start_address": f"0x{func.start_ea:X}",
            "assembly": asm_lines,
            "xrefs_to": xrefs,
            "external_calls": ext_calls
        })
    output["vulnerabilities"].append(vuln_entry)

# 写入输出文件
with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2)

# 退出 IDA
idc.qexit(0)