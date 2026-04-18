#!/usr/bin/env python3
"""
IDA Python脚本 - 从二进制文件中提取汇编代码
由IDA Pro headless模式调用
"""
import idaapi
import idc
import idautils
import json
import sys
import os


def wait_for_analysis():
    """等待IDA自动分析完成"""
    print("[IDA] Waiting for auto-analysis to complete...")
    idaapi.auto_wait()
    print("[IDA] Analysis complete")


def get_function_by_name(func_name):
    """根据函数名获取函数地址"""
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if name == func_name:
            return func_ea
    return None


def get_function_by_address(address):
    """根据地址获取函数"""
    if isinstance(address, str):
        if address.startswith("0x") or address.startswith("0X"):
            address = int(address, 16)
        else:
            address = int(address)
    return idaapi.get_func(address)


def extract_assembly(func_ea):
    """提取函数的汇编代码"""
    func = idaapi.get_func(func_ea)
    if not func:
        return None

    assembly = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        # 获取反汇编指令
        disasm = idc.generate_disasm_line(head, 0)

        # 获取字节码
        item_size = idc.get_item_size(head)
        raw_bytes = idc.get_bytes(head, item_size)
        if raw_bytes:
            bytes_hex = " ".join(f"{b:02x}" for b in raw_bytes)
        else:
            bytes_hex = ""

        assembly.append({
            "address": f"0x{head:08x}",
            "instruction": disasm,
            "bytes": bytes_hex
        })

    return assembly


def get_xrefs_to(func_ea):
    """获取对函数的交叉引用"""
    xrefs = []
    for xref in idautils.XrefsTo(func_ea):
        xrefs.append(f"0x{xref.frm:08x}")
    return xrefs


def process_vulnerabilities(vuln_paths_file, output_file):
    """处理漏洞路径并提取汇编代码"""
    # 读取vuln_paths.json
    if not os.path.exists(vuln_paths_file):
        print(f"[ERROR] File not found: {vuln_paths_file}")
        return False

    with open(vuln_paths_file, 'r', encoding='utf-8') as f:
        vuln_data = json.load(f)

    # 获取架构信息
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        arch = "x86_64" if info.procname == "metapc" else "ARM64"
    else:
        if info.procname == "metapc":
            arch = "x86"
        elif info.procname == "ARM":
            arch = "ARM"
        else:
            arch = info.procname

    # 构建输出数据
    output_data = {
        "binary_file": vuln_data.get("binary_file", ""),
        "architecture": arch,
        "vulnerabilities": []
    }

    # 处理每个漏洞
    for vuln in vuln_data.get("vulnerabilities", []):
        vuln_id = vuln.get("vuln_id", "UNKNOWN")
        print(f"\n[IDA] Processing vulnerability: {vuln_id}")

        vuln_result = {
            "vuln_id": vuln_id,
            "functions": []
        }

        # 提取调用路径中的每个函数
        for path_item in vuln.get("call_path", []):
            func_name = path_item.get("function")
            func_addr = path_item.get("address")

            # 尝试通过函数名查找
            func_ea = None
            if func_name:
                func_ea = get_function_by_name(func_name)
                print(f"[IDA] Looking for function: {func_name}")

            # 如果没找到，尝试通过地址查找
            if not func_ea and func_addr:
                print(f"[IDA] Trying address: {func_addr}")
                func = get_function_by_address(func_addr)
                if func:
                    func_ea = func.start_ea

            if not func_ea:
                print(f"[WARNING] Function not found: {func_name} @ {func_addr}")
                continue

            # 提取汇编代码
            print(f"[IDA] Extracting assembly from 0x{func_ea:08x}")
            assembly = extract_assembly(func_ea)
            if not assembly:
                print(f"[WARNING] Failed to extract assembly for {func_name}")
                continue

            # 获取交叉引用
            xrefs = get_xrefs_to(func_ea)

            func_result = {
                "name": func_name or idc.get_func_name(func_ea),
                "start_address": f"0x{func_ea:08x}",
                "assembly": assembly,
                "xrefs_to": xrefs
            }

            vuln_result["functions"].append(func_result)
            print(f"[IDA] Extracted {len(assembly)} instructions")

        output_data["vulnerabilities"].append(vuln_result)

    # 写入输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\n[IDA] Output written to: {output_file}")
    return True


def main():
    """主函数"""
    print("[IDA] Script started")

    # 等待分析完成
    wait_for_analysis()

    # 获取当前IDB所在目录
    idb_path = idc.get_idb_path()
    work_dir = os.path.dirname(idb_path)

    vuln_paths_file = os.path.join(work_dir, "vuln_paths.json")
    #output_file = os.path.join(work_dir, "asm_code.json")
    output_file = r"C:\Users\xudiz\Desktop\test-code\asm_code.json"

    print(f"[IDA] Working directory: {work_dir}")
    print(f"[IDA] Input file: {vuln_paths_file}")
    print(f"[IDA] Output file: {output_file}")

    # 处理漏洞
    success = process_vulnerabilities(vuln_paths_file, output_file)

    if success:
        print("[IDA] Script completed successfully")
        idc.qexit(0)
    else:
        print("[IDA] Script failed")
        idc.qexit(1)


if __name__ == "__main__":
    main()
