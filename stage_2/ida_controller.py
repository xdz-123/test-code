#!/usr/bin/env python3
import subprocess
import os
import sys

def run_ida(target_binary, input_json, output_json, ida_path=r"D:\IDA Pro 9.3\idat.exe"):
    env = os.environ.copy()
    env["ASM_INPUT_FILE"]  = os.path.abspath(input_json)
    env["ASM_OUTPUT_FILE"] = os.path.abspath(output_json)
    env["BINARY_NAME"]     = os.path.basename(target_binary)

    cmd = [
        ida_path,
        "-A",                           # 自动模式
        "-B",                           # 禁止初始自动分析（加速，可按需保留或删除）
        f"-S{os.path.abspath('ida_extract.py')}",  # 执行插件
        target_binary
    ]
    print("[*] 执行命令:", ' '.join(cmd))
    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        print(f"[!] IDA 返回错误码: {result.returncode}")
    else:
        print(f"[+] asm_code.json 已生成: {output_json}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python ida_controller.py <httpd路径> <vuln_paths.json>")
        sys.exit(1)
    target = sys.argv[1]
    input_j = sys.argv[2]
    output_j = "asm_code.json"
    run_ida(target, input_j, output_j)