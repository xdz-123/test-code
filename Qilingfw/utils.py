# qilingfw/utils.py
import os
import json

def ensure_tmp_dir(rootfs: str):
    """确保虚拟根文件系统中的 /tmp 目录真实存在（修复符号链接问题）"""
    tmp_path = os.path.join(rootfs, 'tmp')
    if os.path.islink(tmp_path) or not os.path.isdir(tmp_path):
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        os.makedirs(tmp_path, exist_ok=True)

def load_vuln_targets(json_file: str) -> list:
    """加载漏洞目标 JSON 文件"""
    with open(json_file, 'r') as f:
        return json.load(f)