# qilingfw/utils.py
import os
import json

def ensure_tmp_dir(rootfs: str):
    tmp_path = os.path.join(rootfs, 'tmp')
    if os.path.islink(tmp_path) or not os.path.isdir(tmp_path):
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        os.makedirs(tmp_path, exist_ok=True)

def load_vuln_targets(json_input):
    """支持单个文件路径或文件路径列表"""
    if isinstance(json_input, str):
        json_input = [json_input]
    all_targets = []
    for f in json_input:
        with open(f, 'r') as fp:
            data = json.load(fp)
            all_targets.extend(data)
    return all_targets
