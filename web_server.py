#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞分析系统 - Web 控制台后端
提供 Stage 1-3 的 Web API 接口
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import subprocess
import os
import json
from pathlib import Path

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# 项目根目录
PROJECT_ROOT = Path(__file__).parent

# Stage 脚本映射
STAGE_SCRIPTS = {
    1: "stage1_parse_excel.py",
    2: "stage2_ida_controller.py",
}

STAGE3_SUBSTAGES = {
    1: ["stage3_vuln_analyzer.py", "--stage", "1"],
    2: ["stage3_vuln_analyzer.py", "--stage", "2"],
}


def run_script(script_args, cwd=None):
    """运行 Python 脚本并返回结果"""
    if cwd is None:
        cwd = PROJECT_ROOT

    try:
        result = subprocess.run(
            ["python", *script_args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=300  # 5分钟超时
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "脚本执行超时（超过 5 分钟）",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "returncode": -1
        }


@app.route('/')
def index():
    """主页"""
    return send_from_directory('.', 'index.html')


@app.route('/api/run-stage/<int:stage_num>', methods=['POST'])
def run_stage(stage_num):
    """运行指定 Stage"""
    if stage_num not in STAGE_SCRIPTS:
        return jsonify({
            "success": False,
            "error": f"不支持的 Stage: {stage_num}"
        }), 400

    script_name = STAGE_SCRIPTS[stage_num]
    script_path = PROJECT_ROOT / script_name

    if not script_path.exists():
        return jsonify({
            "success": False,
            "error": f"脚本不存在: {script_name}"
        }), 404

    # 运行脚本（各 Stage 需要不同参数）
    if stage_num == 1:
        script_args = [script_name, "--input", "targets.xlsx", "--output", ".", "--mode", "compact"]
    elif stage_num == 2:
        script_args = [script_name, "httpd", "vuln_paths.json"]
    else:
        script_args = [script_name]
    result = run_script(script_args)

    if result["success"]:
        # 根据 Stage 确定输出文件
        output_files = {
            1: "vuln_paths.json",
            2: "asm_code.json",
        }
        return jsonify({
            "success": True,
            "output_file": output_files.get(stage_num, ""),
            "stdout": result["stdout"][-500:] if result["stdout"] else ""  # 只返回最后 500 字符
        })
    else:
        return jsonify({
            "success": False,
            "error": result.get("error", result.get("stderr", "未知错误"))
        }), 500


@app.route('/api/run-stage3/<int:substage>', methods=['POST'])
def run_stage3_substage(substage):
    """运行 Stage 3 子阶段"""
    if substage not in STAGE3_SUBSTAGES:
        return jsonify({
            "success": False,
            "error": f"不支持的 Stage 3 子阶段: {substage}"
        }), 400

    script_args = STAGE3_SUBSTAGES[substage]
    result = run_script(script_args)

    if result["success"]:
        output_files = {
            1: "enriched_analysis.json + stage4_targets.json",
            2: "exploit_result.json + exploit_result_report.md",
        }
        return jsonify({
            "success": True,
            "output_file": output_files.get(substage, ""),
            "stdout": result["stdout"][-500:] if result["stdout"] else ""
        })
    else:
        return jsonify({
            "success": False,
            "error": result.get("error", result.get("stderr", "未知错误"))
        }), 500


@app.route('/api/results/<filename>')
def get_result_file(filename):
    """获取结果文件内容"""
    allowed_files = [
        "exploit_result.json",
        "stage4_targets.json",
        "enriched_analysis.json",
        "vuln_paths.json",
        "asm_code.json",
    ]

    if filename not in allowed_files:
        return jsonify({"error": "不允许访问该文件"}), 403

    file_path = PROJECT_ROOT / filename

    if not file_path.exists():
        return jsonify({"error": "文件不存在"}), 404

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except json.JSONDecodeError:
        return jsonify({"error": "JSON 解析失败"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/results/exploit_result_report.md')
def get_report():
    """获取 Markdown 报告"""
    file_path = PROJECT_ROOT / "exploit_result_report.md"

    if not file_path.exists():
        return "报告文件不存在", 404

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return str(e), 500


if __name__ == '__main__':
    print("=" * 50)
    print("漏洞分析系统 - Web 控制台")
    print("=" * 50)
    print("访问地址: http://localhost:5000")
    print("按 Ctrl+C 停止服务器")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
