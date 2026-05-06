import streamlit as st
import json
import os
import subprocess
import time
import sys

st.set_page_config(page_title="漏洞分析系统 | VulnAnalyzer", page_icon="🛡️", layout="wide")

st.markdown(
    '<h1 style="font-size: 2.8rem; background: linear-gradient(90deg, #00ff9d, #00b8ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🛡️ 漏洞分析系统</h1>',
    unsafe_allow_html=True)
st.caption("Grok LLM + angr 智能二进制漏洞分析平台")

# ====================== 侧边栏 ======================
with st.sidebar:
    st.header("⚙️ 系统配置")
    config_path = "config.json"
    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

    api_key = st.text_input("Grok API Key (xAI)",
                            value=config.get("llm", {}).get("api_key", ""),
                            type="password")
    model = st.selectbox("Grok 模型",
                         ["grok-4.20", "grok-4.20-reasoning", "grok-4-1-fast-reasoning"],
                         index=0)

    excel_file = st.text_input("Excel 文件", value=config.get("paths", {}).get("excel_file", "targets.xlsx"))
    binary_file = st.text_input("二进制文件", value=config.get("paths", {}).get("binary_file", "httpd"))

    if st.button("💾 保存 Grok 配置", type="primary", use_container_width=True):
        config["llm"] = {
            "api_key": api_key,
            "model": model,
            "base_url": "https://api.x.ai/v1",
            "max_tokens": 8192,
            "temperature": 0.1
        }
        config["paths"] = {"excel_file": excel_file, "binary_file": binary_file}
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        st.success("✅ 配置已保存")
        st.rerun()

# ====================== 主界面 ======================
tab_overview, tab_results, tab_raw, tab_log = st.tabs(["📊 仪表盘", "🔍 分析结果", "📜 原始数据", "📖 运行日志"])

result_file = "exploit_result.json"
log_file = "vuln_analyzer.log"

# ====================== TAB 1: 仪表盘（已修复 + 可折叠） ======================
with tab_overview:
    # === 新增：可折叠的文件状态检查（满足你的折叠需求）===
    with st.expander("📁 文件状态检查（点击折叠/展开）", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            if os.path.exists(excel_file):
                st.success(f"✅ Excel: {excel_file}")
            else:
                st.error(f"❌ Excel: {excel_file}")

        with col2:
            if os.path.exists(binary_file):
                st.success(f"✅ 二进制: {binary_file}")
            else:
                st.error(f"❌ 二进制: {binary_file}")

    if st.button("🔥 开始完整漏洞分析（Grok）", type="primary", use_container_width=True):
        if not os.path.exists(excel_file) or not os.path.exists(binary_file):
            st.error("❌ 请确保两个输入文件都存在！")
        else:
            for f in [log_file, result_file]:
                if os.path.exists(f):
                    os.remove(f)

            st.session_state.analysis_running = True
            st.session_state.start_time = time.time()
            st.session_state.process = subprocess.Popen(
                [sys.executable, "-u", "vuln_analyzer.py"],
                cwd=os.getcwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            st.success("🚀 分析已启动！")
            st.rerun()

    # 实时监控部分（保持不变）
    if st.session_state.get("analysis_running", False):
        with st.status("🧪 Grok 正在分析中（5-15分钟）...", expanded=True) as status:
            log_placeholder = st.empty()
            time_placeholder = st.empty()
            output_buffer = ""

            while st.session_state.analysis_running:
                for line in iter(st.session_state.process.stdout.readline, ''):
                    if line:
                        output_buffer += line
                        log_placeholder.code(output_buffer[-2000:], language="bash")

                elapsed = int(time.time() - st.session_state.start_time)
                time_placeholder.info(f"⏱️ 已运行 {elapsed} 秒")

                if st.session_state.process.poll() is not None:
                    st.session_state.analysis_running = False
                    if os.path.exists(result_file):
                        status.update(label="✅ 分析完成！", state="complete")
                        st.success("🎉 完成！请查看【分析结果】")
                    else:
                        status.update(label="⚠️ 异常结束", state="error")
                    st.rerun()
                time.sleep(0.3)
                st.rerun()

# ====================== 其他 TAB（不变） ======================
with tab_results:
    if os.path.exists(result_file):
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        results = data.get("results", [])
        st.info("✅ 分析结果已生成（详细内容见下方）")
    else:
        st.info("💡 请先点击上方按钮开始分析")

with tab_raw:
    for f in ["vuln_paths.json", "asm_code.json", "exploit_result.json"]:
        if os.path.exists(f):
            with st.expander(f"📄 {f}"):
                st.json(json.load(open(f, "r", encoding="utf-8")))

with tab_log:
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            st.text_area("完整日志", f.read()[-15000:], height=600)
        st.download_button("📥 下载日志", open(log_file, "rb").read(), log_file)

st.caption("✅ 已修复 DeltaGenerator 调试信息 + 文件状态可折叠 | Powered by Grok + Streamlit")