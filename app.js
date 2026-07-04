// 日志输出
function log(message, type = 'info') {
    const logOutput = document.getElementById('log-output');
    const timestamp = new Date().toLocaleTimeString('zh-CN');
    const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
    logOutput.textContent += `[${timestamp}] ${prefix} ${message}\n`;
    logOutput.scrollTop = logOutput.scrollHeight;
}

function clearLogs() {
    document.getElementById('log-output').textContent = '';
}

// 更新阶段状态
function updateStageStatus(stageNum, status, message) {
    const statusEl = document.getElementById(`stage${stageNum}-status`);
    statusEl.className = `stage-status ${status}`;
    statusEl.textContent = message;
    statusEl.style.display = 'block';
}

// 运行单个 Stage
async function runStage(stageNum) {
    const card = document.getElementById(`stage${stageNum}-card`);
    card.style.borderColor = '#3b82f6';

    updateStageStatus(stageNum, 'running', '⏳ 运行中...');
    log(`开始运行 Stage ${stageNum}...`);

    try {
        // 这里调用后端 API（需要你实现后端）
        const response = await fetch(`/api/run-stage/${stageNum}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        if (result.success) {
            updateStageStatus(stageNum, 'success', `✅ 完成: ${result.output_file || ''}`);
            log(`Stage ${stageNum} 运行成功`, 'success');
        } else {
            throw new Error(result.error || '未知错误');
        }
    } catch (error) {
        updateStageStatus(stageNum, 'error', `❌ 失败: ${error.message}`);
        log(`Stage ${stageNum} 运行失败: ${error.message}`, 'error');
    }

    card.style.borderColor = '#475569';
}

// 运行 Stage 3 子阶段
async function runStage3Substage(substage) {
    const stageNum = 3;
    const statusEl = document.getElementById('stage3-status');

    statusEl.className = 'stage-status running';
    statusEl.textContent = `⏳ Stage 3.${substage} 运行中...`;
    statusEl.style.display = 'block';

    log(`开始运行 Stage 3.${substage}...`);

    try {
        const response = await fetch(`/api/run-stage3/${substage}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        if (result.success) {
            statusEl.className = 'stage-status success';
            statusEl.textContent = `✅ Stage 3.${substage} 完成`;
            log(`Stage 3.${substage} 运行成功`, 'success');
        } else {
            throw new Error(result.error || '未知错误');
        }
    } catch (error) {
        statusEl.className = 'stage-status error';
        statusEl.textContent = `❌ Stage 3.${substage} 失败: ${error.message}`;
        log(`Stage 3.${substage} 运行失败: ${error.message}`, 'error');
    }
}

// 加载 JSON 结果文件
async function loadResult(filename) {
    const outputId = filename === 'stage4_targets.json' ? 'targets-output' : 'json-output';
    const outputEl = document.getElementById(outputId);

    outputEl.textContent = '加载中...';

    try {
        const response = await fetch(`/api/results/${filename}`);
        if (!response.ok) {
            throw new Error(`无法加载 ${filename}`);
        }

        const data = await response.json();
        outputEl.textContent = JSON.stringify(data, null, 2);
        log(`已加载 ${filename}`, 'success');
    } catch (error) {
        outputEl.textContent = `加载失败: ${error.message}`;
        log(`加载 ${filename} 失败: ${error.message}`, 'error');
    }
}

// 加载 Markdown 报告
async function loadReport() {
    const outputEl = document.getElementById('report-output');
    outputEl.innerHTML = '<p style="color:#94a3b8">加载中...</p>';

    try {
        const response = await fetch('/api/results/exploit_result_report.md');
        if (!response.ok) {
            throw new Error('无法加载报告');
        }

        const markdown = await response.text();
        // 简单渲染 Markdown（可后续集成 marked.js）
        outputEl.innerHTML = renderSimpleMarkdown(markdown);
        log('已加载 exploit_result_report.md', 'success');
    } catch (error) {
        outputEl.innerHTML = `<p style="color:#f87171">加载失败: ${error.message}</p>`;
        log(`加载报告失败: ${error.message}`, 'error');
    }
}

// 简单 Markdown 渲染
function renderSimpleMarkdown(md) {
    return md
        .replace(/^### (.*$)/gm, '<h3>$1</h3>')
        .replace(/^## (.*$)/gm, '<h2>$1</h2>')
        .replace(/^# (.*$)/gm, '<h1>$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
}

// 切换 Tab
function showTab(tabId) {
    // 隐藏所有 tab
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // 显示选中 tab
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');
}

// 上传文件
async function uploadFile(type) {
    const inputId = type === 'excel' ? 'excel-input' : 'bin-input';
    const statusId = type === 'excel' ? 'excel-status' : 'bin-status';
    const input = document.getElementById(inputId);
    const statusEl = document.getElementById(statusId);

    if (!input.files || input.files.length === 0) {
        return;
    }

    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    statusEl.textContent = '⏳ 上传中...';
    statusEl.className = 'upload-status';
    statusEl.style.display = 'inline';

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            statusEl.textContent = `✅ 已保存为 ${result.filename}`;
            statusEl.className = 'upload-status success';
            log(`${type === 'excel' ? 'Excel' : '二进制'}文件上传成功: ${result.filename}`, 'success');
        } else {
            throw new Error(result.error || '上传失败');
        }
    } catch (error) {
        statusEl.textContent = `❌ ${error.message}`;
        statusEl.className = 'upload-status error';
        log(`文件上传失败: ${error.message}`, 'error');
    }

    // 清空 input，允许重复选择同一文件
    input.value = '';
}

// 页面加载时自动检查文件状态
window.addEventListener('load', () => {
    log('漏洞分析系统 Web 控制台已加载');
    log('提示: 先上传 Excel 和二进制文件，再运行各 Stage');
});
