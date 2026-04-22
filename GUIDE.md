# 漏洞分析系统 - 运行指南

本指南面向所有用户，包括初学者。按照步骤操作即可运行程序。

---

## 前置要求

- **Python 3.8+**（推荐3.11）
- **Windows/Linux/macOS** 均可
- **网络连接**（调用LLM API）

---

## 第一步：安装Python依赖

### 1.1 打开命令行

**Windows**：
- 按 `Win + R`，输入 `cmd`，回车
- 或在开始菜单搜索"命令提示符"

**macOS/Linux**：
- 打开终端（Terminal）

### 1.2 进入项目目录

```bash
cd C:\Users\xudiz\Desktop\test-code
```

> 注意：把路径改成你实际存放代码的位置

### 1.3 安装依赖包

```bash
pip install -r requirements.txt
```

如果提示 `pip` 不是命令，尝试：
```bash
python -m pip install -r requirements.txt
```

**安装的库**：
- `openai` — 调用LLM API（支持DeepSeek、OpenAI等）
- `openpyxl` — 读取Excel文件
- `pydantic` — JSON数据验证
- `angr` — 二进制分析框架
- `python-dotenv` — 环境变量支持

> angr安装可能需要几分钟，请耐心等待

---

## 第二步：配置API密钥

### 2.1 获取DeepSeek API Key（默认）

1. 访问 [platform.deepseek.com](https://platform.deepseek.com)
2. 注册/登录账号
3. 进入 API Keys 页面
4. 点击"创建新Key"，复制生成的key（格式：`sk-xxxxxx`）

### 2.2 填入config.json

打开项目目录下的 `config.json` 文件，找到这一行：

```json
"api_key": "sk-d1493f47c2df41e086b85a37ea6b472c",
```

把引号里的内容替换成你自己的API key。

---

## 第三步：准备输入文件

确保项目目录下有以下文件：

- `targets.xlsx` — 漏洞路径信息（Excel格式）
- `httpd`（或其他二进制文件） — 待分析的可执行文件

如果要分析其他文件，修改 `config.json` 中的：

```json
"paths": {
    "excel_file": "你的Excel文件名.xlsx",
    "binary_file": "你的二进制文件名"
}
```

---

## 第四步：运行程序

在项目目录下执行：

```bash
python vuln_analyzer.py
```

**运行过程**（大约需要5-15分钟）：
1. Stage 1：LLM读取Excel，提取漏洞路径 → 生成 `vuln_paths.json`
2. Stage 2：angr分析二进制，提取汇编代码 → 生成 `asm_code.json`
3. Stage 3：LLM分析汇编，判断可利用性 → 生成 `exploit_result.json`

---

## 第五步：查看结果

运行完成后，检查以下文件：

| 文件 | 说明 |
|------|------|
| `vuln_paths.json` | LLM从Excel提取的结构化漏洞路径 |
| `asm_code.json` | angr提取的汇编代码（每个漏洞相关函数） |
| `exploit_result.json` | **最终结果**：可利用性判断和攻击方法 |
| `vuln_analyzer.log` | 完整运行日志（出错时查看） |

打开 `exploit_result.json`，每个漏洞的分析结果包含：
- `exploitable`: true/false（是否可利用）
- `confidence`: high/medium/low（置信度）
- `analysis`: 详细分析过程
- `exploit`: 攻击方法、payload描述、命令
- `reason`: 如果不可利用，说明原因

---

## 常见问题

### Q1: 提示"Config file not found: config.json"

**原因**：不在项目目录下运行

**解决**：
```bash
cd C:\Users\xudiz\Desktop\test-code
python vuln_analyzer.py
```

### Q2: 提示"No module named 'angr'"

**原因**：依赖未安装

**解决**：
```bash
pip install -r requirements.txt
```

### Q3: 程序运行很久没反应

**原因**：angr分析大型二进制或LLM API响应慢

**解决**：
- 查看 `vuln_analyzer.log` 确认当前进度
- 等待5-15分钟（正常现象）
- 如果超过30分钟，按 `Ctrl+C` 终止，检查网络和API配额

### Q4: Stage 3报错"Failed to parse LLM response"

**原因**：LLM返回格式不符合预期

**解决**：
- 查看日志中的"LLM Raw Response"部分
- 检查API key是否有效
- 检查API配额是否用完
- 尝试增加 `config.json` 中的 `max_tokens`（当前8192）

### Q5: 想分析其他二进制文件

**步骤**：
1. 把新的二进制文件和Excel放入项目目录
2. 修改 `config.json` 中的 `excel_file` 和 `binary_file`
3. 重新运行 `python vuln_analyzer.py`

---

## 更换LLM API提供商

### 使用OpenAI API

修改 `config.json`：

```json
"llm": {
    "api_key": "sk-your-openai-api-key",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4",
    "max_tokens": 8192,
    "temperature": 0.1
}
```

### 使用Google Gemini API

**步骤1**：安装Google SDK
```bash
pip install google-generativeai
```

**步骤2**：修改 `vuln_analyzer.py` 中的 `LLMClient` 类

找到 `LLMClient.__init__` 方法（约第50行），替换为：

```python
import google.generativeai as genai

class LLMClient:
    def __init__(self, api_key: str, base_url: str = None, model: str = "gemini-pro", 
                 max_tokens: int = 8192, temperature: float = 0.1):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)
        self.max_tokens = max_tokens
        self.temperature = temperature
    
    def call(self, prompt: str, max_retries: int = 3) -> str:
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        max_output_tokens=self.max_tokens,
                        temperature=self.temperature
                    )
                )
                return response.text
            except Exception as e:
                logger.warning(f"LLM API call failed (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
```

**步骤3**：修改 `config.json`

```json
"llm": {
    "api_key": "your-gemini-api-key",
    "model": "gemini-pro",
    "max_tokens": 8192,
    "temperature": 0.1
}
```

> 注意：Gemini API的base_url不需要配置

### 使用其他兼容OpenAI格式的API

只要API兼容OpenAI格式（如Azure OpenAI、Claude API等），只需修改 `config.json`：

```json
"llm": {
    "api_key": "your-api-key",
    "base_url": "https://your-api-endpoint/v1",
    "model": "your-model-name",
    "max_tokens": 8192,
    "temperature": 0.1
}
```

---

## 技术支持

如遇到其他问题：
1. 查看 `vuln_analyzer.log` 日志文件
2. 检查 `CLAUDE.md` 中的"已知问题与修复记录"
3. 确认Python版本 ≥ 3.8：`python --version`
4. 确认依赖完整安装：`pip list | grep angr`
