# 运行指南

## 1. 安装Python依赖

在项目目录下运行：

```bash
pip install -r requirements.txt
```

安装的库：
- `openai` — 调用DeepSeek API
- `openpyxl` — 读取Excel文件
- `pydantic` — JSON格式验证
- `python-dotenv` — 环境变量支持（可选）

---

## 2. 配置 config.json

打开 `config.json`，需要修改以下内容：

### 2.1 填入DeepSeek API Key

```json
"llm": {
    "api_key": "YOUR_DEEPSEEK_API_KEY",   ← 改成你的API key
    ...
}
```

获取API key：登录 [platform.deepseek.com](https://platform.deepseek.com) → API Keys → 创建新Key

### 2.2 设置IDA路径

```json
"ida": {
    "path": "C:\\Program Files\\IDA Pro 8.3\\idat.exe",   ← 改成你的IDA实际路径
    ...
}
```

**如何确认IDA路径：**
- 默认安装路径通常是 `C:\Program Files\IDA Pro X.X\`
- 32位二进制用 `idat.exe`，64位二进制用 `idat64.exe`
- 当前 `httpd` 是 ARM 32-bit，使用 `idat.exe`

### 2.3 确认文件路径

```json
"paths": {
    "excel_file": "targets.xlsx",    ← Excel文件名（默认已正确）
    "binary_file": "httpd"           ← 二进制文件名（默认已正确）
}
```

> 所有文件（脚本、Excel、二进制）必须在同一目录下，默认配置已满足此要求。

---

## 3. 确认IDA许可证

IDA Pro需要有效许可证才能运行。确认以下几点：
- IDA Pro已激活
- 支持ARM处理器模块（分析ARM二进制需要）
- 支持Python脚本（IDA 7.0+默认支持IDAPython）

---

## 4. 运行

在项目目录下执行：

```bash
python vuln_analyzer.py
```

---

## 5. 查看结果

运行完成后会生成以下文件：

| 文件 | 内容 |
|------|------|
| `vuln_paths.json` | LLM从Excel提取的漏洞路径（可检查提取是否正确） |
| `asm_code.json` | IDA提取的汇编代码 |
| `exploit_result.json` | 最终分析结果和攻击指令 |
| `vuln_analyzer.log` | 完整运行日志（出错时查看） |

---

## 6. 常见问题

**Q: IDA分析失败？**
- 检查 `config.json` 中IDA路径是否正确
- 查看 `vuln_analyzer.log` 中的IDA输出
- 确认IDA许可证有效

**Q: LLM返回格式错误？**
- 查看日志中LLM的原始返回内容
- 可以尝试将模型改为 `deepseek-reasoner`（推理能力更强）

**Q: 找不到函数？**
- 确认Excel中的函数名与二进制中的符号名一致
- 如果二进制stripped（无符号），需要在Excel中提供函数地址

**Q: 更换Excel或二进制文件？**
- 将新文件放入同一目录
- 修改 `config.json` 中的 `excel_file` 和 `binary_file` 字段
