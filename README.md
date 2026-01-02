<div align="center">

# 🛡️ 365skill - Skill 安全卫士

**Claude Code 技能安全扫描器**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com)

*检测恶意代码、数据外传和安全风险*

</div>

---

## 📖 简介

**365skill** 是专门为 Claude Code 技能设计的安全扫描器。它可以自动检测潜在的安全风险，包括硬编码凭据、恶意命令、代码混淆和数据外传等。

### 为什么需要 365skill？

当你安装社区技能时，实际上是在你的机器上执行代码。**365skill** 帮你：

- 🔍 **安装前扫描** - 通过 Hook 自动检测风险
- 🛡️ **保护你的凭据** - 发现硬编码的 API 密钥和令牌
- 🚨 **捕获恶意行为** - 检测数据外传和危险命令
- ✅ **白名单可信技能** - 跳过你已审查并信任的技能

---

## ✨ 功能特性

### 🔬 三种扫描模式

| 模式 | 描述 | 适用场景 |
|------|------|----------|
| **基础** | 敏感信息、危险命令、可疑网络 | 快速扫描 |
| **深度** | + 代码混淆、文件操作、数据外传、Shell 注入 | **默认模式** |
| **全量** | + 行为分析、指纹采集、持久化机制 | 全面审计 |

### 🎯 风险等级

- 🔴 **严重** - 危险命令、Shell 注入、持久化机制
- 🟠 **高** - 硬编码凭据、数据外传、代码混淆
- 🟡 **中** - 可疑文件操作、网络请求
- 🟢 **低** - 其他可疑模式

### 🛠️ 核心能力

- ✅ 通过预安装 Hook 自动扫描
- ✅ 交互式审查和可选删除
- ✅ 白名单支持可信技能
- ✅ JSON 输出支持 CI/CD 集成
- ✅ 跨平台（Windows、macOS、Linux）
- ✅ 零依赖（仅使用 Python 标准库）

---

## 📦 安装

### 方法 1：克隆仓库

```bash
cd ~/.claude/skills
git clone https://github.com/yourusername/365skill.git
```

### 方法 2：手动安装

1. 下载并解压到 `~/.claude/skills/365skill/`
2. 确保目录结构完整

### 验证安装

```bash
python ~/.claude/skills/365skill/scripts/scan_skills.py --help
```

---

## 🚀 使用方法

### 快速开始

```bash
# 扫描所有已安装的技能（深度模式）
python ~/.claude/skills/365skill/scripts/scan_skills.py

# 交互式模式（可选择删除）
python ~/.claude/skills/365skill/scripts/interactive_scan.py
```

### 命令选项

```bash
# 基础扫描（更快）
python ~/.claude/skills/365skill/scripts/scan_skills.py --level basic

# 全量扫描（最全面）
python ~/.claude/skills/365skill/scripts/scan_skills.py --level full

# 扫描指定技能
python ~/.claude/skills/365skill/scripts/scan_skills.py --skill <技能名称>

# JSON 输出（用于脚本/CI）
python ~/.claude/skills/365skill/scripts/scan_skills.py --json

# 禁用白名单（扫描全部）
python ~/.claude/skills/365skill/scripts/scan_skills.py --no-whitelist
```

### 白名单管理

```bash
# 查看白名单
python ~/.claude/skills/365skill/scripts/scan_skills.py --whitelist-show

# 添加到白名单
python ~/.claude/skills/365skill/scripts/scan_skills.py --whitelist-add <技能名称>

# 从白名单移除
python ~/.claude/skills/365skill/scripts/scan_skills.py --whitelist-remove <技能名称>
```

---

## 📊 输出示例

```
======================================================================
365skill 安全扫描报告
======================================================================

扫描统计:
   总扫描技能数: 9
   安全技能数: 7
   存在风险的技能数: 2
   总风险点数: 15

[WHITELIST] 跳过 1 个技能:
   - 我信任的技能

[ 高风险 ] 高风险 (2):

   ! 可疑技能
      [HIGH] 检测到可能的认证令牌硬编码
         文件: suspicious-skill/config.json:42
         修复: 使用环境变量或配置文件管理敏感信息
      [MEDIUM] Localhost 端口连接
         文件: suspicious-skill/api.py:15

======================================================================
发现 2 个存在风险的技能
======================================================================
```

---

## ⚙️ 配置

### 启用安装时自动扫描

编辑 `~/.claude/settings.json`：

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/365skill/scripts/scan_skills.py --skill {skill_name} --level deep"
  }
}
```

现在每个新安装的技能都会自动扫描！

### 白名单配置

白名单文件位置：`~/.claude/skills/365skill/assets/whitelist.json`

```json
{
  "whitelisted_skills": [
    {
      "name": "我信任的技能",
      "reason": "已审查并确认安全",
      "added_at": "2026-01-02"
    }
  ],
  "notes": "白名单中的技能将在安全扫描中被跳过"
}
```

---

## 🔍 检测规则

### 1. 敏感信息泄露

检测硬编码的凭据：
- API 密钥（`api_key`、`apikey`、`API_KEY`）
- 认证令牌（`token`、`access_token`、`bearer_token`）
- 密码（`password`、`passwd`、`pwd`）
- 密钥（`secret`、`private_key`、`secret_key`）

### 2. 危险命令

检测高风险代码执行：
- `eval()` - 动态代码执行
- `exec()` - 动态代码执行
- `os.system()` - 命令执行
- `rm -rf` - 危险删除操作
- Shell 注入模式

### 3. 代码混淆

检测隐藏恶意代码的尝试：
- 十六进制/Unicode 转义序列
- Base64 编码代码
- 字符编码技巧
- 多层混淆

### 4. 数据外传

检测潜在的数据窃取：
- 外部服务通信（pastebin、discord、webhook）
- 遥测/信标 URL
- 原始 socket 连接
- 可疑网络请求

### 5. 文件操作

检测可疑的文件访问：
- SSH/GPG/AWS 凭证文件
- 用户主目录访问
- 批量文件操作
- 邮件发送功能

### 6. 行为分析（全量模式）

- 无限循环或大量迭代
- 长时间延迟攻击
- 多线程/进程创建
- 系统指纹采集

---

## 🛡️ 安全最佳实践

1. **始终审查新技能** - 让 365skill 先扫描
2. **使用环境变量** - 永远不要硬编码凭据
3. **启用预安装 Hook** - 自动化安全检查
4. **定期审查白名单** - 移除不使用的条目
5. **保持 365skill 更新** - 获取最新检测模式

---

## 🤝 贡献

欢迎贡献！请：

1. Fork 仓库
2. 创建功能分支
3. 为新检测模式添加测试
4. 提交 Pull Request

### 添加新的检测模式

编辑 `scripts/scan_skills.py`，将模式添加到相应类别：

```python
self.basic_patterns = {
    "你的类别": [
        (r'你的正则表达式',
         "人类可读的描述"),
    ],
    # ...
}
```

---

## 📝 路线图

- [ ] Web 扫描结果仪表板
- [ ] 定时后台扫描
- [ ] 基于机器学习的异常检测
- [ ] 集成病毒扫描服务
- [ ] 社区威胁情报源

---

## 🐛 故障排除

### 扫描失败提示"权限被拒绝"

确保 Python 对你的技能目录有读取权限：

```bash
chmod -R +r ~/.claude/skills
```

### 误报处理

如果遇到误报：
1. 审查代码确认安全
2. 添加到白名单：`--whitelist-add <技能名称>`
3. 报告误报以改进检测

### Hook 未触发

1. 验证 `settings.json` 语法正确
2. 使用绝对 Python 路径：`/usr/bin/python3` 或 `python`
3. 手动测试：`python ~/.claude/skills/365skill/scripts/scan_skills.py`

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

---

## 🌟 致谢

感谢 Claude Code 社区的支持！

**灵感来源**：不断增长的 Claude 生态系统中对技能安全的需求。

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐**

用 ❤️ 制作
</div>
