# Hook 配置参考

本文档说明如何配置 360skill 的 Hook 功能，实现新技能安装时自动检测。

## 方法 1: 配置 settings.json

编辑 `~/.claude/settings.json` 文件，添加以下内容：

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep"
  }
}
```

### 参数说明

- `{skill_name}` - 会被替换为实际安装的 skill 名称
- `--level deep` - 使用深度检测模式（推荐）

### 其他 Hook 选项

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep && echo '扫描完成'",
    "post-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep"
  }
}
```

## 方法 2: 使用环境变量

在 shell 配置文件（`.bashrc`, `.zshrc` 等）中添加：

```bash
export CLAUDE_PRE_SKILL_INSTALL="python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep"
```

## 方法 3: 创建 Hook 脚本

创建一个包装脚本 `~/.claude/hooks/pre-skill-install`：

```bash
#!/bin/bash
SKILL_NAME="$1"
python ~/.claude/skills/360skill/scripts/scan_skills.py --skill "$SKILL_NAME" --level deep
if [ $? -ne 0 ]; then
    echo "⚠️  检测到风险！建议取消安装"
    read -p "是否继续安装？(y/n): " confirm
    if [ "$confirm" != "y" ]; then
        exit 1
    fi
fi
```

## 配置示例

### 最小配置（基础检测）

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level basic"
  }
}
```

### 推荐配置（深度检测）

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level deep"
  }
}
```

### 严格配置（全量检测）

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/scan_skills.py --skill {skill_name} --level full"
  }
}
```

### 交互式配置

```json
{
  "hooks": {
    "pre-skill-install": "python ~/.claude/skills/360skill/scripts/interactive_scan.py --skill {skill_name}"
  }
}
```

## 验证 Hook 是否生效

安装一个测试 skill，观察是否自动触发扫描：

```bash
# 应该会看到扫描输出
claude skill install test-skill
```

## 故障排除

### Hook 没有执行

1. 检查 `settings.json` 格式是否正确
2. 确认 Python 路径是否正确
3. 使用 `which python` 确认 Python 可执行文件位置

### 找不到 skill

确认 `{skill_name}` 占位符是否正确设置。有些系统可能使用不同的占位符语法。

### 权限问题

确保脚本有执行权限：

```bash
chmod +x ~/.claude/skills/360skill/scripts/*.py
```

## 禁用 Hook

临时禁用 Hook，删除 `settings.json` 中的 hooks 配置即可。
