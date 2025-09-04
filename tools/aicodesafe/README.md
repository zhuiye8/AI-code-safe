AI Code Safe — Claude Code Hook 提示词安全审查

用法

- 本地扫描：
  - echo "text" | node tools/aicodesafe/bin/aicodesafe.js scan
  - 或：node tools/aicodesafe/bin/aicodesafe.js scan --text "your prompt here"

- 作为 Claude Code Hook（UserPromptSubmit）：
  在 Claude Code 设置文件中加入：

  {
    "hooks": {
      "UserPromptSubmit": [
        {
          "hooks": [
            { "type": "command", "command": "node tools/aicodesafe/bin/hook-user-prompt.js" }
          ]
        }
      ]
      ,
      "PreToolUse": [
        {
          "matcher": ".*",
          "hooks": [
            { "type": "command", "command": "node tools/aicodesafe/bin/hook-pre-tool-use.js" }
          ]
        }
      ]
    }
  }

行为与退出码

- 无命中：exit 0（放行）。
- 中/低危：exit 2（阻断一次），stderr 显示命中详情与“已脱敏提示”，用户复制后重新提交。
- 高危：exit 2（阻断），stderr 显示命中详情与处理建议。

注意

- hooks 配置在会话开始时快照，修改后需在 /hooks 菜单审查并应用。
- Windows/Linux/macOS 通用；需要 Node.js 18+。
