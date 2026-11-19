# agentcfg-audit

**Find the security holes in your AI coding agent setup in five seconds.**

```bash
npx agentcfg-audit --global
```

AI coding agents (Claude Code, Cursor, Codex, Gemini CLI, Windsurf, Copilot…) are configured through
JSON, TOML and Markdown files that nobody reviews: API keys pasted into `mcp.json`, MCP servers
launched with `npx -y whatever`, `Bash(*)` allow-rules committed to a repo, and rule files that can
carry instructions invisible to a human reader. `agentcfg-audit` reads those files and tells you
what is dangerous and how to fix it.

- **Offline and read-only.** No network calls, no telemetry, nothing is executed. Secrets are redacted in output.
- **Zero dependencies.** One small package; audit the source in a few minutes.
- **CI-ready.** Exit codes, `--json`, and `--sarif` for GitHub code scanning.

## What it checks

| ID | Severity | Finding |
|----|----------|---------|
| SEC001 | high | Known credential formats in any agent file (Anthropic, OpenAI, GitHub, AWS, Slack, Google, GitLab, npm, Stripe, JWT, private keys, URLs with passwords) |
| SEC002 | medium | High-entropy literal in a secret-looking `env` / `headers` key |
| MCP001 | medium | MCP server launched from an unpinned package (`npx -y pkg`, `uvx pkg`, `pnpm dlx`, git URL without commit) |
| MCP002 | high | MCP server command downloads or decodes code and executes it (`curl … \| sh`, `base64 -d`) |
| MCP003 | medium | Remote MCP server over plain `http://` |
| MCP004 | medium | Filesystem MCP server scoped to `/`, a drive root or the whole home directory |
| MCP005 | high | MCP container with `--privileged`, `docker.sock` or root filesystem mount |
| MCP006 | low | MCP container image on a floating tag |
| CC001 | high | Claude Code `defaultMode: bypassPermissions` |
| CC002 | high | Allow rule for unrestricted shell (`Bash`, `Bash(*)`) |
| CC003 | medium | Wildcard allow rule for an arbitrary-execution command (`Bash(curl:*)`, `Bash(python:*)`, `Bash(sudo:*)`…) |
| CC004 | medium | `enableAllProjectMcpServers` (any cloned repo can start MCP servers) |
| CC005 | high/medium | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing at a third-party host |
| CC006 | high | `apiKeyHelper` defined in repository settings |
| CC007 | high | Hook command that uses the network, credential files or obfuscated code |
| CC008 | low | Repository ships an auto-running hook (review it) |
| CX001 | high/medium | Codex `sandbox_mode = "danger-full-access"` (high with `approval_policy = "never"`) |
| INJ001 | high | Invisible Unicode tag characters in a rule file (hidden text is decoded and shown) |
| INJ002 | high | Bidirectional control characters |
| INJ003 | medium | Zero-width characters |
| INJ004 | high | "Ignore previous instructions"-style override |
| INJ005 | high | Instruction to hide actions from the user |
| INJ006 | high | Credential file + network command on one line |
| INJ007 | medium | Download-and-execute command in a rule file |
| INJ008 | medium | HTML comment (invisible when rendered) containing agent-directed instructions |
| INJ009 | medium | Slash command / skill with `allowed-tools: Bash` |

## Files it reads

**Project** (default, recursive from the given path): `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
`.claude/settings*.json`, `.gemini/settings.json`, `.codex/config.toml`, `CLAUDE.md`, `AGENTS.md`,
`GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`,
`.github/copilot-instructions.md`, `.github/instructions/*.md`, `.claude/{commands,agents,skills}/**/*.md`.

**User level** (`--global`): `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/{commands,agents,skills}`,
Claude Desktop `claude_desktop_config.json`, `~/.cursor/mcp.json`, Windsurf `mcp_config.json`,
`~/.gemini/settings.json`, `~/.codex/config.toml`, VS Code / Cursor user `mcp.json`.

## Usage

```bash
npx agentcfg-audit                 # audit the current repository
npx agentcfg-audit --global        # …plus your user-level agent configs
npx agentcfg-audit --global-only   # only your machine, no repository
npx agentcfg-audit path/to/repo --fail-on medium
npx agentcfg-audit --ignore CC008,MCP006 --json
```

Exit code is `1` when a finding at or above `--fail-on` (default `high`) exists, `2` on usage errors.

### Before you open a repository you just cloned

```bash
npx agentcfg-audit ./that-repo --fail-on low
```

Repository-level agent files (`.mcp.json`, `.claude/settings.json`, rule files) are an attack surface:
they are applied the moment you start an agent in that directory.

### GitHub Actions

```yaml
name: agent-config-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: npx --yes agentcfg-audit@0.1.1 --sarif --fail-on none > agentcfg.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentcfg.sarif
      - run: npx --yes agentcfg-audit@0.1.1
```

## Limits

This is a static linter, not a sandbox. It does not download or analyse the MCP server packages
themselves, cannot tell whether a pinned package is trustworthy, and its phrase-based
prompt-injection rules catch common patterns, not every wording. A clean report means "no known
foot-guns in the config", not "safe".

## 日本語

AIコーディングエージェント（Claude Code / Cursor / Codex / Gemini CLI / Windsurf / Copilot）の設定ファイルを
監査する、依存ゼロ・完全オフラインのCLIです。MCP設定に直書きされたAPIキー、バージョン未固定の
MCPサーバー、`Bash(*)` などの危険な許可ルール、ルールファイルに埋め込まれた不可視文字による
プロンプトインジェクションを検出し、修正方法を表示します。

```bash
npx agentcfg-audit --global
```

## License

MIT
