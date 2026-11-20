'use strict';
// agentcfg-audit: offline auditor for AI coding agent configuration.
// Reads files only. Never executes anything, never touches the network.

const fs = require('fs');
const path = require('path');
const os = require('os');

const SEV = { low: 1, medium: 2, high: 3 };
const MAX_SIZE = 2 * 1024 * 1024;

// ---------------------------------------------------------------- patterns

const SECRET_PATTERNS = [
  ['Anthropic API key', /sk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}/],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{40,}/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['AWS access key ID', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}/],
  ['Stripe live key', /\b[sr]k_live_[A-Za-z0-9]{20,}/],
  ['Private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ['Bearer token', /\bBearer\s+[A-Za-z0-9._~+/-]{24,}/],
  ['Credentials in URL', /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@"'$]+:[^/\s:@"'${}]{6,}@/i],
];

const SECRET_KEY = /(api[_-]?key|token|secret|passw(or)?d|credential|private[_-]?key|auth)/i;
const NET = /\b(curl|wget|nc|ncat|netcat|scp|ftp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i;
const PIPE_SHELL = /\|\s*(sudo\s+)?(sh|bash|zsh|iex|python3?|node)\b/i;
const OBFUSCATED = /base64\s+(-d|--decode)\b|\beval\b|FromBase64String|-enc(odedcommand)?\s/i;
const SENSITIVE = /(\.ssh\b|id_rsa|id_ed25519|\.aws[\\/]credentials|\.env\b|\.npmrc|\.netrc|\.git-credentials|\.claude\.json|keychain)/i;
const DANGEROUS_BASH = new Set([
  'curl', 'wget', 'sh', 'bash', 'zsh', 'python', 'python3', 'node', 'eval', 'sudo', 'rm',
  'powershell', 'pwsh', 'ssh', 'nc', 'npx', 'docker', 'chmod', 'env', 'xargs',
]);

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', 'out', 'vendor', 'target', 'venv', '__pycache__', 'coverage',
]);
const AGENT_DOT_DIRS = new Set([
  '.claude', '.cursor', '.vscode', '.github', '.gemini', '.codex', '.windsurf', '.roo', '.kiro',
  '.clinerules', '.continue', '.amazonq',
]);
const INSTRUCTION_NAMES = new Set([
  'claude.md', 'claude.local.md', 'agents.md', 'gemini.md', '.cursorrules', '.windsurfrules',
  '.clinerules', 'copilot-instructions.md',
]);
const CONFIG_NAMES = new Set([
  '.mcp.json', 'mcp.json', 'mcp_config.json', 'claude_desktop_config.json', '.claude.json',
  'managed-settings.json',
]);

// ---------------------------------------------------------------- helpers

function parseJsonc(text) {
  try { return JSON.parse(text); } catch { /* fall through to tolerant parse */ }
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const d = text[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') { out += d === undefined ? '' : d; i++; } else if (c === '"') inStr = false;
    } else if (c === '"') { inStr = true; out += c; } else if (c === '/' && d === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && d === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') out += '\n'; i++; }
      i++;
    } else out += c;
  }
  return JSON.parse(out.replace(/^﻿/, '').replace(/,(\s*[}\]])/g, '$1'));
}

function lineOf(text, needle) {
  if (!needle) return 1;
  let idx = text.indexOf(needle);
  if (idx < 0) idx = text.indexOf(JSON.stringify(needle).slice(1, -1));
  if (idx < 0) return 1;
  let line = 1;
  for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function redact(s) {
  s = String(s);
  if (s.length <= 8) return '*'.repeat(s.length);
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

const isRef = (v) => /\$\{[^}]+\}|^\$[A-Za-z_]\w*$|^%\w+%$/.test(v);
const isPlaceholder = (v) => /^<.*>$|your[_-]|xxx|changeme|example|placeholder|todo|\*{3,}|^\.{3}$/i.test(v);
const isPathLike = (v) => /^([~./\\]|[A-Za-z]:[\\/]|https?:\/\/)/.test(v);
const knownSecret = (v) => SECRET_PATTERNS.find(([, re]) => re.test(v));

function cmdBase(c) {
  return path.posix.basename(String(c || '').replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, '');
}

function trunc(s, n = 140) {
  s = String(s).replace(/\s+/g, ' ').trim();
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// ---------------------------------------------------------------- secrets

function scanSecrets(ctx) {
  const lines = ctx.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 20000) continue;
    for (const [name, re] of SECRET_PATTERNS) {
      const m = re.exec(line);
      if (!m) continue;
      ctx.add('SEC001', 'high', `${name} stored in plain text`, {
        line: i + 1,
        detail: redact(m[0]),
        fix: 'Rotate this credential now, then reference it via an environment variable (e.g. "${MY_TOKEN}") or a secret manager instead of writing it in the file.',
      });
      break;
    }
  }
}

function checkEnvSecrets(ctx, env, where) {
  if (!env || typeof env !== 'object') return;
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string' || !SECRET_KEY.test(k)) continue;
    if (v.length < 12 || isRef(v) || isPlaceholder(v) || isPathLike(v) || knownSecret(v)) continue;
    if (entropy(v) < 3) continue;
    ctx.add('SEC002', 'medium', `Possible hardcoded secret in ${where}: ${k}`, {
      needle: v,
      detail: redact(v),
      fix: `Replace the literal value with an environment reference such as "\${${k}}".`,
    });
  }
}

// ---------------------------------------------------------------- MCP servers

function unwrap(tokens) {
  let t = tokens.slice();
  if (cmdBase(t[0]) === 'cmd' && /^\/c$/i.test(t[1] || '')) t = t.slice(2);
  if (cmdBase(t[0]) === 'env') { t = t.slice(1); while (t[0] && /^\w+=/.test(t[0])) t.shift(); }
  return t;
}

function uvPackage(a) {
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    if (x === '--from') return { kind: 'pypi', spec: a[i + 1] };
    if (x === '--with' || x === '--python' || x === '-p' || x === '--index-url') { i++; continue; }
    if (x.startsWith('-')) continue;
    return { kind: 'pypi', spec: x };
  }
  return null;
}

function runnerPackage(t) {
  const b = cmdBase(t[0]);
  let a = t.slice(1);
  if (b === 'uvx') return uvPackage(a);
  if (b === 'uv') return a[0] === 'tool' && a[1] === 'run' ? uvPackage(a.slice(2)) : null;
  if (['pnpm', 'yarn', 'bun'].includes(b)) {
    if (a[0] !== 'dlx' && a[0] !== 'x') return null;
    a = a.slice(1);
  } else if (!['npx', 'bunx', 'pnpx'].includes(b)) return null;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    if (x === '-p' || x === '--package') return { kind: 'npm', spec: a[i + 1] };
    if (x.startsWith('--package=')) return { kind: 'npm', spec: x.slice(10) };
    if (x.startsWith('-')) continue;
    return { kind: 'npm', spec: x };
  }
  return null;
}

function pinState(pkg) {
  const spec = String(pkg.spec || '');
  if (!spec || /^([~./\\]|[A-Za-z]:[\\/])/.test(spec)) return 'local';
  if (/^(https?:|git\+|git:|github:|ssh:)/.test(spec)) return /[#@][0-9a-f]{40}\b/.test(spec) ? 'pinned' : 'remote';
  if (pkg.kind === 'pypi') return /==\d|@\d+\.\d+/.test(spec) ? 'pinned' : 'unpinned';
  const at = spec.lastIndexOf('@');
  return at > 0 && /^\d+\.\d+\.\d+/.test(spec.slice(at + 1)) ? 'pinned' : 'unpinned';
}

const DOCKER_VALUE_FLAGS = new Set([
  '-e', '--env', '-v', '--volume', '-p', '--publish', '--name', '--network', '--net', '--mount', '-w',
  '--workdir', '-u', '--user', '--entrypoint', '-l', '--label', '--env-file', '--platform', '-h',
  '--hostname', '--add-host', '--memory', '-m', '--cpus',
]);

function dockerImage(t) {
  const runAt = t.indexOf('run');
  if (cmdBase(t[0]) !== 'docker' && cmdBase(t[0]) !== 'podman') return null;
  if (runAt < 0) return null;
  for (let i = runAt + 1; i < t.length; i++) {
    const x = t[i];
    if (DOCKER_VALUE_FLAGS.has(x)) { i++; continue; }
    if (x.startsWith('-')) continue;
    return x;
  }
  return null;
}

function auditMcpServer(ctx, name, s) {
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  const command = typeof s.command === 'string' ? s.command : '';
  const tokens = unwrap(args.length ? [command, ...args] : command.split(/\s+/).filter(Boolean));
  const joined = [command, ...args].join(' ');
  const needle = args.find((a) => a.length > 3 && !a.startsWith('-')) || command || name;

  checkEnvSecrets(ctx, s.env, `MCP server "${name}" env`);
  checkEnvSecrets(ctx, s.headers, `MCP server "${name}" headers`);

  const pkg = tokens.length ? runnerPackage(tokens) : null;
  const state = pkg && pinState(pkg);
  ctx.inv.mcp.push({ name, file: ctx.file, unpinned: state === 'unpinned' || state === 'remote' });

  if (tokens.length) {
    if (state === 'unpinned' || state === 'remote') {
      ctx.add('MCP001', 'medium', `MCP server "${name}" runs an unpinned package: ${trunc(pkg.spec, 80)}`, {
        needle: pkg.spec,
        detail: 'Every launch downloads and executes whatever is currently published under this name. A hijacked or typosquatted release runs with your user privileges and your agent\'s credentials.',
        fix: pkg.kind === 'pypi' ? `Pin an exact version: ${pkg.spec}==X.Y.Z` : `Pin an exact version: ${pkg.spec.replace(/@latest$/, '')}@X.Y.Z (or a full git commit SHA).`,
      });
    }
    const image = dockerImage(tokens);
    if (image && !image.includes('@sha256:') && (!/:[^/]+$/.test(image) || /:latest$/.test(image))) {
      ctx.add('MCP006', 'low', `MCP server "${name}" uses a floating Docker image tag: ${image}`, {
        needle: image, fix: 'Pin a specific version tag or an @sha256 digest.',
      });
    }
    if (image && /--privileged|docker\.sock|(^|\s)(-v|--volume)\s+\/:/.test(joined)) {
      ctx.add('MCP005', 'high', `MCP server "${name}" runs a container with host-level access`, {
        needle: image, detail: trunc(joined),
        fix: 'Remove --privileged, the docker.sock mount and root filesystem mounts; mount only the directories the server needs.',
      });
    }
  }

  if ((NET.test(joined) && PIPE_SHELL.test(joined)) || OBFUSCATED.test(joined)) {
    ctx.add('MCP002', 'high', `MCP server "${name}" downloads or decodes code and executes it`, {
      needle, detail: trunc(joined),
      fix: 'Do not pipe remote content into a shell. Install a pinned release and run it directly.',
    });
  }

  const url = s.url || s.serverUrl || s.httpUrl;
  if (typeof url === 'string') {
    const m = /^http:\/\/([^/:]+)/i.exec(url);
    if (m && !/^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|host\.docker\.internal)$/i.test(m[1])) {
      ctx.add('MCP003', 'medium', `MCP server "${name}" is reached over unencrypted HTTP`, {
        needle: url, detail: trunc(url.replace(/\?.*/, '?…'), 100),
        fix: 'Use https:// so prompts, tool results and auth headers cannot be read or modified in transit.',
      });
    }
  }

  if (/filesystem/i.test(joined + name)) {
    const home = os.homedir();
    const broad = args.find((a) => a === '/' || a === '~' || a === '$HOME' || a === '%USERPROFILE%' || /^[A-Za-z]:[\\/]?$/.test(a) || path.resolve(a) === home);
    if (broad) {
      ctx.add('MCP004', 'medium', `Filesystem MCP server "${name}" exposes ${broad === '/' || /^[A-Za-z]:/.test(broad) ? 'the whole disk' : 'your entire home directory'}`, {
        needle: JSON.stringify(broad),
        detail: 'The agent (and anything that prompt-injects it) can read SSH keys, cloud credentials and browser profiles.',
        fix: 'Scope the server to specific project directories.',
      });
    }
  }
}

// ---------------------------------------------------------------- Claude Code settings

function collectCommands(node, out = []) {
  if (Array.isArray(node)) node.forEach((n) => collectCommands(n, out));
  else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (k === 'command' && typeof v === 'string') out.push(v);
      else collectCommands(v, out);
    }
  }
  return out;
}

const COMMAND_SECRETS = [
  ['MySQL password', /\b(?:mysql|mariadb|mysqldump|mysqladmin)\b[^)]*?\s-p(?!\s)([^\s)'"]{4,})/],
  ['sshpass password', /\bsshpass\s+-p\s*['"]?([^\s)'"]{4,})/],
  ['--password flag', /--password[=\s]+['"]?([^\s)'"$][^\s)'"]{3,})/],
  ['password variable', /\b(?:PGPASSWORD|MYSQL_PWD|REDISCLI_AUTH|PASSWORD|PASSWD)=['"]?([^\s)'"$][^\s)'"]{3,})/i],
  ['auth header', /-H\s*['"]?(?:authorization|x-api-key|api-key|x-auth-token|private-token)\s*:\s*(?:bearer\s+|token\s+|basic\s+)?([^\s)'"$][^\s)'"]{7,})/i],
  ['basic auth', /\bcurl\b[^)]*?\s(?:-u|--user)\s+['"]?[^\s:'"]+:([^\s)'"$][^\s)'"]{3,})/],
  ['token in URL', /[?&](?:token|api_key|apikey|access_token|key|password)=([^\s&)'"$][^\s&)'"]{7,})/i],
];

function passwordInCommand(rule) {
  for (const [kind, re] of COMMAND_SECRETS) {
    const m = re.exec(rule);
    if (m && !isRef(m[1]) && !isPlaceholder(m[1])) return { kind, value: m[1] };
  }
  return null;
}

// The inventory prints approved commands verbatim, so blank out anything secret first.
function maskSecrets(text) {
  let out = text;
  for (const [, re] of SECRET_PATTERNS) out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`), (m) => redact(m));
  for (let i = 0; i < COMMAND_SECRETS.length; i++) {
    const pw = passwordInCommand(out);
    if (!pw) break;
    out = out.split(pw.value).join('****');
  }
  return out;
}

function auditClaudeSettings(ctx, j) {
  const perms = j.permissions && typeof j.permissions === 'object' ? j.permissions : {};
  const where = ctx.project ? 'A repository-level setting applies to everyone who opens this repo.' : '';

  if (perms.defaultMode === 'bypassPermissions') {
    ctx.add('CC001', 'high', 'Permission prompts are disabled (defaultMode: bypassPermissions)', {
      needle: 'bypassPermissions',
      detail: `The agent can run any command and edit any file without asking. ${where}`.trim(),
      fix: 'Use "default" or "acceptEdits" and allow-list the specific commands you need.',
    });
  }

  for (const rule of Array.isArray(perms.allow) ? perms.allow : []) {
    if (typeof rule !== 'string') continue;
    ctx.inv.allow.push({ rule: maskSecrets(rule), file: ctx.file });
    // "Yes, and don't ask again" saves the literal command, so a password typed on the command
    // line ends up in the settings file. Known token formats are already caught by SEC001.
    const pw = !knownSecret(rule) && passwordInCommand(rule);
    if (pw) {
      ctx.add('SEC003', 'high', `Password or token saved inside an approved command (${pw.kind})`, {
        needle: rule,
        detail: redact(pw.value),
        fix: 'Delete this rule, rotate the credential, and if the file was ever committed, treat it as leaked (old commits and forks keep it).',
      });
    }
    if (/^(Bash|PowerShell)(\((\*|:\*|\*:\*)\))?$/.test(rule)) {
      ctx.add('CC002', 'high', `Allow rule "${maskSecrets(rule)}" lets the agent run any shell command without asking`, {
        needle: rule, detail: where,
        fix: 'Replace it with narrow rules such as "Bash(npm test)" or "Bash(git status)".',
      });
      continue;
    }
    const m = /^(?:Bash|PowerShell)\(([\w.-]+)(?::\*|\s\*|\*)\)$/.exec(rule);
    if (m && DANGEROUS_BASH.has(m[1].toLowerCase())) {
      ctx.add('CC003', 'medium', `Allow rule "${maskSecrets(rule)}" pre-approves an arbitrary-execution command`, {
        needle: rule,
        detail: `"${m[1]}" with any arguments is equivalent to unrestricted shell access (downloads, interpreters, privilege escalation).`,
        fix: 'Allow only the exact invocations you need, or leave this command on "ask".',
      });
    }
  }

  if (j.enableAllProjectMcpServers === true) {
    ctx.add('CC004', 'medium', 'enableAllProjectMcpServers auto-approves MCP servers defined by any repository', {
      needle: 'enableAllProjectMcpServers',
      detail: 'Cloning and opening a malicious repo would start its MCP servers (arbitrary commands) without a prompt.',
      fix: 'Remove it and list trusted servers in "enabledMcpjsonServers".',
    });
  }

  const env = j.env && typeof j.env === 'object' ? j.env : {};
  checkEnvSecrets(ctx, env, 'settings env');
  for (const key of ['ANTHROPIC_BASE_URL', 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL', 'OPENAI_BASE_URL']) {
    const v = env[key];
    if (typeof v !== 'string') continue;
    const host = (/^[a-z]+:\/\/([^/:]+)/i.exec(v) || [])[1] || '';
    if (/(^|\.)(anthropic\.com|openai\.com|amazonaws\.com|googleapis\.com)$|^(localhost|127\.0\.0\.1)$/i.test(host)) continue;
    ctx.add('CC005', ctx.project ? 'high' : 'medium', `${key} redirects all model traffic to ${host || trunc(v, 60)}`, {
      needle: v,
      detail: 'Every prompt, file content and API key sent by the agent passes through this host.',
      fix: ctx.project ? 'Never commit a base-URL override to a repository; confirm this host is one you operate.' : 'Confirm this is a proxy you operate and trust.',
    });
  }

  if (ctx.project && typeof j.apiKeyHelper === 'string') {
    ctx.add('CC006', 'high', 'Repository settings define apiKeyHelper (a command executed to obtain credentials)', {
      needle: j.apiKeyHelper, detail: trunc(j.apiKeyHelper),
      fix: 'Keep apiKeyHelper in user-level settings only.',
    });
  }

  for (const cmd of collectCommands(j.hooks)) {
    ctx.inv.hooks.push({ command: maskSecrets(cmd), file: ctx.file });
    if (NET.test(cmd) || OBFUSCATED.test(cmd) || SENSITIVE.test(cmd)) {
      ctx.add('CC007', 'high', 'Hook command touches the network, credentials or obfuscated code', {
        needle: cmd, detail: trunc(maskSecrets(cmd)),
        fix: 'Hooks run automatically with your privileges. Remove this hook unless you wrote it and understand it.',
      });
    } else if (ctx.project) {
      ctx.add('CC008', 'low', 'Repository ships a hook that runs automatically during agent sessions', {
        needle: cmd, detail: trunc(maskSecrets(cmd)), fix: 'Review the command before trusting this repository.',
      });
    }
  }
}

// ---------------------------------------------------------------- Codex config.toml

function auditCodexToml(ctx) {
  const { text } = ctx;
  const noSandbox = /^\s*sandbox_mode\s*=\s*["']danger-full-access["']/m.exec(text);
  const noApproval = /^\s*approval_policy\s*=\s*["']never["']/m.exec(text);
  if (noSandbox) {
    ctx.add('CX001', noApproval ? 'high' : 'medium',
      noApproval ? 'Codex runs with no sandbox and no approval prompts' : 'Codex sandbox is disabled (danger-full-access)', {
        needle: noSandbox[0].trim(),
        fix: 'Use sandbox_mode = "workspace-write" and approval_policy = "on-request".',
      });
  }
  // Minimal TOML reader: just enough to recover [mcp_servers.*] tables.
  const servers = {};
  let cur = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      const parts = sec[1].split('.').map((p) => p.trim().replace(/^["']|["']$/g, ''));
      cur = null;
      if (parts[0] === 'mcp_servers' && parts[1]) {
        const srv = (servers[parts[1]] = servers[parts[1]] || {});
        cur = parts[2] ? (srv[parts[2]] = srv[parts[2]] || {}) : srv;
      }
      continue;
    }
    const kv = /^([\w.-]+|"[^"]+")\s*=\s*(.+)$/.exec(line);
    if (!cur || !kv) continue;
    let value = kv[2].replace(/\s+#.*$/, '');
    try { value = JSON.parse(value.replace(/^'(.*)'$/, (_, s) => JSON.stringify(s))); } catch { continue; }
    cur[kv[1].replace(/"/g, '')] = value;
  }
  for (const [name, s] of Object.entries(servers)) auditMcpServer(ctx, name, s);
}

// ---------------------------------------------------------------- instruction files

function auditInstructions(ctx) {
  const lines = ctx.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const n = i + 1;
    let tags = '';
    let bidi = 0;
    let zw = 0;
    let pos = 0;
    for (const ch of line) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xe0000 && cp <= 0xe007f) tags += cp >= 0xe0020 && cp <= 0xe007e ? String.fromCharCode(cp - 0xe0000) : '';
      else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
      else if (cp === 0x200b || cp === 0x200c || cp === 0x2060 || (cp === 0xfeff && !(i === 0 && pos === 0))) zw++;
      pos++;
    }
    if (tags || /[\u{E0000}-\u{E007F}]/u.test(line)) {
      ctx.add('INJ001', 'high', 'Invisible Unicode "tag" characters hide text that only the model can read', {
        line: n, detail: tags ? `Decoded hidden text: "${trunc(tags, 200)}"` : '',
        fix: 'Delete the invisible characters. Treat this file (and whoever added them) as compromised.',
      });
    }
    if (bidi) {
      ctx.add('INJ002', 'high', 'Bidirectional control characters make this line display differently from what the model reads', {
        line: n, detail: `${bidi} control character(s)`, fix: 'Remove the U+202A–202E / U+2066–2069 characters and re-read the line.',
      });
    }
    if (zw) {
      ctx.add('INJ003', 'medium', 'Zero-width characters found in an agent instruction file', {
        line: n, detail: `${zw} invisible character(s); often used to hide or split instructions`,
        fix: 'Remove them unless the surrounding text is in a script that requires them (e.g. Persian ZWNJ).',
      });
    }
    if (/ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|prompts|guidelines)/i.test(line)) {
      ctx.add('INJ004', 'high', 'Instruction-override phrase ("ignore previous instructions")', {
        line: n, detail: trunc(line), fix: 'Legitimate project rules do not need to cancel other instructions. Review who added this.',
      });
    }
    if (/(do\s+not|don't|never)\s+(tell|inform|mention|reveal|notify|show|disclose)[^.\n]{0,40}\b(user|human|developer|anyone)\b/i.test(line)) {
      ctx.add('INJ005', 'high', 'Instruction tells the agent to conceal its actions from the user', {
        line: n, detail: trunc(line), fix: 'Remove it. An agent rule that hides behaviour from you is a backdoor.',
      });
    }
    if (SENSITIVE.test(line) && NET.test(line)) {
      ctx.add('INJ006', 'high', 'Instruction combines credential files with a network command (possible exfiltration)', {
        line: n, detail: trunc(line), fix: 'Remove it unless you wrote it and it is clearly documentation.',
      });
    } else if (NET.test(line) && PIPE_SHELL.test(line)) {
      ctx.add('INJ007', 'medium', 'Instruction file contains a download-and-execute command', {
        line: n, detail: trunc(line), fix: 'Agents may run commands they read here. Replace with a pinned, reviewed install step.',
      });
    }
    if (/^allowed-tools\s*:.*\b(Bash|PowerShell)(\(\*\))?\s*(,|\]|$)/i.test(line.trim())) {
      ctx.add('INJ009', 'medium', 'Command/skill pre-approves unrestricted shell access (allowed-tools)', {
        line: n, detail: trunc(line), fix: 'List specific commands, e.g. allowed-tools: Bash(git status), Bash(npm test)',
      });
    }
  }
  const comment = /<!--([\s\S]*?)-->/g;
  let m;
  while ((m = comment.exec(ctx.text))) {
    const body = m[1];
    if (NET.test(body) || SENSITIVE.test(body) || /\b(you must|always run|execute the|system prompt|ignore\s+(all|previous)|do not (tell|mention))\b/i.test(body)) {
      ctx.add('INJ008', 'medium', 'HTML comment (invisible in rendered Markdown) contains agent-directed instructions', {
        needle: m[0], detail: trunc(body), fix: 'Read the raw file. Remove the comment if you did not write it.',
      });
    }
  }
}

// ---------------------------------------------------------------- file dispatch

// Inventory: everything agents may do or load without asking, risky or not.
function newInventory() {
  return { allow: [], mcp: [], hooks: [], instructions: [] };
}

function classify(file) {
  const base = path.basename(file).toLowerCase();
  if (base.endsWith('.toml')) return 'toml';
  if (base.endsWith('.json')) return 'json';
  return 'instructions';
}

function scanFile(file, opts = {}) {
  const findings = [];
  let text;
  try {
    if (fs.statSync(file).size > MAX_SIZE) return findings;
    text = fs.readFileSync(file, 'utf8');
  } catch { return findings; }

  const ctx = {
    file,
    text,
    project: opts.scope !== 'global',
    inv: opts.inv || newInventory(),
    add(rule, severity, title, o = {}) {
      findings.push({
        rule, severity, title, file,
        line: o.line || lineOf(text, o.needle),
        detail: o.detail || '',
        fix: o.fix || '',
      });
    },
  };

  scanSecrets(ctx);
  const kind = classify(file);
  if (kind === 'instructions') { ctx.inv.instructions.push(file); auditInstructions(ctx); } else if (kind === 'toml') auditCodexToml(ctx);
  else {
    let j;
    try { j = parseJsonc(text); } catch {
      ctx.add('CFG001', 'low', 'Could not parse this config file as JSON; only secret scanning was applied', {});
      return findings;
    }
    if (!j || typeof j !== 'object') return findings;
    const base = path.basename(file).toLowerCase();
    const groups = [j.mcpServers, j.mcp && j.mcp.servers];
    if (base.includes('mcp')) groups.push(j.servers);
    if (j.projects && typeof j.projects === 'object') {
      for (const p of Object.values(j.projects)) if (p && typeof p === 'object') groups.push(p.mcpServers);
    }
    for (const g of groups) {
      if (!g || typeof g !== 'object') continue;
      for (const [name, s] of Object.entries(g)) if (s && typeof s === 'object') auditMcpServer(ctx, name, s);
    }
    const dir = path.basename(path.dirname(file));
    if ((dir === '.claude' && base.startsWith('settings')) || base === 'managed-settings.json' || j.permissions || j.hooks) {
      auditClaudeSettings(ctx, j);
    }
  }
  return findings;
}

function isTarget(dir, name) {
  const lower = name.toLowerCase();
  const parent = path.basename(dir).toLowerCase();
  const norm = dir.replace(/\\/g, '/').toLowerCase();
  if (CONFIG_NAMES.has(lower) || INSTRUCTION_NAMES.has(lower)) return true;
  if (lower === 'config.toml' && parent === '.codex') return true;
  if (/^settings(\.local)?\.json$/.test(lower) && (parent === '.claude' || parent === '.gemini')) return true;
  if (/\.(md|mdc)$/.test(lower) && /\/\.(claude\/(commands|agents|skills)|cursor\/rules|windsurf\/rules|github\/instructions|clinerules|roo\/rules|kiro\/steering|amazonq\/rules)(\/|$)/.test(`${norm}/`)) return true;
  return false;
}

function walk(dir, depth, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (depth <= 0 || SKIP_DIRS.has(e.name)) continue;
      if (e.name.startsWith('.') && !AGENT_DOT_DIRS.has(e.name)) continue;
      walk(full, depth - 1, out);
    } else if (e.isFile() && isTarget(dir, e.name)) out.push(full);
  }
}

function globalFiles() {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const xdg = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  const mac = path.join(home, 'Library', 'Application Support');
  const out = [
    path.join(home, '.claude.json'),
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
    path.join(home, '.claude', 'CLAUDE.md'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    path.join(home, '.gemini', 'settings.json'),
    path.join(home, '.gemini', 'GEMINI.md'),
    path.join(home, '.codex', 'config.toml'),
    path.join(home, '.codex', 'AGENTS.md'),
  ];
  for (const base of [appData, xdg, mac]) {
    out.push(path.join(base, 'Claude', 'claude_desktop_config.json'));
    for (const code of ['Code', 'Code - Insiders', 'Cursor', 'VSCodium']) out.push(path.join(base, code, 'User', 'mcp.json'));
  }
  for (const sub of ['commands', 'agents', 'skills']) walk(path.join(home, '.claude', sub), 4, out);
  // "Don't ask again" approvals are saved per project. Claude Code records every project it
  // has opened in ~/.claude.json, so follow those paths to the settings where approvals pile up.
  try {
    const known = parseJsonc(fs.readFileSync(path.join(home, '.claude.json'), 'utf8')).projects || {};
    for (const dir of Object.keys(known).slice(0, 500)) {
      if (!path.isAbsolute(dir)) continue;
      out.push(path.join(dir, '.claude', 'settings.json'), path.join(dir, '.claude', 'settings.local.json'), path.join(dir, '.mcp.json'));
    }
  } catch { /* no ~/.claude.json, or unreadable */ }
  return [...new Set(out)].filter((f) => { try { return fs.statSync(f).isFile(); } catch { return false; } });
}

function scan(root, opts = {}) {
  const files = [];
  const seen = new Set();
  const add = (list, scope) => {
    for (const f of list) {
      const key = path.resolve(f);
      if (!seen.has(key)) { seen.add(key); files.push({ file: key, scope }); }
    }
  };
  if (root) {
    const st = fs.statSync(root);
    if (st.isFile()) add([root], 'project');
    else { const found = []; walk(root, opts.depth === undefined ? 6 : opts.depth, found); add(found, 'project'); }
  }
  if (opts.global) add(globalFiles(), 'global');

  const ignore = new Set(opts.ignore || []);
  const findings = [];
  const inventory = newInventory();
  for (const { file, scope } of files) {
    for (const f of scanFile(file, { scope, inv: inventory })) if (!ignore.has(f.rule)) findings.push(f);
  }
  findings.sort((a, b) => SEV[b.severity] - SEV[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { files: files.map((f) => f.file), findings, inventory };
}

module.exports = { scan, scanFile, parseJsonc, SEV };
