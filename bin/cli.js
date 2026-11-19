#!/usr/bin/env node
'use strict';

const path = require('path');
const os = require('os');
const { pathToFileURL } = require('url');
const { scan, SEV } = require('../src/index.js');
const pkg = require('../package.json');

const HELP = `agentcfg-audit ${pkg.version}
Audit AI coding agent configuration for leaked secrets, risky permissions,
unpinned MCP servers and hidden prompt injection. Offline, read-only.

Usage
  npx agentcfg-audit [path] [options]

Options
  -g, --global          also scan user-level configs (~/.claude.json, Claude Desktop,
                        Cursor, Windsurf, Gemini CLI, Codex, VS Code)
      --global-only     scan only user-level configs
      --json            machine-readable output
      --sarif           SARIF 2.1.0 output (GitHub code scanning)
      --fail-on <sev>   exit 1 when a finding at or above: high | medium | low | none
                        (default: high)
      --ignore <ids>    comma-separated rule IDs to skip, e.g. MCP001,CC008
      --list            list every pre-approved rule, MCP server and hook, not just a sample
      --no-color        disable ANSI colours
  -h, --help            show this help
  -v, --version         show version
`;

function parseArgs(argv) {
  const o = { root: null, failOn: 'high', ignore: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '-g' || a === '--global') o.global = true;
    else if (a === '--global-only') { o.global = true; o.globalOnly = true; } else if (a === '--json') o.json = true;
    else if (a === '--sarif') o.sarif = true;
    else if (a === '--no-color') o.noColor = true;
    else if (a === '--list') o.list = true;
    else if (a === '--fail-on') o.failOn = argv[++i];
    else if (a.startsWith('--fail-on=')) o.failOn = a.slice(10);
    else if (a === '--ignore') o.ignore = String(argv[++i] || '').split(',').filter(Boolean);
    else if (a.startsWith('--ignore=')) o.ignore = a.slice(9).split(',').filter(Boolean);
    else if (a.startsWith('-')) throw new Error(`Unknown option: ${a}`);
    else if (o.root === null) o.root = a;
    else throw new Error(`Unexpected argument: ${a}`);
  }
  if (!['high', 'medium', 'low', 'none'].includes(o.failOn)) throw new Error('--fail-on must be high, medium, low or none');
  return o;
}

function display(file, root) {
  const rel = path.relative(root, file);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel.replace(/\\/g, '/');
  const home = path.relative(os.homedir(), file);
  if (home && !home.startsWith('..') && !path.isAbsolute(home)) return `~/${home.replace(/\\/g, '/')}`;
  return file;
}

// "What can my agents do without asking me?" Shown on every run, clean or not.
function summarize(inv) {
  const uniq = (list) => [...new Set(list)];
  const shell = inv.allow.filter((a) => /^(Bash|PowerShell)\b/.test(a.rule));
  return {
    preApprovedRules: inv.allow.length,
    preApprovedShellRules: shell.length,
    filesWithApprovals: uniq(inv.allow.map((a) => a.file)).length,
    shellRules: uniq(shell.map((a) => a.rule)),
    otherRules: uniq(inv.allow.filter((a) => !shell.includes(a)).map((a) => a.rule)),
    mcpServers: uniq(inv.mcp.map((m) => m.name)),
    unpinnedMcpServers: uniq(inv.mcp.filter((m) => m.unpinned).map((m) => m.name)),
    hooks: inv.hooks.map((h) => h.command),
    instructionFiles: inv.instructions.length,
  };
}

function summaryLines(s, c, list) {
  const out = [];
  const sample = (items, n) => {
    const shown = list ? items : items.slice(0, n);
    for (const it of shown) out.push(`       ${c(2, it.length > 90 ? `${it.slice(0, 90)}…` : it)}`);
    if (items.length > shown.length) out.push(`       ${c(2, `… and ${items.length - shown.length} more (--list shows all)`)}`);
  };
  const row = (n, text) => out.push(`  ${c(1, String(n).padStart(4))}  ${text}`);
  out.push(c(1, 'What your AI agents can do without asking you'));
  row(s.preApprovedRules, `pre-approved permission rule(s) in ${s.filesWithApprovals} file(s), ${s.preApprovedShellRules} of them shell commands`);
  sample(s.shellRules, 6);
  if (list) sample(s.otherRules, 0);
  row(s.mcpServers.length, `MCP server(s) start with your agent, ${s.unpinnedMcpServers.length} of them from unpinned packages`);
  sample(s.mcpServers, 6);
  row(s.hooks.length, 'hook command(s) run automatically');
  sample(s.hooks, 3);
  row(s.instructionFiles, 'instruction file(s) are loaded by agents whether or not you have read them');
  out.push('');
  return out;
}

function toSarif(findings, root) {
  const rules = new Map();
  for (const f of findings) if (!rules.has(f.rule)) rules.set(f.rule, f);
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'agentcfg-audit',
        version: pkg.version,
        rules: [...rules.values()].map((f) => ({
          id: f.rule,
          shortDescription: { text: f.title.replace(/"[^"]*"/g, '…').slice(0, 120) },
          properties: { 'security-severity': { high: '8.0', medium: '5.0', low: '2.0' }[f.severity] },
        })),
      } },
      results: findings.map((f) => {
        const rel = path.relative(root, f.file);
        const inside = rel && !rel.startsWith('..') && !path.isAbsolute(rel);
        return {
          ruleId: f.rule,
          level: { high: 'error', medium: 'warning', low: 'note' }[f.severity],
          message: { text: [f.title, f.detail, f.fix && `Fix: ${f.fix}`].filter(Boolean).join('\n') },
          locations: [{ physicalLocation: {
            artifactLocation: { uri: inside ? rel.replace(/\\/g, '/') : pathToFileURL(f.file).href },
            region: { startLine: f.line },
          } }],
        };
      }),
    }],
  };
}

function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) {
    process.stderr.write(`${e.message}\n\n${HELP}`);
    return 2;
  }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(`${pkg.version}\n`); return 0; }

  const root = path.resolve(o.root || '.');
  let result;
  try {
    result = scan(o.globalOnly ? null : root, { global: o.global, ignore: o.ignore });
  } catch (e) {
    process.stderr.write(`agentcfg-audit: ${e.message}\n`);
    return 2;
  }
  const { files, findings } = result;
  const summary = summarize(result.inventory);
  const failed = o.failOn !== 'none' && findings.some((f) => SEV[f.severity] >= SEV[o.failOn]);

  if (o.sarif) {
    process.stdout.write(`${JSON.stringify(toSarif(findings, root), null, 2)}\n`);
  } else if (o.json) {
    process.stdout.write(`${JSON.stringify({
      version: pkg.version,
      scannedFiles: files.map((f) => display(f, root)),
      summary,
      findings: findings.map((f) => ({ ...f, file: display(f.file, root) })),
    }, null, 2)}\n`);
  } else {
    const color = !o.noColor && process.stdout.isTTY && !process.env.NO_COLOR;
    const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
    const badge = { high: c('41;97;1', ' HIGH '), medium: c('43;30;1', ' MED  '), low: c('100;97', ' LOW  ') };
    const out = [];
    out.push(c(1, `agentcfg-audit ${pkg.version}`) + c(2, `  ·  ${files.length} agent config file(s) scanned`));
    out.push('');
    if (!files.length) {
      out.push('No AI agent configuration found here. Try: agentcfg-audit --global');
    } else {
      out.push(...summaryLines(summary, c, o.list));
      if (!findings.length) out.push(c(32, '✔ No known-dangerous settings found.'));
    }
    for (const f of findings) {
      out.push(`${badge[f.severity]} ${c(1, f.title)}`);
      out.push(`       ${c(36, `${display(f.file, root)}:${f.line}`)}  ${c(2, f.rule)}`);
      if (f.detail) out.push(`       ${f.detail}`);
      if (f.fix) out.push(`       ${c(32, 'fix:')} ${f.fix}`);
      out.push('');
    }
    if (findings.length) {
      const n = (s) => findings.filter((f) => f.severity === s).length;
      out.push(c(1, `${findings.length} finding(s): ${n('high')} high, ${n('medium')} medium, ${n('low')} low`));
    }
    if (!o.global && files.length) out.push(c(2, 'Tip: add --global to also audit your user-level agent configs.'));
    process.stdout.write(`${out.join('\n')}\n`);
  }
  return failed ? 1 : 0;
}

process.exitCode = main();
