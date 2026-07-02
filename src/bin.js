/**
 * cdk-guard — run cdk synth then AI-Powered security analysis in one command.
 *
 * Usage:
 *   npx @shieldly/cdk-guard [options] [-- cdk synth flags]
 *
 * Options:
 *   --api-key <key>    Shieldly API key (or SHIELDLY_API_KEY env var)
 *                      Get an API key (Builder plan or above): https://www.shieldly.io/app/api
 *   --fail-on <sev>    Fail exit code threshold: Critical|High|Medium|Low|none
 *                      Default: High
 *   --out-dir <dir>    CDK output directory  [default: cdk.out]
 *   --no-synth         Skip cdk synth; analyze --out-dir as-is
 *   --format <fmt>     Output format: table|json  [default: table]
 *   -h, --help         Show this help
 *
 * Examples:
 *   npx @shieldly/cdk-guard
 *   npx @shieldly/cdk-guard --fail-on Critical
 *   npx @shieldly/cdk-guard --no-synth --out-dir cdk.out
 *   npx @shieldly/cdk-guard -- --context env=prod
 *
 * CI (GitHub Actions):
 *   - name: CDK security check
 *     run: npx @shieldly/cdk-guard
 *     env:
 *       SHIELDLY_API_KEY: ${{ secrets.SHIELDLY_API_KEY }}
 *
 * cdk.json hook (runs after every cdk synth):
 *   {
 *     "hooks": {
 *       "afterSynth": ["npx", "@shieldly/cdk-guard", "--no-synth"]
 *     }
 *   }
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { analyzeAssembly } from './analyze.js';

const HELP = `
cdk-guard — AI-Powered AWS security analysis for CDK apps

Usage:
  npx @shieldly/cdk-guard [options] [-- cdk synth flags]
  npx @shieldly/cdk-guard accept "<title>" [--path "<glob>"] [--reason "<text>"]

Commands:
  accept --resource <glob>   Suppress all findings on a CDK resource path (recommended)
                             --max-severity <sev>  Only suppress up to this severity level
                             --reason <text>       Document why this risk is accepted
  accept "<title>"           Legacy: suppress by AI-generated title (fragile — use --resource instead)
                             --path <glob>         Scope to aws:cdk:path glob

Options:
  --api-key <key>      Shieldly API key (or SHIELDLY_API_KEY env var)
  --fail-on <sev>      Fail threshold: Critical|High|Medium|Low|none  [default: High]
  --out-dir <dir>      CDK output directory  [default: cdk.out]
  --no-synth           Skip cdk synth; analyze --out-dir only
  --format <fmt>       Output format: table|json  [default: table]
  --interactive, -i    After analysis, prompt to accept findings (requires TTY)
  --accept-on-fail     Like --interactive but only prompts when findings exceed --fail-on
  -h, --help           Show this help

Examples:
  npx @shieldly/cdk-guard
  npx @shieldly/cdk-guard --fail-on Critical
  npx @shieldly/cdk-guard --interactive
  npx @shieldly/cdk-guard --accept-on-fail
  npx @shieldly/cdk-guard -- --context env=prod
  npx @shieldly/cdk-guard accept --resource "ExampleStack/BroadRole/*" --reason "Bootstrap role"
  npx @shieldly/cdk-guard accept --resource "ExampleStack/BroadRole/*" --max-severity High

Get an API key (Builder plan or above): https://www.shieldly.io/app/api
`;

async function acceptCommand(argv) {
  function argVal(name) {
    const i = argv.indexOf(name);
    return i !== -1 ? argv[i + 1] : undefined;
  }

  const resource = argVal('--resource');
  const reason = argVal('--reason');
  const maxSeverity = argVal('--max-severity');

  // Legacy title form: first positional arg that isn't a flag value
  const title = !resource && !argv[0]?.startsWith('--') ? argv[0] : undefined;
  const legacyPath = title ? argVal('--path') : undefined;

  if (!resource && !title) {
    console.error(
      '[Shieldly] Usage:\n' +
        '  cdk-guard accept --resource "<cdkPath glob>" [--max-severity <sev>] [--reason <text>]\n' +
        '  cdk-guard accept "<title>" [--path <glob>] [--reason <text>]  (legacy)'
    );
    process.exit(1);
  }

  const configPath = resolve(process.cwd(), '.shieldly.json');
  let cfg = { ignore: [] };
  if (existsSync(configPath)) {
    try {
      cfg = JSON.parse(readFileSync(configPath, 'utf8'));
      if (!Array.isArray(cfg.ignore)) cfg.ignore = [];
    } catch {
      cfg = { ignore: [] };
    }
  }

  let rule;
  let isDupe;
  if (resource) {
    rule = { resource };
    if (maxSeverity) rule.maxSeverity = maxSeverity;
    if (reason) rule.reason = reason;
    isDupe = cfg.ignore.some(
      (r) => r.resource === resource && (r.maxSeverity ?? '') === (maxSeverity ?? '')
    );
  } else {
    rule = { title };
    if (legacyPath) rule.path = legacyPath;
    if (reason) rule.reason = reason;
    isDupe = cfg.ignore.some((r) => r.title === title && (r.path ?? '') === (legacyPath ?? ''));
  }

  if (!isDupe) {
    cfg.ignore.push(rule);
    writeFileSync(configPath, `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');
  }

  const scope = resource
    ? `resource: ${resource}${maxSeverity ? ` (≤${maxSeverity})` : ''}`
    : legacyPath
      ? `path: ${legacyPath}`
      : 'global title';
  console.log(`[Shieldly] Accepted: ${scope}`);
  if (reason) console.log(`           Reason: ${reason}`);
  if (isDupe) console.log('           (rule already exists — no change)');
  console.log(`           Written to: ${configPath}`);
}

const SEV_COL = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m', MEDIUM: '\x1b[36m', LOW: '\x1b[32m' };
const B = '\x1b[1m';
const D = '\x1b[2m';
const C = '\x1b[36m';
const R = '\x1b[0m';

async function interactiveAccept(allFindings) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log('\n[Shieldly] --interactive requires a TTY — skipping accept prompt.');
    return;
  }
  if (allFindings.length === 0) return;

  // Deduplicate by title, keeping first occurrence (which has cdkPath)
  const seen = new Set();
  const unique = allFindings.filter((f) => {
    if (seen.has(f.title)) return false;
    seen.add(f.title);
    return true;
  });

  console.log(`\n${B}Accept findings interactively:${R}`);
  for (const [i, f] of unique.entries()) {
    const col = SEV_COL[(f.severity || '').toUpperCase()] ?? '';
    console.log(`  ${i + 1}. ${col}[${f.severity}]${R} ${f.title}`);
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const input = await rl.question(`\nNumbers to accept (e.g. 1,3) or Enter to skip: `);
    if (!input.trim()) return;

    const indices = input
      .split(',')
      .map((s) => Number.parseInt(s.trim(), 10) - 1)
      .filter((i) => !Number.isNaN(i) && i >= 0 && i < unique.length);

    if (indices.length === 0) return;

    const cfgPath = resolve(process.cwd(), '.shieldly.json');
    let cfg = { ignore: [] };
    if (existsSync(cfgPath)) {
      try {
        cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
        if (!Array.isArray(cfg.ignore)) cfg.ignore = [];
      } catch {
        cfg = { ignore: [] };
      }
    }

    let added = 0;
    for (const idx of indices) {
      const f = unique[idx];
      const reason = (await rl.question(`  Reason (optional): `)).trim();

      // Suggest resource glob from cdkPath: strip last segment, append /*
      const suggested = f.cdkPath ? f.cdkPath.replace(/\/[^/]+$/, '/*') : '';
      const resourceHint = suggested ? ` [${D}${suggested}${R}]` : '';
      const resourceAnswer = (
        await rl.question(`  CDK resource path${resourceHint} or Enter for global: `)
      ).trim();
      const resource = resourceAnswer || suggested || undefined;

      const isDupe = resource
        ? cfg.ignore.some((r) => r.resource === resource)
        : cfg.ignore.some((r) => !r.resource && !r.path && r.title === f.title);

      if (!isDupe) {
        const rule = resource ? { resource } : { title: f.title };
        if (reason) rule.reason = reason;
        cfg.ignore.push(rule);
        added++;
      }

      const scope = resource ? `resource: ${resource}` : 'global (all resources, by title)';
      console.log(
        `  ${C}✓${R} ${isDupe ? '(already accepted)' : 'Accepted:'} "${f.title}" — ${scope}`
      );
    }

    if (added > 0) {
      writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');
      console.log(`\n  Written to ${cfgPath}`);
      console.log(`  ${D}Re-run analysis to verify suppressions took effect.${R}\n`);
    }
  } finally {
    rl.close();
  }
}

async function main() {
  const argv = process.argv.slice(2);

  if (argv[0] === 'accept') {
    await acceptCommand(argv.slice(1));
    process.exit(0);
  }

  if (argv.includes('-h') || argv.includes('--help')) {
    console.log(HELP);
    process.exit(0);
  }

  // Split on -- to separate our flags from cdk synth flags
  const ddIdx = argv.indexOf('--');
  const ourArgs = ddIdx === -1 ? argv : argv.slice(0, ddIdx);
  const cdkArgs = ddIdx === -1 ? [] : argv.slice(ddIdx + 1);

  function flag(name) {
    const i = ourArgs.indexOf(name);
    return i !== -1 ? ourArgs[i + 1] : undefined;
  }

  const apiKey = flag('--api-key') || process.env.SHIELDLY_API_KEY;
  const failOn = flag('--fail-on') || 'High';
  const outDir = flag('--out-dir') || 'cdk.out';
  const noSynth = ourArgs.includes('--no-synth');
  const format = flag('--format') || 'table';
  const interactive = ourArgs.includes('--interactive') || ourArgs.includes('-i');
  const acceptOnFail = ourArgs.includes('--accept-on-fail');

  if (!apiKey) {
    console.error(
      '[Shieldly] API key required. Set SHIELDLY_API_KEY or pass --api-key.\n' +
        'Get an API key (Builder plan or above): https://www.shieldly.io/app/api'
    );
    process.exit(1);
  }

  if (!['Critical', 'High', 'Medium', 'Low', 'none'].includes(failOn)) {
    console.error(
      `[Shieldly] Invalid --fail-on value: "${failOn}". Use: Critical | High | Medium | Low | none`
    );
    process.exit(1);
  }

  if (!noSynth) {
    console.log('[Shieldly] Running cdk synth...');
    const result = spawnSync('npx', ['cdk', 'synth', '--output', outDir, ...cdkArgs], {
      stdio: 'inherit',
      shell: false,
    });
    if (result.status !== 0) {
      console.error('[Shieldly] cdk synth failed — skipping security analysis.');
      process.exit(result.status ?? 1);
    }
  }

  const silent = format === 'json';
  const { results, failed } = await analyzeAssembly(outDir, { apiKey, failOn, silent });

  if (format === 'json') {
    console.log(
      JSON.stringify(
        results.map(({ filePath, data, error }) => ({
          stack: filePath,
          ...(error ? { error } : data),
        })),
        null,
        2
      )
    );
  }

  if (!silent && (interactive || (acceptOnFail && failed))) {
    const allActiveFindings = results.filter((r) => r.data).flatMap((r) => r.data.findings ?? []);
    await interactiveAccept(allActiveFindings);
  }

  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(`[Shieldly] Fatal: ${err.message}`);
  process.exit(1);
});
