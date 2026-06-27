import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const DEFAULT_API_URL = 'https://api.shieldly.io';
const SEVERITY_ORDER = ['Low', 'Medium', 'High', 'Critical'];

// __CG_VERSION__ is replaced at build time by esbuild define.
// When imported as library source (unbundled) it falls back to the package version.
const CG_VERSION = typeof __CG_VERSION__ !== 'undefined' ? __CG_VERSION__ : '1.3.0';
const UA = `Shieldly-CDKGuard/${CG_VERSION}`;

const SEV_COLOR = {
  CRITICAL: '\x1b[31m',
  HIGH: '\x1b[33m',
  MEDIUM: '\x1b[36m',
  LOW: '\x1b[32m',
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';

function severityRank(s) {
  const target = String(s ?? '').toLowerCase();
  const i = SEVERITY_ORDER.findIndex((x) => x.toLowerCase() === target);
  return i === -1 ? 0 : i;
}

// ---------------------------------------------------------------------------
// Risk acceptance helpers
// ---------------------------------------------------------------------------

/**
 * Load .shieldly.json from configPath or CWD.
 * Returns { ignore: [] } if not found or unreadable.
 */
export function loadConfig(configPath) {
  const path = configPath ?? resolve(process.cwd(), '.shieldly.json');
  if (!existsSync(path)) return { ignore: [] };
  try {
    const cfg = JSON.parse(readFileSync(path, 'utf8'));
    return { ignore: [], ...cfg };
  } catch {
    return { ignore: [] };
  }
}

/**
 * Minimal glob matching for aws:cdk:path strings.
 * Supports * (single segment) and ** (multi-segment).
 */
function globMatch(pattern, str) {
  const re = new RegExp(
    `^${pattern
      .split('**')
      .map((seg) => seg.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*'))
      .join('.*')}$`
  );
  return re.test(str);
}

/**
 * Check if a finding should be accepted (suppressed from failure).
 *
 * Precedence:
 *   1. Inline `shieldly:accept` on the CFN resource Metadata
 *      - Object form: { reason?, maxSeverity? } — matches all findings on the resource
 *      - Array form (legacy): [title, …] — matches by exact AI title (kept for compat)
 *   2. .shieldly.json `resource` glob (or legacy `path`) — no title needed
 *   3. .shieldly.json title-only rule (global, legacy fallback)
 *
 * @returns {{ accepted: boolean, reason?: string, source?: string }}
 */
function checkAccepted(finding, resourceNode, ignoreRules) {
  const meta = resourceNode?.Metadata ?? {};
  const cdkPath = meta['aws:cdk:path'] ?? '';
  const inlineAccept = meta['shieldly:accept'];

  // 1. Inline accept
  if (inlineAccept != null) {
    if (Array.isArray(inlineAccept)) {
      // Legacy: title array — still supported for backwards compat
      if (inlineAccept.includes(finding.title)) {
        return { accepted: true, reason: meta['shieldly:reason'], source: 'inline' };
      }
    } else {
      // Object (or truthy scalar): accept all findings on this resource
      const opts = typeof inlineAccept === 'object' ? inlineAccept : {};
      if (!opts.maxSeverity || severityRank(finding.severity) <= severityRank(opts.maxSeverity)) {
        return {
          accepted: true,
          reason: opts.reason ?? meta['shieldly:reason'],
          source: 'inline',
        };
      }
    }
  }

  // 2 & 3. Config rules
  let globalTitleFallback = null;
  for (const rule of ignoreRules) {
    // 'resource' is the preferred field; 'path' is the legacy alias
    const resourceGlob = rule.resource ?? rule.path ?? null;

    if (resourceGlob && !globMatch(resourceGlob, cdkPath)) continue;
    if (rule.title && rule.title !== finding.title) continue;
    if (rule.maxSeverity && severityRank(finding.severity) > severityRank(rule.maxSeverity))
      continue;

    if (resourceGlob) {
      return {
        accepted: true,
        reason: rule.reason,
        source: `config (resource: ${resourceGlob})`,
      };
    }
    // Title-only global rule — lower precedence, keep as fallback
    if (rule.title && !globalTitleFallback) globalTitleFallback = rule;
  }

  if (globalTitleFallback) {
    return { accepted: true, reason: globalTitleFallback.reason, source: 'config (global title)' };
  }

  return { accepted: false };
}

// ---------------------------------------------------------------------------
// CDK manifest + template discovery
// ---------------------------------------------------------------------------

function readCDKManifest(dir) {
  try {
    const raw = readFileSync(join(dir, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    if (!manifest.artifacts || typeof manifest.artifacts !== 'object') return null;
    const files = Object.values(manifest.artifacts)
      .filter((a) => a.type === 'aws:cloudformation:stack' && a.properties?.templateFile)
      .map((a) => join(dir, a.properties.templateFile))
      .filter((p) => existsSync(p));
    return files.length > 0 ? files : null;
  } catch {
    return null;
  }
}

function findTemplates(dir) {
  const fromManifest = readCDKManifest(dir);
  if (fromManifest) return fromManifest;
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith('.template.json'))
      .map((e) => join(dir, e.name));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function pollJob(jobId, apiKey, apiUrl) {
  const delays = [2000, 3000, 5000];
  const startMs = Date.now();
  let consecutiveErrors = 0;
  for (let i = 0; i < 180; i++) {
    await new Promise((r) => setTimeout(r, delays[Math.min(i, delays.length - 1)]));
    const elapsed = Math.round((Date.now() - startMs) / 1000);
    process.stderr.write(`\rAI-Powered analysis in progress... (${elapsed}s)`);
    try {
      const res = await fetch(`${apiUrl}/v1/jobs/${encodeURIComponent(jobId)}`, {
        headers: { Authorization: `Bearer ${apiKey}`, 'User-Agent': UA },
      });
      const data = await res.json().catch(() => ({}));
      consecutiveErrors = 0;
      if (data.status === 'complete') {
        process.stderr.write('\n');
        return { ...data.result, unitInfo: data.unitInfo };
      }
      if (data.status === 'failed') {
        process.stderr.write('\n');
        throw new Error(data.error || 'Analysis failed');
      }
    } catch (err) {
      if (++consecutiveErrors >= 3) {
        process.stderr.write('\n');
        throw err;
      }
    }
  }
  process.stderr.write('\n');
  throw new Error('Analysis timed out after polling');
}

async function callAPI(templateContent, apiKey, apiUrl) {
  const res = await fetch(`${apiUrl}/v1/analyze/cf`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': UA,
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ template: templateContent }),
  });
  if (res.status === 202) {
    const data = await res.json().catch(() => ({}));
    if (data.jobId) return pollJob(data.jobId, apiKey, apiUrl);
    throw new Error('Analysis queued but no job ID returned');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function printResult(filePath, data, acceptedList) {
  const { score, riskLevel, findings = [], summary } = data;
  const scoreStr = score === null || score === undefined ? '—' : `${score}/100`;
  const scoreCol = score >= 80 ? '\x1b[32m' : score >= 50 ? '\x1b[33m' : '\x1b[31m';

  console.log('');
  console.log(`${BOLD}[Shieldly] AI-Powered Security Analysis${RESET} — ${DIM}${filePath}${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(
    `  Score: ${scoreCol}${scoreStr}${RESET}  ` +
      `Risk: ${SEV_COLOR[(riskLevel ?? '').toUpperCase()] ?? ''}${riskLevel || 'Unknown'}${RESET}`
  );
  if (summary) console.log(`  ${DIM}${summary}${RESET}`);
  console.log('');

  if (findings.length === 0 && acceptedList.length === 0) {
    console.log(`  ${CYAN}[PASS] No findings${RESET}`);
  } else {
    if (findings.length > 0) {
      console.log(`${BOLD}Findings (${findings.length}):${RESET}`);
      for (const f of findings) {
        const col = SEV_COLOR[(f.severity || '').toUpperCase()] ?? '';
        console.log(`\n  ${col}[${f.severity}]${RESET} ${BOLD}${f.title}${RESET}`);
        if (f.resource && f.resource !== '*') {
          console.log(`         ${DIM}Resource: ${f.resource}${RESET}`);
        }
        if (f.description) console.log(`         ${DIM}${f.description}${RESET}`);
        if (f.remediation) console.log(`  ${CYAN}Fix:${RESET}  ${f.remediation}`);
        const acceptPath = f.cdkPath ? f.cdkPath.replace(/\/[^/]+$/, '/*') : '';
        const acceptCmd = acceptPath
          ? `cdk-guard accept --resource "${acceptPath}"`
          : `cdk-guard accept "${f.title}"`;
        console.log(`  ${DIM}Accept: ${acceptCmd}${RESET}`);
      }
      console.log('');
    }

    if (acceptedList.length > 0) {
      console.log(`${BOLD}Accepted risks (${acceptedList.length}):${RESET}`);
      for (const { finding, reason, source } of acceptedList) {
        const parts = [`  ${YELLOW}[ACCEPTED]${RESET} ${DIM}${finding.title}${RESET}`];
        if (reason) parts.push(`${DIM}— ${reason}${RESET}`);
        console.log(parts.join('  '));
        console.log(`             ${DIM}via: ${source}${RESET}`);
      }
      console.log('');
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyze a CDK output directory (or any directory containing *.template.json files).
 *
 * @param {string} assemblyDir  Path to cdk.out or equivalent.
 * @param {object} options
 * @param {string} options.apiKey           Shieldly API key (sk_live_...).
 * @param {'Critical'|'High'|'Medium'|'Low'|'none'} [options.failOn='High']
 * @param {string} [options.apiUrl]         Override API base URL.
 * @param {boolean} [options.silent]        Suppress console output.
 * @param {string} [options.configPath]     Path to .shieldly.json (default: CWD/.shieldly.json).
 * @returns {Promise<{results: Array, failed: boolean}>}
 */
export async function analyzeAssembly(assemblyDir, options = {}) {
  const { apiKey, apiUrl = DEFAULT_API_URL, failOn = 'High', silent = false, configPath } = options;

  if (!apiKey) {
    throw new Error(
      'Shieldly API key required. Set SHIELDLY_API_KEY or pass { apiKey } option.\n' +
        'Get an API key (Builder plan or above): https://www.shieldly.io/app/api'
    );
  }

  const config = loadConfig(configPath);
  const templates = findTemplates(assemblyDir);

  if (templates.length === 0) {
    if (!silent) console.log(`[Shieldly] No CloudFormation templates found in ${assemblyDir}`);
    return { results: [], failed: false };
  }

  if (!silent) {
    console.log(
      `\n[Shieldly] AI-Powered Security Analysis — ${templates.length} stack(s) in ${assemblyDir}`
    );
  }

  const results = [];
  const failRank = severityRank(failOn);
  let failed = false;

  for (const filePath of templates) {
    const templateContent = readFileSync(filePath, 'utf8');
    if (!silent) process.stdout.write(`  Analyzing ${filePath}... `);

    // Parse template locally for resource metadata lookup (acceptance rules).
    let templateResources = {};
    try {
      templateResources = JSON.parse(templateContent).Resources ?? {};
    } catch {
      // Non-standard template — acceptance matching skipped, all findings active.
    }

    try {
      const data = await callAPI(templateContent, apiKey, apiUrl);
      if (!silent) console.log('done');

      // Split findings into active (fail-eligible) and accepted (suppressed).
      const active = [];
      const accepted = [];
      for (const f of data.findings ?? []) {
        const resourceNode = templateResources[f.resource];
        const result = checkAccepted(f, resourceNode, config.ignore ?? []);
        if (result.accepted) {
          accepted.push({ finding: f, reason: result.reason, source: result.source });
        } else {
          active.push({ ...f, cdkPath: resourceNode?.Metadata?.['aws:cdk:path'] ?? '' });
        }
      }

      if (!silent) printResult(filePath, { ...data, findings: active }, accepted);
      results.push({ filePath, data: { ...data, findings: active }, accepted });

      const maxRank = active.reduce((max, f) => {
        const rank = severityRank(f.severity);
        return rank > max ? rank : max;
      }, -1);

      if (failOn !== 'none' && maxRank >= failRank) failed = true;
    } catch (err) {
      if (!silent) console.log(`\n  Error: ${err.message}`);
      results.push({ filePath, error: err.message, accepted: [] });
    }
  }

  if (!silent) {
    if (failed) {
      console.log(
        `[Shieldly] FAIL — findings at or above ${failOn} severity detected. Remediate before deploying.\n` +
          '  Full report: https://www.shieldly.io/app/iam\n'
      );
    } else {
      console.log('[Shieldly] PASS — all stacks analyzed.\n');
    }
  }

  return { results, failed };
}
