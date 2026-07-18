/**
 * @shieldly/cdk-guard — AI-Powered AWS security analysis for CDK apps.
 *
 * Integrates into the CDK synthesis lifecycle via a process.on('beforeExit')
 * hook, so it runs automatically after `cdk synth` completes — no code changes
 * to the CDK app required beyond adding the guard.
 *
 * Usage — automatic (hook-based):
 *
 *   import { ShieldlyGuard } from '@shieldly/cdk-guard';
 *
 *   const app = new cdk.App();
 *   new ShieldlyGuard({ failOn: 'High' }); // reads SHIELDLY_API_KEY from env
 *   new MyStack(app, 'MyStack');
 *   // ShieldlyGuard analyzes cdk.out/ automatically when the process exits.
 *
 * Usage — explicit (post-synth):
 *
 *   import { shieldlyGuard } from '@shieldly/cdk-guard';
 *
 *   const app = new cdk.App();
 *   const stack = new MyStack(app, 'MyStack');
 *   const assembly = app.synth();
 *   await shieldlyGuard(assembly.directory, { failOn: 'High' });
 *
 * Usage — CLI (any language CDK app, no app code changes):
 *
 *   npx @shieldly/cdk-guard [--fail-on High] [-- cdk synth flags]
 */
import { analyzeAssembly } from './analyze.js';

/**
 * Mark a CDK construct's findings as accepted (suppressed).
 * Embeds shieldly:accept into the CFN resource Metadata block so Shieldly
 * can match it at analysis time without relying on AI-generated titles.
 *
 * @param {import('constructs').Construct} construct  CDK L1 or L2 construct.
 * @param {{ reason?: string, maxSeverity?: 'Critical'|'High'|'Medium'|'Low' } | string[]} [optionsOrTitles]
 *   - Object (recommended): accept all findings on this resource, optionally capped by severity.
 *   - Array (legacy): accept only findings whose AI-generated title is in the list.
 * @param {{ reason?: string }} [legacyOptions]  Only used with the legacy array form.
 *
 * @example — recommended (resource-based, title-independent)
 * accept(broadRole, { reason: 'Bootstrap role — removed post-deploy' });
 * accept(broadRole, { maxSeverity: 'High', reason: 'Known risk, tracked in JIRA-123' });
 *
 * @example — legacy (title-based, brittle if AI rewrites the finding title)
 * accept(broadRole, ['Overly Permissive IAM Role Policy'], { reason: '...' });
 */
export function accept(construct, optionsOrTitles = {}, legacyOptions = {}) {
  // node.addMetadata() writes to the CDK tree — NOT the CFN Metadata block.
  // CfnResource.addMetadata() (via defaultChild for L2) writes to the template.
  const cfnResource = construct?.node?.defaultChild ?? construct;
  if (typeof cfnResource?.addMetadata !== 'function') {
    throw new Error(
      '[Shieldly] accept() requires a CDK L1/L2 construct. ' +
        'Pass the construct directly (e.g. the Role or Bucket instance).'
    );
  }
  if (Array.isArray(optionsOrTitles)) {
    // Legacy title-array form
    cfnResource.addMetadata('shieldly:accept', optionsOrTitles);
    if (legacyOptions.reason) cfnResource.addMetadata('shieldly:reason', legacyOptions.reason);
  } else {
    // Resource-based form: store options object directly
    cfnResource.addMetadata('shieldly:accept', optionsOrTitles);
  }
}

export class ShieldlyGuard {
  #ran = false;
  #opts;

  /**
   * @param {object} [options]
   * @param {string} [options.apiKey]       Shieldly API key. Defaults to SHIELDLY_API_KEY env var.
   * @param {string} [options.outDir]       CDK output directory. Defaults to 'cdk.out'.
   * @param {'Critical'|'High'|'Medium'|'Low'|'none'} [options.failOn]  Default: 'High'.
   * @param {string} [options.apiUrl]       Override API base URL.
   * @param {boolean} [options.silent]      Suppress all console output.
   */
  constructor(options = {}) {
    this.#opts = {
      apiKey: process.env.SHIELDLY_API_KEY,
      outDir: 'cdk.out',
      failOn: 'High',
      silent: false,
      ...options,
    };

    // Register after CDK's own beforeExit (which fires app.synth()).
    // Node.js fires beforeExit listeners in registration order, so CDK synthesizes
    // first, then we analyze the resulting assembly directory.
    // The async work here keeps the event loop alive until analysis completes.
    process.on('beforeExit', async () => {
      if (this.#ran) return;
      this.#ran = true;

      const { outDir, ...analyzeOptions } = this.#opts;
      try {
        const { failed } = await analyzeAssembly(outDir, analyzeOptions);
        if (failed) process.exit(1);
      } catch (err) {
        if (!this.#opts.silent) {
          console.error(`\n[Shieldly] Error during analysis: ${err.message}`);
        }
        if (this.#opts.failOn !== 'none') process.exit(1);
      }
    });
  }
}

/**
 * Analyze a CDK CloudAssembly output directory for security issues.
 *
 * @param {string} assemblyDir  Path to the CDK output directory (e.g. 'cdk.out' or assembly.directory).
 * @param {object} [options]
 * @param {string} [options.apiKey]       Shieldly API key. Defaults to SHIELDLY_API_KEY env var.
 * @param {'Critical'|'High'|'Medium'|'Low'|'none'} [options.failOn]  Default: 'High'.
 * @param {string} [options.apiUrl]       Override API base URL.
 * @param {boolean} [options.silent]      Suppress all console output.
 * @returns {Promise<{results: Array, failed: boolean}>}
 */
export async function shieldlyGuard(assemblyDir, options = {}) {
  return analyzeAssembly(assemblyDir, {
    apiKey: process.env.SHIELDLY_API_KEY,
    ...options,
  });
}
