# @shieldly/cdk-guard

**AI-Powered AWS security analysis for CDK apps.** Catch risky IAM policies and
CloudFormation misconfigurations on every `cdk synth` — before you deploy.

[![npm](https://img.shields.io/npm/v/@shieldly/cdk-guard)](https://www.npmjs.com/package/@shieldly/cdk-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```bash
npm install --save-dev @shieldly/cdk-guard
```

Get an API key at **[shieldly.io/app/api](https://www.shieldly.io/app/api)**
(API keys require a Builder plan or above; a free demo runs without a key).

> **Privacy:** your CDK templates are never logged. Cache keys are one-way
> SHA-256 hashes.

---

## Ways to use it

### 1. CLI — no code changes (any language CDK app)

Runs `cdk synth` then analyzes all synthesized stacks:

```bash
npx @shieldly/cdk-guard
```

```bash
# Pass extra cdk synth flags after --
npx @shieldly/cdk-guard -- --context env=prod

# Fail only on Critical findings
npx @shieldly/cdk-guard --fail-on Critical

# Analyze an existing cdk.out/ without re-synthesizing
npx @shieldly/cdk-guard --no-synth --out-dir cdk.out

# JSON output for scripting
npx @shieldly/cdk-guard --format json | jq '.[].findings[]'
```

Set your API key via environment variable:

```bash
export SHIELDLY_API_KEY=sk_live_...
npx @shieldly/cdk-guard
```

---

### 2. CDK Construct — hook-based (JavaScript/TypeScript CDK apps)

Add `ShieldlyGuard` to your CDK app. It runs automatically after `cdk synth`
via `process.on('beforeExit')` — no explicit call needed.

```js
import * as cdk from 'aws-cdk-lib';
import { ShieldlyGuard } from '@shieldly/cdk-guard';

const app = new cdk.App();

// Add the guard — reads SHIELDLY_API_KEY from environment by default.
new ShieldlyGuard({
  failOn: 'High',  // Critical | High | Medium | Low | none
});

new MyStack(app, 'MyStack');
// Guard analyzes cdk.out/ automatically when the process exits.
```

**Options:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `apiKey` | `string` | `SHIELDLY_API_KEY` env | Shieldly API key |
| `failOn` | `string` | `'High'` | Exit code 1 if findings at or above this severity |
| `outDir` | `string` | `'cdk.out'` | CDK output directory to analyze |
| `apiUrl` | `string` | `https://api.shieldly.io` | Override for self-hosted / dev |
| `silent` | `boolean` | `false` | Suppress all console output |

---

### 3. Explicit post-synth (ESM with top-level await)

```js
import * as cdk from 'aws-cdk-lib';
import { shieldlyGuard } from '@shieldly/cdk-guard';

const app = new cdk.App();
const stack = new MyStack(app, 'MyStack');
const assembly = app.synth();

const { failed } = await shieldlyGuard(assembly.directory, {
  failOn: 'High',
});
if (failed) process.exit(1);
```

---

### 4. cdk.json hook

Runs analysis after every `cdk synth` automatically — works with any CDK language:

```json
{
  "app": "node bin/my-app.js",
  "hooks": {
    "afterSynth": ["npx", "@shieldly/cdk-guard", "--no-synth"]
  }
}
```

---

## CI / CD

### GitHub Actions

```yaml
- name: CDK security check
  run: npx @shieldly/cdk-guard
  env:
    SHIELDLY_API_KEY: ${{ secrets.SHIELDLY_API_KEY }}
```

### package.json scripts

```json
{
  "scripts": {
    "synth:check": "cdk synth && npx @shieldly/cdk-guard --no-synth",
    "deploy:safe": "npx @shieldly/cdk-guard && cdk deploy"
  }
}
```

---

## How it works

1. Reads the CDK manifest (`cdk.out/manifest.json`) to find synthesized stack
   templates for the current synthesis only (not stale outputs from prior runs).
2. Sends each `*.template.json` to the Shieldly AI analysis engine
   (`POST /v1/analyze/cf`).
3. The AI analyzes IAM roles, policies, resource policies, and CloudFormation
   security configurations, explaining each finding in plain English and
   providing the tightened policy.
4. Prints results to the terminal. Exits with code `1` if any finding meets or
   exceeds the `failOn` severity threshold.

---

## What it analyzes

- IAM roles and managed policies
- Inline policies on Lambda functions, EC2 instances, ECS tasks
- Resource policies (S3 bucket policies, SQS queue policies, KMS key policies)
- CloudFormation security misconfigurations (public S3 buckets, unencrypted
  resources, overly permissive security groups)

---

## Related

- **[shieldly.io](https://www.shieldly.io)** — web-based IAM Advisor (free demo, no signup)
- **[@shieldly/cli](https://www.npmjs.com/package/@shieldly/cli)** — analyze from any terminal
- **[shieldly-io/action](https://github.com/shieldly-io/action)** — GitHub Action for PR gating
- **VS Code extension** — search "Shieldly" in the Marketplace
- **[REST API](https://www.shieldly.io/docs/api)** — integrate into any pipeline

---

## Free tools & references (no signup)

No account required — these run in your browser or document the risks:

- **[IAM Privilege Escalation Cheat Sheet](https://www.shieldly.io/iam/cheatsheet?utm_source=github&utm_medium=readme)** — every common escalation path on one page, with fixes
- **[Free browser tools](https://www.shieldly.io/tools?utm_source=github&utm_medium=readme)** — IAM policy linter, trust policy explainer, S3 bucket policy checker, CloudFormation IAM checker
- **[IAM privilege escalation reference](https://www.shieldly.io/iam?utm_source=github&utm_medium=readme)** — each method with a vulnerable policy, the exploit, and the fix

---

*Amazon Web Services (AWS) is a trademark of Amazon.com, Inc. Shieldly is not
affiliated with, endorsed by, or sponsored by Amazon Web Services.*
