import { readFileSync } from 'node:fs';
import { build } from 'esbuild';

const { version } = JSON.parse(readFileSync('./package.json', 'utf8'));
const dev = process.argv.includes('--dev');

build({
  entryPoints: ['src/bin.js'],
  bundle: true,
  platform: 'node',
  target: 'node22',
  outfile: 'dist/cdk-guard.cjs',
  format: 'cjs',
  banner: { js: '#!/usr/bin/env node' },
  define: { __CG_VERSION__: JSON.stringify(version) },
  minify: !dev,
  sourcemap: dev ? 'inline' : false,
}).catch(() => process.exit(1));
