#!/usr/bin/env node
// Generate ready-to-publish npm packages for yorishiro-proxy from the
// cross-compiled Go binaries produced by .github/workflows/release.yml.
//
// This is the SINGLE SOURCE OF TRUTH for the GOOS/GOARCH -> npm os/cpu mapping
// and the platform list. The `release.yml` TARGETS array and this table must
// agree (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64).
//
// Usage:
//   node npm/generate.mjs --version v0.16.0 --dist ./dist --out ./npm-dist
//
//   --version   git tag string, INCLUDING the leading `v` (e.g. v0.16.0).
//               Used verbatim to locate the binary files; the leading `v` is
//               stripped ONLY for the npm `version` field.
//   --dist      directory containing the release binaries named exactly
//               `yorishiro-proxy-<version>-<goos>-<goarch>[.exe]`.
//   --out       output directory; 6 package dirs (1 parent + 5 children) are
//               written under it, each ready for `npm publish`.
//
// Outputs (relative to --out):
//   yorishiro-proxy/                 parent (bin/cli.js + optionalDependencies)
//   yorishiro-proxy-linux-x64/       child (bundled binary, os/cpu)
//   yorishiro-proxy-linux-arm64/
//   yorishiro-proxy-darwin-x64/
//   yorishiro-proxy-darwin-arm64/
//   yorishiro-proxy-win32-x64/

import { readFileSync, writeFileSync, mkdirSync, copyFileSync, rmSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Single source of truth: GOOS/GOARCH -> npm os/cpu.
// Each row is fully spelled out so the mapping is auditable at a glance.
//   windows -> win32, amd64 -> x64; linux/darwin/arm64/x64 pass through.
// ---------------------------------------------------------------------------
const PLATFORMS = [
  { goos: 'linux', goarch: 'amd64', os: 'linux', cpu: 'x64' },
  { goos: 'linux', goarch: 'arm64', os: 'linux', cpu: 'arm64' },
  { goos: 'darwin', goarch: 'amd64', os: 'darwin', cpu: 'x64' },
  { goos: 'darwin', goarch: 'arm64', os: 'darwin', cpu: 'arm64' },
  { goos: 'windows', goarch: 'amd64', os: 'win32', cpu: 'x64' },
];

const SCOPE = '@usk6666';
const PARENT_NAME = `${SCOPE}/yorishiro-proxy`;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--version') out.version = argv[++i];
    else if (a === '--dist') out.dist = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  const missing = ['version', 'dist', 'out'].filter((k) => !out[k]);
  if (missing.length) {
    console.error(`missing required argument(s): ${missing.map((m) => '--' + m).join(', ')}`);
    console.error('usage: node npm/generate.mjs --version v0.16.0 --dist ./dist --out ./npm-dist');
    process.exit(2);
  }
  return out;
}

// Strip a single leading `v` for the npm version field. The binary-file lookup
// keeps the un-stripped tag string.
function npmVersion(tag) {
  return tag.replace(/^v/, '');
}

function writeJSON(path, obj) {
  writeFileSync(path, JSON.stringify(obj, null, 2) + '\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const tag = args.version;
  const version = npmVersion(tag);
  const distDir = args.dist;
  const outDir = args.out;

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const childReadmeTemplate = readFileSync(join(__dirname, 'child.template', 'README.md'), 'utf8');

  // ---- children ----------------------------------------------------------
  const optionalDependencies = {};
  for (const p of PLATFORMS) {
    const pkgShortName = `yorishiro-proxy-${p.os}-${p.cpu}`;
    const pkgName = `${SCOPE}/${pkgShortName}`;
    const isWin = p.os === 'win32';
    const binFile = isWin ? 'yorishiro-proxy.exe' : 'yorishiro-proxy';

    const srcName = `yorishiro-proxy-${tag}-${p.goos}-${p.goarch}${isWin ? '.exe' : ''}`;
    const srcPath = join(distDir, srcName);

    const pkgDir = join(outDir, pkgShortName);
    const binDir = join(pkgDir, 'bin');
    mkdirSync(binDir, { recursive: true });

    const destPath = join(binDir, binFile);
    copyFileSync(srcPath, destPath);
    // Ensure the binary is executable (npm preserves file mode on publish).
    if (!isWin) chmodSync(destPath, 0o755);

    writeJSON(join(pkgDir, 'package.json'), {
      name: pkgName,
      version,
      description: `yorishiro-proxy prebuilt binary for ${p.os}-${p.cpu}`,
      homepage: 'https://github.com/usk6666/yorishiro-proxy#readme',
      repository: {
        type: 'git',
        url: 'git+https://github.com/usk6666/yorishiro-proxy.git',
      },
      license: 'Apache-2.0',
      author: 'usk6666',
      os: [p.os],
      cpu: [p.cpu],
      bin: {
        'yorishiro-proxy': `bin/${binFile}`,
      },
      files: ['bin'],
      publishConfig: {
        access: 'public',
      },
    });

    writeFileSync(
      join(pkgDir, 'README.md'),
      childReadmeTemplate
        .replaceAll('{{PKG_NAME}}', pkgName)
        .replaceAll('{{OS}}', p.os)
        .replaceAll('{{CPU}}', p.cpu)
    );

    optionalDependencies[pkgName] = version;
    console.log(`child:  ${pkgName}@${version}  (bin: ${srcName})`);
  }

  // ---- parent ------------------------------------------------------------
  const parentSrcDir = join(__dirname, 'parent');
  const parentBase = JSON.parse(readFileSync(join(parentSrcDir, 'package.json'), 'utf8'));
  parentBase.version = version;
  parentBase.optionalDependencies = optionalDependencies;

  const parentDir = join(outDir, 'yorishiro-proxy');
  mkdirSync(join(parentDir, 'bin'), { recursive: true });
  writeJSON(join(parentDir, 'package.json'), parentBase);
  copyFileSync(join(parentSrcDir, 'bin', 'cli.js'), join(parentDir, 'bin', 'cli.js'));
  chmodSync(join(parentDir, 'bin', 'cli.js'), 0o755);
  copyFileSync(join(parentSrcDir, 'README.md'), join(parentDir, 'README.md'));

  console.log(`parent: ${PARENT_NAME}@${version}  (optionalDependencies: ${PLATFORMS.length})`);
  console.log(`\nDone. ${PLATFORMS.length + 1} packages written to ${outDir}`);
}

main();
