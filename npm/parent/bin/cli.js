#!/usr/bin/env node
'use strict';

// Zero-dependency CLI shim for @usk6666/yorishiro-proxy.
//
// The real binary is delivered by one of the platform-specific optional
// dependencies (@usk6666/yorishiro-proxy-<os>-<cpu>). npm installs exactly the
// one child package whose `os`/`cpu` match the host and skips the rest. This
// shim resolves that child's bundled binary and re-executes it, forwarding all
// arguments and the exit status faithfully. There is NO postinstall step and NO
// network fetch at install time.

const { execFileSync } = require('node:child_process');

// Node's process.platform / process.arch already use the same spelling as npm's
// `os` / `cpu` fields (linux/darwin/win32 and x64/arm64), so the child package
// suffix is a direct read — no translation table needed on the runtime side.
const platform = process.platform;
const arch = process.arch;

const pkgName = `@usk6666/yorishiro-proxy-${platform}-${arch}`;
const binName = platform === 'win32' ? 'yorishiro-proxy.exe' : 'yorishiro-proxy';
const subpath = `${pkgName}/bin/${binName}`;

let binaryPath;
try {
  binaryPath = require.resolve(subpath);
} catch (err) {
  if (err && err.code === 'MODULE_NOT_FOUND') {
    process.stderr.write(
      `yorishiro-proxy: no matching platform package for ${platform}-${arch}.\n` +
        `\n` +
        `The optional dependency "${pkgName}" is not installed.\n` +
        `This usually means one of:\n` +
        `  - your platform is not supported (supported: linux-x64, linux-arm64, ` +
        `darwin-x64, darwin-arm64, win32-x64), or\n` +
        `  - your package manager skipped optional dependencies ` +
        `(e.g. --no-optional / --omit=optional).\n` +
        `\n` +
        `Reinstall without omitting optional dependencies, or download a binary ` +
        `from https://github.com/usk6666/yorishiro-proxy/releases\n`
    );
    process.exit(1);
  }
  throw err;
}

try {
  execFileSync(binaryPath, process.argv.slice(2), { stdio: 'inherit' });
} catch (err) {
  // execFileSync throws when the child exits non-zero or is killed by a signal.
  if (err && typeof err.status === 'number') {
    // Faithfully propagate the child's exit code.
    process.exit(err.status);
  }
  if (err && err.signal) {
    // The child was terminated by a signal; re-raise it on ourselves so the
    // parent shell observes the same termination cause.
    process.kill(process.pid, err.signal);
    return;
  }
  process.stderr.write(
    `yorishiro-proxy: failed to launch ${binaryPath}: ${(err && err.message) || err}\n`
  );
  process.exit(1);
}
