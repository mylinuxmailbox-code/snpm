#!/usr/bin/env bun
import { runResolve } from './cli/resolve.ts';
import { runInstall } from './cli/install.ts';
import { runSnpx } from './cli/snpx.ts';
import { isSnpmError } from './utils/errors.ts';
import { basename } from 'node:path';

const USAGE = `usage:
  snpm resolve [--json] [--production] [--no-lock]   resolve graph + write snpm.lock (mandatory 12h gate)
  snpm install [--production]                       secure install (12h gate, integrity, scan, stage)
  snpx <package>[@range] [args...]                   run a package binary in a project-local cache
`;
async function main(argv: readonly string[]): Promise<number> {
  const [cmd, ...rest] = argv; const flag = (f: string): boolean => rest.includes(f);
  switch (cmd) {
    case 'resolve': return runResolve(process.cwd(), { json: flag('--json'), production: flag('--production'), writeLock: !flag('--no-lock') });
    case 'install': case 'i': return runInstall(process.cwd(), flag('--production'));
    case 'snpx': return runSnpx(process.cwd(), rest);
    case undefined: case '--help': case '-h': process.stdout.write(USAGE); return 0;
    default: process.stderr.write(`unknown command: ${cmd}\n${USAGE}`); return 2;
  }
}
const argv = Bun.argv.slice(2);
const invokedAs = basename(Bun.argv[1] ?? '');
const action = invokedAs === 'snpx' || invokedAs === 'snpx.exe' ? runSnpx(process.cwd(), argv) : main(argv);
action.then((code) => process.exit(code), (err: unknown) => {
  if (isSnpmError(err)) { process.stderr.write(`[SNPM] ${err.code}: ${err.message}\n`); process.exit(err.exitCode); }
  process.stderr.write(`[SNPM] fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`); process.exit(1);
});
