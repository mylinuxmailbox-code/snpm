#!/usr/bin/env bun
import { runResolve } from './cli/resolve.ts';
import { isSnpmError } from './utils/errors.ts';

const USAGE = `usage:
  snpm resolve [--json] [--production] [--no-lock]   resolve graph + write snpm.lock
  snpm install                                        (Phase 3: quarantine + scan + extract)
`;

async function main(argv: readonly string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const flag = (f: string): boolean => rest.includes(f);
  switch (cmd) {
    case 'resolve':
      return runResolve(process.cwd(), { json: flag('--json'), production: flag('--production'), writeLock: !flag('--no-lock') });
    case 'install':
    case 'i':
      process.stderr.write('snpm install is disabled until the Phase 3 security pipeline lands. Use `snpm resolve`.\n');
      return 2;
    case undefined:
    case '--help':
    case '-h':
      process.stdout.write(USAGE);
      return 0;
    default:
      process.stderr.write(`unknown command: ${cmd}\n${USAGE}`);
      return 2;
  }
}

main(Bun.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    if (isSnpmError(err)) {
      process.stderr.write(`[SNPM] ${err.code}: ${err.message}\n`);
      process.exit(err.exitCode);
    }
    process.stderr.write(`[SNPM] fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exit(1);
  },
);
