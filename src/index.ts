#!/usr/bin/env bun
import { isSnpmError } from './utils/errors.ts';

async function main(argv: readonly string[]): Promise<number> {
  const [cmd] = argv;
  switch (cmd) {
    case 'install':
    case 'i':
      process.stdout.write('snpm install: resolver lands in Phase 2\n');
      return 0;
    case undefined:
    case '--help':
      process.stdout.write('usage: snpm install [--allow-fresh <pkg>] [--json]\n');
      return 0;
    default:
      process.stderr.write(`unknown command: ${cmd}\n`);
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
    process.stderr.write(`[SNPM] fatal: ${String(err)}\n`);
    process.exit(1);
  },
);
