#!/usr/bin/env bun
import { runSnpx } from './cli/snpx.ts';
import { isSnpmError } from './utils/errors.ts';
runSnpx(process.cwd(), Bun.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    if (isSnpmError(err)) { process.stderr.write(`[SNPM] ${err.code}: ${err.message}\n`); process.exit(err.exitCode); }
    process.stderr.write(`[SNPM] fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`); process.exit(1);
  },
);
