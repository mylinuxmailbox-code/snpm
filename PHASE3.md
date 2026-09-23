# Phase 3: secure install path

`snpm install` resolves through the mandatory 12-hour selector, downloads under configured slot/byte limits, verifies the strongest supported SRI digest, and triages each package before extraction. ClamAV receives INSTREAM data; heuristics inspect decompressed archive entries too. `auto` warns on daemon failure and degrades to heuristics; `strict` fails closed.

Tar processing is restrictive: gzip output, total size, entry count, and path lengths are capped; checksums are validated; traversal, links, truncation, malformed sizes, and unsupported records are rejected. Clean package bytes go to project-local staging. Only after the full graph passes verification does snpm replace `node_modules`; existing modules are backed up and restored on rename failure. Infected tarballs are retained under `.snpm/quarantine`. Security and transaction records use a verified hash chain.

The linker stores package contents beneath `node_modules/.snpm-store`, builds dependency links and root `.bin` launchers, and emits Windows `.cmd` shims or executable POSIX links. `snpx <package>[@range] [args...]` creates/reuses an isolated tool install under `.snpm/snpx` and starts its JS binary with Bun without shell-string evaluation. Lifecycle scripts are never run.

## Cross-platform policy

Linux/macOS use configurable ClamAV socket candidates. Windows has no Unix-only default: configure a named pipe path or `tcp://host:3310`. Paths normalize slash styles, Windows gets explicit command shims, and process execution uses Bun. Cross-platform configuration and quarantine behavior are covered by target-platform tests.

## Test evidence and caveat

The available unit suite covers packument parsing, bounded pools, registry failure/revalidation, recursive resolution, range-preserving quarantine selection, SRI tampering, archive checksums/traversal/links, malware heuristics, dead-daemon fallback, audit-chain tampering, and platform configuration. A local mock-registry smoke test installed one package and produced `snpm.lock`, project-local cache/audit state, and a `.bin` link.

The sandbox did not have Bun or TypeScript installed, so tests were run using Node's TypeScript transform and a Bun API shim, not real `bun test` or `tsc`. A GitHub Actions matrix was not committed because the connected GitHub credential lacks workflow-write permission; actual Bun typecheck and multi-OS runs are still required.

## Explicit npm compatibility gap

This is a secure-install prototype, not complete npm parity. Missing: frozen lockfile replay, automatic peer installation, workspaces/overrides/bundled dependencies, `.npmrc` auth compatibility, publish/pack/audit/owner/global commands, lifecycle execution in a sandbox, full npm flags, and full `npx --package` or multi-package syntax. `snpx` is only the initial single-package runner. Script execution stays disabled until a real sandbox exists.
