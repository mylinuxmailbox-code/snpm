# snpm

Safe NPM on Bun. Phase 3 adds the secure install path: a mandatory 12-hour semver-range quarantine gate, SRI verification, ClamAV INSTREAM when configured, heuristic triage, restrictive staged archive extraction, project-local content cache, transaction-style `node_modules` swap, and basic `snpx`.

```sh
bun install
bun run typecheck
bun test
bun run src/index.ts install
bun run src/index.ts snpx <package>[@range] [args...]
```

Safety defaults: install lifecycle scripts are never executed; missing/future publication timestamps fail closed; tarballs are size-capped, integrity-checked, scanned before extraction, and path/link validated; all cache, staging, audit, quarantine artifacts, and ephemeral snpx installs stay under the project `.snpm` directory. Linux/macOS have configurable ClamAV socket candidates; Windows uses explicit named-pipe or TCP configuration. `strict` scanner mode fails closed; `auto` warns before heuristic fallback.

## Compatibility status

This is **not yet a complete npm replacement**. Implemented: registry dependency resolution, semver, npm aliases, optional dependency/platform filtering, peer warnings, deterministic lock generation, secure install, disabled lifecycle scripts, package bin launchers, and basic `snpx <package> [args]`.

Missing: frozen lockfile replay, automatic peer installation, npm workspaces, overrides, bundled dependencies, `.npmrc` auth compatibility, publish/pack/audit/owner/global commands, lifecycle execution in a real sandbox, full npm CLI options, and npx `--package`/multi-package syntax. Those require separate conformance phases. We are not claiming drop-in parity yet.

- [x] Phase 1: architecture map and hermetic scaffold
- [x] Phase 2: bounded transport, full packument parser/cache, recursive resolver, lockfile, mandatory age selector
- [x] Phase 3 initial: SRI, ClamAV/heuristics, safe staged install, audit chain, basic snpx
- [ ] npm compatibility/conformance work
- [ ] Add cross-platform GitHub Actions workflow (the connected credential cannot write workflow files)
