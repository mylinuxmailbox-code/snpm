# snpm

Safe NPM on Bun: 12h quarantine, integrity-first resolution, clamd/heuristic scanning, staged extraction, and install scripts off by default.

```sh
bun install && bun run typecheck && bun test
bun run src/index.ts resolve
```

Phase 2 now enforces the 12-hour gate during version selection: it resolves the requested semver range normally, then walks backward only within that range. A fresh `2.1.0` can fall back to old `2.0.9` for `^2.0.0`; it cannot fall back to `2.0.9` for `^2.1.0`. No eligible version means `QuarantineViolationError`.

Platform policy is explicit for Linux, macOS and Windows. Unix ClamAV paths are configurable, Windows requires a configured endpoint, and terminal/signal behavior avoids Unix-only assumptions.

- [x] Phase 1: architecture map and hermetic scaffold
- [x] Phase 2: bounded transport, packument parser, registry cache, resolver, lockfile, mandatory quarantine selector, platform matrix
- [ ] Phase 3: integrity verification, clamd INSTREAM, heuristic scanner, staged untar, linker

`snpm install` remains disabled until Phase 3 lands. Resolving without scanning is okay; installing without it is not.
