# snpm

Safe NPM on Bun: 12h quarantine gate, integrity-first, clamd INSTREAM + heuristic scanning, staged extraction, install scripts off by default.

See [ARCHITECTURE.md](./ARCHITECTURE.md).

```sh
bun install && bun run typecheck && bun test
bun run src/index.ts resolve          # resolve graph, write snpm.lock
bun run src/index.ts resolve --json   # machine-readable graph
```

## Status

- [x] Phase 1: architecture map, hermetic scaffold, typed error matrix
- [x] Phase 2: bounded transport, packument parser, registry cache, recursive resolver, deterministic lockfile (`snpm resolve`)
- [ ] Phase 3: quarantine gate, integrity verify, clamd INSTREAM + heuristic scanner, staged untar, linker

`snpm install` is intentionally disabled until Phase 3 lands: resolving without the security pipeline is fine, installing without it is not.
