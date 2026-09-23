# snpm (Safe NPM): Phase 1 Architectural Map

Status: Phase 1 (blueprint). Repo was empty at scan time (no commits, no refs). Initialized clean.

## 0. Spec corrections (read first)

| Spec item | Reality | Decision |
|---|---|---|
| `Bun.fetch` | Bun has no `Bun.fetch`; it exposes the WHATWG global `fetch` (Bun-native impl). | Use global `fetch` behind `utils/transport.ts`. |
| `Bun.peek` | Synchronously reads a *settled Promise's* value. Not an I/O primitive. | Used only in the worker pool to skip a microtask hop on already-settled cache hits. |
| "SIMD string ops" | Bun doesn't expose SIMD directly. `Buffer.indexOf`, `Bun.CryptoHasher`, `Bun.gunzipSync` are native (Zig/C) and SIMD-backed internally. | Heuristic scanner uses `Uint8Array`/`Buffer.indexOf` over decompressed bytes, never JS string regex on raw buffers for the hot path. |
| Scanning the `.tgz` | Regex on gzip bytes finds nothing. Obfuscated strings live inside compressed tar entries. | Heuristics run per decompressed tar entry. clamd gets the raw tgz (it unpacks archives itself when `ScanArchive yes`). |
| `/var/run/clamav/clamd.ctl` | Debian/Ubuntu default. Fedora/Arch use `/run/clamd.scan/clamd.sock`, macOS brew differs. | Configurable, with a probe list. |
| Biggest real-world npm attack vector | Install scripts (`preinstall`/`postinstall`), not tarball contents AV can catch. | `ignore-scripts` is ON by default. Allowlist per package in `snpm.config.json`. |

## 1. Hermetic boundary

Everything lives under the repo root (`snpm/`). No writes to `~/.npm`, `~/.bun`, `/tmp`.

```
snpm/
├── src/{cli,core,security,utils}/ + index.ts
├── tests/{unit,integration,e2e,fixtures}/
├── .snpm/                    # runtime state (gitignored)
│   ├── cache/content/sha512/ # content-addressed tarballs (integrity-keyed)
│   ├── cache/meta/           # packuments + ETag, TTL 5 min
│   ├── staging/<txid>/       # extraction sandbox, never node_modules
│   ├── quarantine/           # rejected tarballs + JSON verdict (forensics)
│   └── audit.log             # NDJSON security events, hash-chained
├── snpm.config.json
├── snpm.lock
├── package.json, tsconfig.json, bunfig.toml
```

Path guard: `utils/fs-layout.ts` exposes `resolveInside(root, p)`, which `realpath`s and rejects anything escaping `root` (defeats `../` and symlink tar entries). Every write goes through it.

## 2. Lifecycle: `snpm install`

```
[cli] parse argv -> load config -> acquire lockfile mutex (.snpm/lock.pid)
   |
[core/resolver] read package.json (+ snpm.lock if present, frozen mode trusts pinned integrity)
   |  BFS over dependency graph, dedup by name@range
   v
[utils/transport] GET /<name> (Accept: application/json full packument, NOT corgi: corgi omits `time`)
   |  bounded pool (meta: 16 concurrent), retry w/ jitter, AbortSignal.timeout
   v
[core/manifest] validate shape -> Packument {versions, time, dist-tags}
   v
[security/quarantine] filter versions: satisfies(range) && age(time[v]) >= 12h && !deprecated
   |  pick max. if top candidate was blocked -> stderr WARN. if none -> QuarantineViolationError
   v
[core/resolver] recurse into chosen version's dependencies (+ optional/peer policy)
   v   graph frozen
[utils/transport] GET dist.tarball (pool: 8 concurrent, byte budget 256 MB in flight)
   v
[security/integrity] Bun.CryptoHasher sha512 == dist.integrity (SRI) else IntegrityMismatchError
   v
[security/scanner] clamd INSTREAM(raw tgz)  ||  fallback heuristics
   |  + always: heuristics on decompressed entries + package.json script audit
   |  INFECTED -> move to .snpm/quarantine, abort tx, exit 3
   v
[utils/untar] gunzip -> tar parse in memory -> path-guarded write to .snpm/staging/<txid>/<name>
   v
[core/linker] atomic rename staging -> node_modules/<name>, create .bin symlinks
   v
[core/lockfile] write snpm.lock (tmp + rename), append audit.log, release mutex
```

Failure anywhere before the linker = zero changes to `node_modules`. The transaction id (`txid`) scopes staging, so a crash leaves only garbage in `.snpm/staging`, swept on next run.

## 3. Data structures

```ts
interface Packument {
  name: string;
  'dist-tags': Record<string, string>;
  versions: Record<string, VersionManifest>;
  time: Record<string, string>; // ISO 8601; keys: created, modified, <version>
}
interface VersionManifest {
  name: string; version: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  deprecated?: string;
  dist: { tarball: string; integrity?: string; shasum: string; attestations?: { url: string } };
}
interface ResolvedNode {
  name: string; version: string; integrity: string; tarball: string;
  publishedAt: number; // epoch ms
  deps: Map<string, string>; // name -> resolved version
  quarantineSkipped: string[]; // versions rejected by time gate
}
type ScanVerdict =
  | { kind: 'clean'; engine: 'clamd' | 'heuristic' }
  | { kind: 'infected'; engine: 'clamd' | 'heuristic'; signature: string; file?: string }
  | { kind: 'suspicious'; findings: HeuristicFinding[] }; // policy decides: warn or block
```

## 4. Buffer layouts

**Tarball in memory:** one `Uint8Array` per package (npm tarballs are typically < 5 MB; hard cap `maxTarballBytes` = 50 MB, else `TarballTooLargeError`). Held once, shared by reference across hasher, clamd writer, and gunzip. No copies.

**clamd INSTREAM framing** (`zINSTREAM\0` command):

```
+----------------+----------------------+
| u32 BE length  | chunk bytes (<= 64K) |   repeated
+----------------+----------------------+
| 00 00 00 00    |                          terminator
```

Reply: `stream: OK\0` | `stream: <Sig> FOUND\0` | `INSTREAM size limit exceeded. ERROR\0`. Chunk size 64 KiB, must stay under clamd `StreamMaxLength` (default 25 MB total, configurable; oversize => fallback to heuristic + warn, never silent pass).

**Tar entries (ustar):** 512-byte header blocks; parse `name`(0..100), `size`(124..136 octal), `typeflag`(156), `prefix`(345..500). Only typeflag `0`/`\0` (file) and `5` (dir) accepted. Symlinks/hardlinks (`1`,`2`) rejected. Strip leading `package/`.

## 5. Quarantine gate semantics

```
age(v) = now - Date.parse(time[v])
eligible(v) = semver.satisfies(v, range) && age(v) >= minAgeMs && Number.isFinite(age)
```

- `minAgeMs` default 12h, configurable (`quarantine.minAgeHours`).
- Missing/unparseable `time[v]` => version treated as ineligible (fail closed) + `MalformedMetadataError` logged, not thrown, unless no candidate remains.
- Future timestamps (clock skew or poisoned mirror) => ineligible.
- Clock source: `Date.now()`, optionally cross-checked with registry `Date` response header; skew > 5 min => warning.
- Prerelease versions only when range explicitly includes them (node-semver semantics, via `Bun.semver.satisfies`).
- Lockfile replays re-check the gate (a pinned version published 1h ago in a fresh lock still blocks).
- `QuarantineViolationError` exit code 4. `--allow-fresh <pkg>` escape hatch, audit-logged.

stderr format (single line, grep-able, plus a boxed human view in TTY):

```
[SNPM-SECURITY] QUARANTINE_BLOCK pkg=left-pad@1.4.0 age=00:05:12 min=12:00:00 fallback=1.3.0 sha512=<first16>
```

"Cryptographic" warning = the event line carries the tarball integrity digest and is appended to the hash-chained `audit.log` (`entry.prev = sha256(prevEntry)`), so tampering with history is detectable.

## 6. Scanner design

```ts
interface Scanner { readonly name: string; available(): Promise<boolean>; scan(buf: Uint8Array, ctx: ScanCtx): Promise<ScanVerdict>; }
```

- `ClamdScanner`: `Bun.connect({ unix: socketPath, socket: {...} })`. PING/PONG probe on startup (200 ms timeout). Per-scan timeout 30 s. Socket error mid-stream => `AntivirusSocketDropError` => retry once on fresh socket => fallback.
- `HeuristicScanner`: runs on each decompressed JS/TS/JSON/sh entry. Indicators weighted, not binary:
  - `eval(` + `atob(`/`Buffer.from(..., 'base64')` co-occurring (high)
  - `process.env` serialized and passed to `fetch`/`http.request`/`dns.lookup` (high)
  - `child_process` in install scripts (high)
  - long base64/hex blobs > 2 KB in a single line (medium)
  - access to `~/.npmrc`, `~/.ssh`, `.aws/credentials`, wallet paths (high)
  - `new Function(` with dynamic string (medium)
  Score >= block threshold => infected; mid => suspicious.
- Degradation policy (`scanner.mode`): `strict` (clamd required, else fail), `auto` (default: clamd, fallback heuristics, stderr warning once), `heuristic-only`.
- Honest caveat: heuristics are a speed bump, not an AV. They catch lazy payloads (the eslint-scope/ua-parser-js style), not targeted ones.

## 7. Concurrency model

`utils/pool.ts`: a semaphore-based `BoundedPool<T>` with two limits: slot count and byte budget. Tasks `acquire(bytesEstimate)` using `content-length` (or `dist.unpackedSize` hint). Backpressure blocks the producer (resolver BFS), not memory. In-flight promise map dedups identical `name@version` fetches; `Bun.peek` returns settled cache hits synchronously.

Limits (defaults): metadata 16, tarballs 8, clamd scans 4 (clamd `MaxThreads` default 10), fs writes 32. Retry: 3 attempts, exponential backoff 200ms * 2^n + jitter, only on network errors/5xx/429 (honor `Retry-After`).

## 8. Error matrix

| Error | Exit | Retry | Degrade |
|---|---|---|---|
| `RegistryTimeoutError` | 5 | yes | use cached meta if < 24h, warn |
| `NetworkUnavailableError` | 5 | yes | offline mode with lockfile + content cache only |
| `MalformedMetadataError` | 6 | no | skip version, fail if none |
| `QuarantineViolationError` | 4 | no | `--allow-fresh` |
| `IntegrityMismatchError` | 3 | once (refetch) | never |
| `MalwareDetectedError` | 3 | no | never |
| `AntivirusSocketDropError` | n/a | once | heuristic fallback (auto mode) |
| `AntivirusUnavailableError` | 7 (strict) | no | heuristic (auto) |
| `PathTraversalError` | 3 | no | never |
| `TarballTooLargeError` | 8 | no | config override |

All extend `SnpmError { code: string; exitCode: number; cause?: unknown }`. Exit 0 ok, 1 unknown, 2 usage.

## 9. Output channels

- stdout: progress, spinner (TTY only, `setInterval` 80ms, cleared on exit/SIGINT), summary table. `--json` switches to NDJSON.
- stderr: `[SNPM-SECURITY]` lines only + fatal errors. Never animated, never colored when `!process.stderr.isTTY`.

## 10. Module map

```
src/cli/        args.ts, render.ts (spinner, colors), exit.ts
src/core/       resolver.ts, manifest.ts, lockfile.ts, linker.ts, graph.ts
src/security/   quarantine.ts, integrity.ts, clamd.ts, heuristics.ts, scanner.ts, audit-log.ts, scripts-policy.ts
src/utils/      transport.ts, pool.ts, untar.ts, fs-layout.ts, errors.ts, clock.ts (injectable for tests)
src/index.ts
```

`clock.ts` and `transport.ts` are injected (constructor params), which is what makes the 5-minute zero-day and dead-network tests deterministic without monkeypatching globals.

## 11. Test plan (Phase 3 preview)

1. Zero-day: fake packument, `1.2.0` published `now - 5min`, `1.1.9` published `now - 3d`, range `^1.1.0` => resolves `1.1.9`, stderr has `QUARANTINE_BLOCK`. Range `1.2.0` exact => `QuarantineViolationError`, exit 4.
2. Malware: EICAR test string inside a synthetic tgz => clamd `Eicar-Signature FOUND` (integration, skipped if no clamd) and heuristic fixture `eval(atob(...))` + `process.env` exfil => `MalwareDetectedError`, nothing in `node_modules`, tarball in `.snpm/quarantine`.
3. Degradation: mock unix socket server that closes mid-INSTREAM => `AntivirusSocketDropError` then heuristic fallback, warning on stderr. Transport that rejects all => `NetworkUnavailableError`, exit 5, `node_modules` untouched.

## 12. Phase gates

- P2: package.json/tsconfig (done in scaffold), transport, pool, manifest parser, resolver.
- P3: quarantine, integrity, clamd, heuristics, untar, linker, test harness.
