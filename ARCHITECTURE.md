# snpm (Safe NPM): architecture and implementation map

## Safety contract

Registry metadata, package cache, quarantined payloads, staging, audit log, and temporary `snpx` installs are under the project root in `.snpm/`. The intended project-root mutations are `snpm.lock` and the final `node_modules` swap. Lifecycle scripts are never executed.

The 12-hour gate is mandatory in both user-facing resolution and install. First calculate the normal semver candidate list, newest first. Then choose the highest candidate whose registry `time[version]` is at least 12 hours old and not future-dated. Missing/invalid timestamps fail closed. Fallback only walks versions inside the original range; configuration cannot lower the age threshold.

## Install lifecycle

```text
package.json
  -> recursive resolver + bounded full-packument fetch/cache
  -> semver range candidates -> mandatory 12h selector -> resolved graph
  -> bounded tarball fetch -> SRI verification
  -> ClamAV INSTREAM + decompressed-entry heuristic triage
  -> bounded gzip/tar parser (checksum/path/link validation)
  -> project-local staging -> package store + dependency/bin links
  -> atomic-ish node_modules tree swap with previous-tree rollback on rename failure
  -> deterministic snpm.lock + hash-chained audit entry
```

No archive file is extracted to `node_modules` before verification. Tarball buffer is reused by the hasher, scanner, and extractor. Size caps bound transfer and decompression. ClamAV receives `zINSTREAM\0`, repeated big-endian 32-bit lengths plus chunks, then a zero terminator. High-signal heuristic findings or antivirus detections stop the install; infected tarballs are retained in `.snpm/quarantine`.

## Platform policy

Linux/macOS default to configurable common ClamAV socket candidates. Windows has no Unix-socket default and supports configured named-pipe paths or `tcp://host:3310`. Path checks normalize slash styles and reject drive-root/backslash traversal. The CLI uses Bun for subprocess execution and emits `.cmd` launchers on Windows, executable links on POSIX.

## Current implementation and gaps

Implemented: bounded registry transport/cache, recursive semver resolution, aliases, optional dependencies/platform filtering, peer warnings, deterministic lock generation, fixed quarantine gate, SRI, scanner fallback, restrictive staged extraction, audit log, basic `snpm install` and `snpx`.

Not implemented: lockfile replay/frozen install, auto-install of peers, workspaces, overrides, bundled dependencies, `.npmrc` authentication, publish/pack/audit/global commands, complete CLI compatibility, lifecycle hooks in a sandbox, and full `npx` options. This is not yet a drop-in npm replacement. Runtime/typecheck and real cross-OS validation still need Bun-enabled CI; the current sandbox lacked Bun and TypeScript.
