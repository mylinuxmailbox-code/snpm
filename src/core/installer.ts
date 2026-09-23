import { mkdir, rename, rm, symlink, cp, chmod } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Resolver, DEFAULT_RESOLVER_OPTIONS, type ResolvedGraph } from './resolver.ts';
import type { RootManifest } from './resolver.ts';
import type { Layout } from '../utils/fs-layout.ts';
import { resolveInside } from '../utils/fs-layout.ts';
import { BoundedPool } from '../utils/pool.ts';
import { HttpTransport } from '../utils/transport.ts';
import { TarballTooLargeError, MalwareDetectedError, UnsupportedSpecError } from '../utils/errors.ts';
import { verifyIntegrity } from '../security/integrity.ts';
import { scanPackage, type ScannerOptions, type PackageScan } from '../security/scanner.ts';
import type { ClamdTarget } from '../security/clamd.ts';
import { unpackTarball } from '../utils/tar.ts';
import { appendAudit } from '../security/audit-log.ts';
import { writeLockfile } from './lockfile.ts';
import { loadConfig } from './config.ts';
import { readRootManifest } from './project.ts';
import { FsMetaStore, RegistryClient as Registry, DEFAULT_REGISTRY_OPTIONS } from './registry.ts';
import { systemClock } from '../utils/clock.ts';
import { quarantineSelector } from './quarantine.ts';

export interface InstallOptions { readonly root: string; readonly production?: boolean; readonly frozen?: boolean; readonly scannerMode?: ScannerOptions['mode']; readonly clamdTarget?: ClamdTarget; }
export interface InstallSummary { readonly packages: number; readonly warnings: number; readonly lockfile: string; }
/** Transaction: resolve -> download -> verify -> scan -> extract to private staging -> commit. Scripts never run. */
export async function installProject(options: InstallOptions): Promise<InstallSummary> {
  const root = resolve(options.root); const layout = layoutForRoot(root); const config = await loadConfig(root);
  const registry = new Registry(new HttpTransport(), new BoundedPool(config.limits.metaConcurrency), new FsMetaStore(layout.metaCache), systemClock, { ...DEFAULT_REGISTRY_OPTIONS, registry: config.registry });
  const selector = quarantineSelector({ nowMs: systemClock.now(), minAgeMs: 12 * 3_600_000 });
  const resolver = new Resolver(registry, selector, { ...DEFAULT_RESOLVER_OPTIONS, includeDev: !options.production, platform: config.platform });
  const graph = await resolver.resolve(await readRootManifest(root));
  if (options.frozen) validateFrozenLock(layout.lockfile, graph);
  const tx = randomUUID(); const stage = join(layout.staging, tx);
  const targets = options.clamdTarget !== undefined ? [options.clamdTarget] : configuredClamdTargets(config.scanner.clamdSockets);
  const scannerOpts: ScannerOptions = { mode: options.scannerMode ?? config.scanner.mode, clamdTargets: targets, onFallback: (reason) => process.stderr.write(`[SNPM-WARN] CLAMAV_FALLBACK ${JSON.stringify(reason)}\n`), chunkBytes: config.scanner.chunkBytes, timeoutMs: config.scanner.scanTimeoutMs, tarLimits: { maxUnpackedBytes: 256 * 1024 * 1024, maxFiles: 20_000, maxPathBytes: 1024 } };
  const tarPool = new BoundedPool(config.limits.tarballConcurrency, config.limits.inFlightBytes);
  const verified = new Map<string, readonly ReturnType<typeof unpackTarball>[number][]>();
  try {
    await mkdir(stage, { recursive: true });
    await Promise.all([...graph.nodes.values()].map((node) => tarPool.run(async () => {
      const cacheFile = contentCachePath(layout.contentCache, node.integrity); let tarball = await readCachedTarball(cacheFile);
      if (tarball === undefined) {
        const response = await new HttpTransport().get(node.tarball, { accept: 'application/octet-stream', timeoutMs: 30_000, maxBytes: config.limits.maxTarballBytes });
        if (response.status !== 200) throw new Error(`tarball HTTP ${response.status}: ${node.tarball}`);
        if (response.body.byteLength > config.limits.maxTarballBytes) throw new TarballTooLargeError(node.key, response.body.byteLength, config.limits.maxTarballBytes);
        tarball = response.body;
      }
      verifyIntegrity(node.key, tarball, node.integrity); let scan: PackageScan;
      try { scan = await scanPackage(node.key, tarball, scannerOpts); }
      catch (err: unknown) {
        if (err instanceof MalwareDetectedError) {
          const quarantineKey = new Bun.CryptoHasher('sha256').update(`${node.key}:${Date.now()}`).digest('hex'); const quarantined = join(layout.quarantine, `${quarantineKey}.tgz`);
          await mkdir(dirname(quarantined), { recursive: true }); await Bun.write(quarantined, tarball);
          await appendAudit(layout.auditLog, { at: new Date().toISOString(), kind: 'malware-quarantine', package: node.key, detail: `${err.signature}; artifact=${quarantineKey}.tgz` });
        }
        throw err;
      }
      if (scan.verdict.kind === 'suspicious') await appendAudit(layout.auditLog, { at: new Date().toISOString(), kind: 'suspicious', package: node.key, detail: JSON.stringify(scan.verdict.findings) });
      verified.set(node.key, scan.files); await mkdir(dirname(cacheFile), { recursive: true }); await Bun.write(cacheFile, tarball);
    }, Math.max(config.limits.maxTarballBytes, node.unpackedSize ?? 0))));
    await writeNodeTree(stage, graph, verified); await commitTree(stage, layout.nodeModules, tx);
    const lockfile = await writeLockfile(layout.lockfile, graph); await appendAudit(layout.auditLog, { at: new Date().toISOString(), kind: 'install-commit', detail: `${graph.nodes.size} packages` });
    return { packages: graph.nodes.size, warnings: graph.warnings.length, lockfile };
  } catch (err: unknown) {
    await appendAudit(layout.auditLog, { at: new Date().toISOString(), kind: err instanceof MalwareDetectedError ? 'malware-block' : 'install-abort', detail: String(err) });
    await rm(stage, { recursive: true, force: true }); throw err;
  }
}
function configuredClamdTargets(endpoints: readonly string[]): NonNullable<ScannerOptions['clamdTargets']> {
  const targets: NonNullable<ScannerOptions['clamdTargets']>[number][] = [];
  for (const endpoint of endpoints) {
    if (endpoint.startsWith('tcp://')) { const url = new URL(endpoint); targets.push({ kind: 'tcp', hostname: url.hostname, port: url.port === '' ? 3310 : Number(url.port) }); }
    else targets.push({ kind: 'unix', path: endpoint });
  }
  return targets;
}
function contentCachePath(base: string, integrity: string): string { const key = new Bun.CryptoHasher('sha256').update(integrity).digest('hex'); return join(base, 'by-integrity', key.slice(0, 2), `${key}.tgz`); }
async function readCachedTarball(path: string): Promise<Uint8Array | undefined> { const file = Bun.file(path); if (!(await file.exists()) || file.size > 50 * 1024 * 1024) return undefined; return new Uint8Array(await file.arrayBuffer()); }
function layoutForRoot(root: string): Layout { const state = join(root, '.snpm'); return { root, state, metaCache: join(state, 'cache', 'meta'), contentCache: join(state, 'cache', 'content'), staging: join(state, 'staging'), quarantine: join(state, 'quarantine'), auditLog: join(state, 'audit.log'), lockfile: join(root, 'snpm.lock'), nodeModules: join(root, 'node_modules') }; }
function validateFrozenLock(path: string, graph: ResolvedGraph): void { void path; void graph; throw new UnsupportedSpecError('install', '--frozen is not supported yet; refusing to silently ignore the lockfile'); }
async function writeNodeTree(stage: string, graph: ResolvedGraph, files: ReadonlyMap<string, readonly { readonly path: string; readonly data: Uint8Array }[]>): Promise<void> {
  const packageDirs = new Map<string, string>(); const rootModules = join(stage, 'node_modules'); const store = join(rootModules, '.snpm-store'); await mkdir(store, { recursive: true });
  for (const node of graph.nodes.values()) {
    const keyHash = new Bun.CryptoHasher('sha256').update(node.key).digest('hex'); const dest = resolveInside(store, keyHash); packageDirs.set(node.key, dest); await mkdir(dest, { recursive: true });
    for (const file of files.get(node.key) ?? []) { const out = resolveInside(dest, file.path); await mkdir(dirname(out), { recursive: true }); await Bun.write(out, file.data); }
  }
  for (const node of graph.nodes.values()) {
    const from = packageDirs.get(node.key); if (from === undefined) continue; const depsDir = join(from, 'node_modules');
    for (const [alias, key] of node.dependencies) { const target = packageDirs.get(key); if (target === undefined) continue; const link = resolveInside(depsDir, alias); await mkdir(dirname(link), { recursive: true }); const rel = relative(dirname(link), target) || '.'; try { await symlink(rel, link, process.platform === 'win32' ? 'junction' : 'dir'); } catch { await cp(target, link, { recursive: true, force: true }); } }
  }
  const binDir = join(rootModules, '.bin'); await mkdir(binDir, { recursive: true }); const emittedBins = new Set<string>();
  for (const [alias, key] of graph.roots) {
    const target = packageDirs.get(key); if (target === undefined) continue; const link = resolveInside(rootModules, alias); await mkdir(dirname(link), { recursive: true }); const rel = relative(dirname(link), target) || '.';
    try { await symlink(rel, link, process.platform === 'win32' ? 'junction' : 'dir'); } catch { await cp(target, link, { recursive: true, force: true }); }
    const node = graph.nodes.get(key); if (node === undefined) continue;
    for (const [command, relativeBin] of packageBins(files.get(key), node.name)) {
      if (emittedBins.has(command)) continue; const binSource = resolveInside(target, relativeBin); const binLink = resolveInside(binDir, command); await mkdir(dirname(binLink), { recursive: true });
      if (process.platform === 'win32') { const cmdFile = `${binLink}.cmd`; await Bun.write(cmdFile, `@echo off\r\n"${process.execPath.replaceAll('/', '\\\\')}" "${binSource.replaceAll('/', '\\\\')}" %*\r\n`); }
      else { const binRel = relative(binDir, binSource); try { await symlink(binRel, binLink, 'file'); } catch { await cp(binSource, binLink, { force: true }); } await chmod(binLink, 0o755); }
      emittedBins.add(command);
    }
  }
}
function packageBins(files: readonly { readonly path: string; readonly data: Uint8Array }[] | undefined, packageName: string): ReadonlyArray<readonly [string, string]> {
  const pkg = files?.find((file) => file.path === 'package.json'); if (pkg === undefined) return [];
  let raw: unknown; try { raw = JSON.parse(new TextDecoder().decode(pkg.data)); } catch { return []; }
  if (typeof raw !== 'object' || raw === null || !('bin' in raw)) return [];
  const bin = Reflect.get(raw, 'bin');
  if (typeof bin === 'string') { const command = packageName.split('/').pop() ?? packageName; return /^[A-Za-z0-9._-]+$/.test(command) ? [[command, bin]] : []; }
  if (typeof bin !== 'object' || bin === null || Array.isArray(bin)) return [];
  const result: Array<readonly [string, string]> = [];
  for (const [command, path] of Object.entries(bin)) if (typeof path === 'string' && /^[A-Za-z0-9._-]+$/.test(command)) result.push([command, path]);
  return result;
}
async function commitTree(stage: string, nodeModules: string, tx: string): Promise<void> {
  const stagedModules = join(stage, 'node_modules'); const backup = `${nodeModules}.snpm-backup-${tx}`; let backedUp = false; let installed = false;
  try { try { await rename(nodeModules, backup); backedUp = true; } catch (err: unknown) { if (!isMissingPath(err)) throw err; } await rename(stagedModules, nodeModules); installed = true; }
  catch (err: unknown) { if (installed) await rm(nodeModules, { recursive: true, force: true }); if (backedUp) { try { await rename(backup, nodeModules); } catch { /* retain backup */ } } throw err; }
  finally { await rm(stage, { recursive: true, force: true }); }
  if (backedUp) { try { await rm(backup, { recursive: true, force: true }); } catch { /* safe stale backup */ } }
}
function isMissingPath(err: unknown): boolean { return typeof err === 'object' && err !== null && 'code' in err && Reflect.get(err, 'code') === 'ENOENT'; }
