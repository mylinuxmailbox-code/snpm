import { loadConfig } from '../core/config.ts';
import { writeLockfile } from '../core/lockfile.ts';
import { readRootManifest } from '../core/project.ts';
import { quarantineSelector } from '../core/quarantine.ts';
import { FsMetaStore, RegistryClient, DEFAULT_REGISTRY_OPTIONS, type RegistryEvent } from '../core/registry.ts';
import { Resolver, DEFAULT_RESOLVER_OPTIONS } from '../core/resolver.ts';
import { systemClock } from '../utils/clock.ts';
import { layoutFor } from '../utils/fs-layout.ts';
import { BoundedPool } from '../utils/pool.ts';
import { HttpTransport } from '../utils/transport.ts';
import { c, securityWarn, Spinner } from './render.ts';

export interface ResolveFlags { readonly json: boolean; readonly production: boolean; readonly writeLock: boolean; }

export async function runResolve(root: string, flags: ResolveFlags): Promise<number> {
  const layout = layoutFor(root);
  const config = await loadConfig(layout.root);
  const spinner = flags.json ? undefined : new Spinner().start('resolving dependency graph');
  let fetched = 0;
  let cached = 0;
  const onEvent = (e: RegistryEvent): void => {
    switch (e.kind) {
      case 'fetched': fetched += 1; spinner?.update(`resolving ${c.dim(e.name)} (${fetched} fetched, ${cached} cached)`); return;
      case 'cache-hit':
      case 'revalidated': cached += 1; return;
      case 'stale-fallback': securityWarn('STALE_METADATA', { pkg: e.name, ageMin: Math.round(e.ageMs / 60_000), cause: JSON.stringify(e.cause) }); return;
      case 'metadata-warning': securityWarn('MALFORMED_METADATA', { pkg: e.error.pkg, reason: JSON.stringify(e.error.reason) }); return;
    }
  };
  const registry = new RegistryClient(new HttpTransport(), new BoundedPool(16), new FsMetaStore(layout.metaCache), systemClock, { ...DEFAULT_REGISTRY_OPTIONS, registry: config.registry }, onEvent);
  const selector = quarantineSelector({
    nowMs: systemClock.now(),
    minAgeMs: 12 * 3_600_000,
    onBlocked: (e) => securityWarn('QUARANTINE_BLOCK', { pkg: e.name, range: JSON.stringify(e.range), version: e.version, ageHours: e.ageMs === undefined ? 'unknown' : (e.ageMs / 3_600_000).toFixed(2), minAgeHours: 12 }),
  });
  const resolver = new Resolver(registry, selector, { ...DEFAULT_RESOLVER_OPTIONS, includeDev: !flags.production });
  try {
    const graph = await resolver.resolve(await readRootManifest(layout.root));
    spinner?.stop(`${c.green('✔')} resolved ${c.bold(String(graph.nodes.size))} packages (${fetched} fetched, ${cached} cached)`);
    for (const w of graph.warnings) {
      if (w.kind === 'install-script' || w.kind === 'weak-integrity') securityWarn(w.kind.toUpperCase().replace('-', '_'), { pkg: w.subject, detail: JSON.stringify(w.detail) });
      else if (!flags.json) process.stdout.write(`${c.yellow('!')} ${w.kind} ${w.subject}: ${w.detail}\n`);
    }
    if (flags.writeLock) await writeLockfile(layout.lockfile, graph);
    if (flags.json) process.stdout.write(`${JSON.stringify({ roots: Object.fromEntries(graph.roots), nodes: [...graph.nodes.values()].map((n) => ({ ...n, dependencies: Object.fromEntries(n.dependencies) })), warnings: graph.warnings })}\n`);
    return 0;
  } catch (err: unknown) { spinner?.stop(); throw err; }
}
