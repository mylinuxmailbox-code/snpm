import { describe, expect, test } from 'bun:test';
import { MemoryMetaStore, RegistryClient, DEFAULT_REGISTRY_OPTIONS, type RegistryEvent } from '../../src/core/registry.ts';
import { fixedClock } from '../../src/utils/clock.ts';
import { MalformedMetadataError, NetworkUnavailableError, PackageNotFoundError } from '../../src/utils/errors.ts';
import { BoundedPool } from '../../src/utils/pool.ts';
import { HttpTransport, type FetchLike } from '../../src/utils/transport.ts';
import { HOUR, mockRegistry, noSleep, NOW, packument, REG } from '../helpers/mock-registry.ts';

const opts = { ...DEFAULT_REGISTRY_OPTIONS, registry: REG };
const fast = { attempts: 2, baseDelayMs: 1, maxDelayMs: 1 };

const client = (f: FetchLike, store = new MemoryMetaStore(), now = NOW, events: RegistryEvent[] = []) =>
  new RegistryClient(new HttpTransport(f, fast, noSleep), new BoundedPool(4), store, fixedClock(now), opts, (e) => events.push(e));

describe('RegistryClient', () => {
  test('fetches once, dedups concurrent callers, caches with etag', async () => {
    const reg = mockRegistry({ a: packument('a', { '1.0.0': {} }) }, 2);
    const store = new MemoryMetaStore();
    const c = client(reg.fetch, store);
    await Promise.all([c.packument('a'), c.packument('a'), c.packument('a')]);
    expect(reg.hits.get('a')).toBe(1);
    expect(store.entries.get('a')?.etag).toBe('"a-v1"');
    expect(c.peek('a')?.packument.name).toBe('a');
  });

  test('404 -> PackageNotFoundError', async () => {
    await expect(client(mockRegistry({}).fetch).packument('nope')).rejects.toBeInstanceOf(PackageNotFoundError);
  });

  test('garbage JSON is rejected and NOT cached', async () => {
    const store = new MemoryMetaStore();
    const f: FetchLike = async () => new Response('{not json');
    await expect(client(f, store).packument('a')).rejects.toBeInstanceOf(MalformedMetadataError);
    expect(store.entries.size).toBe(0);
  });

  test('network down + recent cache -> stale fallback with event', async () => {
    const store = new MemoryMetaStore();
    await store.write('a', { fetchedAt: NOW - 2 * HOUR, body: JSON.stringify(packument('a', { '1.0.0': {} })) });
    const events: RegistryEvent[] = [];
    const dead: FetchLike = async () => { throw new TypeError('ECONNREFUSED'); };
    const r = await client(dead, store, NOW, events).packument('a');
    expect(r.packument.versions.has('1.0.0')).toBe(true);
    expect(events.some((e) => e.kind === 'stale-fallback')).toBe(true);
  });

  test('network down + no cache -> hard NetworkUnavailableError', async () => {
    const dead: FetchLike = async () => { throw new TypeError('ECONNREFUSED'); };
    await expect(client(dead).packument('a')).rejects.toBeInstanceOf(NetworkUnavailableError);
  });

  test('network down + cache older than staleMax -> still fails', async () => {
    const store = new MemoryMetaStore();
    await store.write('a', { fetchedAt: NOW - 48 * HOUR, body: JSON.stringify(packument('a', { '1.0.0': {} })) });
    const dead: FetchLike = async () => { throw new TypeError('down'); };
    await expect(client(dead, store).packument('a')).rejects.toBeInstanceOf(NetworkUnavailableError);
  });

  test('304 revalidation reuses cached body', async () => {
    const store = new MemoryMetaStore();
    await store.write('a', { etag: '"x"', fetchedAt: NOW - HOUR, body: JSON.stringify(packument('a', { '9.9.9': {} })) });
    const f: FetchLike = async () => new Response(null, { status: 304 });
    const r = await client(f, store).packument('a');
    expect(r.packument.versions.has('9.9.9')).toBe(true);
    expect(store.entries.get('a')?.fetchedAt).toBe(NOW);
  });
});
