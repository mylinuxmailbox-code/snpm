import type { FetchLike } from '../../src/utils/transport.ts';

export const REG = 'https://registry.test';
export const NOW = Date.parse('2026-09-23T12:00:00Z');
export const HOUR = 3_600_000;

export interface FakeVersion {
  readonly deps?: Record<string, string>;
  readonly optional?: Record<string, string>;
  readonly peers?: Record<string, string>;
  readonly scripts?: Record<string, string>;
  readonly ageMs?: number;
  readonly os?: string[];
  readonly deprecated?: string;
}

const sri = (s: string): string => `sha512-${Buffer.from(s.padEnd(64, '='), 'utf8').toString('base64')}`;

export function packument(name: string, versions: Record<string, FakeVersion>, latest?: string): unknown {
  const vs: Record<string, unknown> = {};
  const time: Record<string, string> = { created: new Date(NOW - 1000 * HOUR).toISOString() };
  for (const [v, f] of Object.entries(versions)) {
    vs[v] = {
      name,
      version: v,
      dependencies: f.deps ?? {},
      optionalDependencies: f.optional ?? {},
      peerDependencies: f.peers ?? {},
      scripts: f.scripts ?? {},
      ...(f.os !== undefined ? { os: f.os } : {}),
      ...(f.deprecated !== undefined ? { deprecated: f.deprecated } : {}),
      dist: { tarball: `${REG}/${name}/-/${name.split('/').pop()}-${v}.tgz`, integrity: sri(`${name}@${v}`), shasum: 'a'.repeat(40) },
    };
    time[v] = new Date(NOW - (f.ageMs ?? 48 * HOUR)).toISOString();
  }
  const keys = Object.keys(versions);
  return { name, 'dist-tags': { latest: latest ?? keys[keys.length - 1] }, versions: vs, time };
}

export interface MockRegistry {
  readonly fetch: FetchLike;
  readonly hits: Map<string, number>;
  inFlight: number;
  peakInFlight: number;
}

/** Serves packuments from a map; unknown names 404. Optional artificial latency. */
export function mockRegistry(docs: Record<string, unknown>, latencyMs = 0): MockRegistry {
  const state: MockRegistry = {
    hits: new Map(),
    inFlight: 0,
    peakInFlight: 0,
    fetch: async (url) => {
      state.inFlight += 1;
      state.peakInFlight = Math.max(state.peakInFlight, state.inFlight);
      try {
        if (latencyMs > 0) await Bun.sleep(latencyMs);
        const name = decodeURIComponent(new URL(url).pathname.slice(1));
        state.hits.set(name, (state.hits.get(name) ?? 0) + 1);
        const doc = docs[name];
        if (doc === undefined) return new Response('{"error":"Not found"}', { status: 404 });
        return new Response(JSON.stringify(doc), { status: 200, headers: { etag: `"${name}-v1"` } });
      } finally {
        state.inFlight -= 1;
      }
    },
  };
  return state;
}

export const noSleep = async (): Promise<void> => {};
