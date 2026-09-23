/**
 * snpm.lock: deterministic JSON (sorted keys, stable ordering, trailing newline) so the
 * same graph always produces byte-identical output and diffs stay reviewable.
 */
import { atomicWrite } from '../utils/fs-layout.ts';
import type { NodeKey, ResolvedGraph } from './resolver.ts';

export const LOCKFILE_VERSION = 1;

export interface LockEntry {
  readonly resolved: string;
  readonly integrity: string;
  readonly publishedAt?: string;
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly optional?: true;
  readonly hasInstallScript?: true;
}

export interface Lockfile {
  readonly lockfileVersion: number;
  readonly generatedBy: string;
  readonly roots: Readonly<Record<string, string>>;
  readonly packages: Readonly<Record<string, LockEntry>>;
}

const byKey = <T>(entries: Iterable<readonly [string, T]>): Record<string, T> => {
  const sorted = [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(sorted);
};

export function toLockfile(graph: ResolvedGraph): Lockfile {
  const packages: Array<readonly [NodeKey, LockEntry]> = [];
  for (const n of graph.nodes.values()) {
    const deps = byKey(n.dependencies);
    packages.push([
      n.key,
      {
        resolved: n.tarball,
        integrity: n.integrity,
        ...(n.publishedAt !== undefined ? { publishedAt: new Date(n.publishedAt).toISOString() } : {}),
        ...(Object.keys(deps).length > 0 ? { dependencies: deps } : {}),
        ...(n.optional ? { optional: true as const } : {}),
        ...(n.hasInstallScript ? { hasInstallScript: true as const } : {}),
      },
    ]);
  }
  return {
    lockfileVersion: LOCKFILE_VERSION,
    generatedBy: 'snpm/0.0.1',
    roots: byKey(graph.roots),
    packages: byKey(packages),
  };
}

export const serializeLockfile = (lock: Lockfile): string => `${JSON.stringify(lock, null, 2)}\n`;

export async function writeLockfile(path: string, graph: ResolvedGraph): Promise<string> {
  const text = serializeLockfile(toLockfile(graph));
  await atomicWrite(path, text);
  return text;
}
