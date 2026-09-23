import { mkdir, rename, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { PathTraversalError } from './errors.ts';

/** Everything snpm writes lives under `<root>/.snpm` (hermetic, no ~/.npm, no /tmp). */
export interface Layout {
  readonly root: string;
  readonly state: string;
  readonly metaCache: string;
  readonly contentCache: string;
  readonly staging: string;
  readonly quarantine: string;
  readonly auditLog: string;
  readonly lockfile: string;
  readonly nodeModules: string;
}

export function layoutFor(root: string): Layout {
  const r = resolve(root);
  const state = join(r, '.snpm');
  return {
    root: r,
    state,
    metaCache: join(state, 'cache', 'meta'),
    contentCache: join(state, 'cache', 'content'),
    staging: join(state, 'staging'),
    quarantine: join(state, 'quarantine'),
    auditLog: join(state, 'audit.log'),
    lockfile: join(r, 'snpm.lock'),
    nodeModules: join(r, 'node_modules'),
  };
}

/** Lexical containment check. Rejects absolute paths, `..` escapes, and NUL bytes. */
export function resolveInside(base: string, untrusted: string): string {
  if (untrusted.includes('\0') || isAbsolute(untrusted)) throw new PathTraversalError(untrusted);
  const target = resolve(base, untrusted);
  const rel = relative(base, target);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel) || rel.split(sep).includes('..')) {
    throw new PathTraversalError(untrusted);
  }
  return target;
}

/** Physical containment check (follows symlinks). Use right before writing. */
export async function assertRealInside(base: string, target: string): Promise<void> {
  const realBase = await realpath(base);
  let probe = target;
  // Walk up to the nearest existing ancestor; that's what a symlink attack would hijack.
  for (;;) {
    try {
      const real = await realpath(probe);
      const rel = relative(realBase, real);
      if (rel.startsWith('..') || isAbsolute(rel)) throw new PathTraversalError(target);
      return;
    } catch (err: unknown) {
      if (err instanceof PathTraversalError) throw err;
      const parent = dirname(probe);
      if (parent === probe) throw new PathTraversalError(target);
      probe = parent;
    }
  }
}

/** Crash-safe write: tmp file in the same dir, then atomic rename. */
export async function atomicWrite(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await Bun.write(tmp, data);
  await rename(tmp, path);
}
