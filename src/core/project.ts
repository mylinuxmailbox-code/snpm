import { join } from 'node:path';
import { MalformedMetadataError } from '../utils/errors.ts';
import type { RootManifest } from './resolver.ts';

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function depMap(v: unknown): Map<string, string> {
  const m = new Map<string, string>();
  if (isRecord(v)) for (const [k, x] of Object.entries(v)) if (typeof x === 'string') m.set(k, x);
  return m;
}

export async function readRootManifest(root: string): Promise<RootManifest> {
  const f = Bun.file(join(root, 'package.json'));
  if (!(await f.exists())) throw new MalformedMetadataError('package.json', `not found in ${root}`);
  let json: unknown;
  try {
    json = await f.json();
  } catch {
    throw new MalformedMetadataError('package.json', 'invalid JSON');
  }
  if (!isRecord(json)) throw new MalformedMetadataError('package.json', 'not an object');
  return {
    dependencies: depMap(json['dependencies']),
    devDependencies: depMap(json['devDependencies']),
    optionalDependencies: depMap(json['optionalDependencies']),
  };
}
