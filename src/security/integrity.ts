import { IntegrityMismatchError } from '../utils/errors.ts';

/** Verify SRI without converting/copying the tarball buffer. */
export function verifyIntegrity(spec: string, data: Uint8Array, sri: string): void {
  const tokens = sri.trim().split(/\s+/).filter(Boolean);
  let strongest: { algo: 'sha512' | 'sha384' | 'sha256' | 'sha1'; digest: string; rank: number } | undefined;
  const ranks = { sha512: 4, sha384: 3, sha256: 2, sha1: 1 } as const;
  for (const token of tokens) {
    const match = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+={0,2})$/.exec(token);
    if (match === null) continue;
    const algo = match[1];
    const digest = match[2];
    if ((algo !== 'sha512' && algo !== 'sha384' && algo !== 'sha256' && algo !== 'sha1') || digest === undefined) continue;
    if (strongest === undefined || ranks[algo] > strongest.rank) strongest = { algo, digest, rank: ranks[algo] };
  }
  if (strongest === undefined) throw new IntegrityMismatchError(spec, sri, 'no-supported-digest');
  const actual = new Bun.CryptoHasher(strongest.algo).update(data).digest('base64');
  if (actual !== strongest.digest) throw new IntegrityMismatchError(spec, strongest.digest, actual);
}
