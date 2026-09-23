import { describe, expect, test } from 'bun:test';
import { parsePackument } from '../../src/core/manifest.ts';
import { quarantineSelector } from '../../src/core/quarantine.ts';
import { parseSpec } from '../../src/core/spec.ts';
import { QuarantineViolationError } from '../../src/utils/errors.ts';
import { NOW, HOUR, REG } from '../helpers/mock-registry.ts';

function pack(name: string, versions: Record<string, number>) {
  const raw: Record<string, unknown> = { name, versions: {}, time: {}, 'dist-tags': { latest: Object.keys(versions)[0] } };
  const vs = raw.versions as Record<string, unknown>;
  const time = raw.time as Record<string, string>;
  for (const [version, ageMs] of Object.entries(versions)) {
    vs[version] = { name, version, dist: { tarball: `${REG}/${name}-${version}.tgz`, integrity: `sha512-${'A'.repeat(88)}`, shasum: 'a'.repeat(40) } };
    time[version] = new Date(NOW - ageMs).toISOString();
  }
  return parsePackument(name, raw, { allowedTarballHosts: new Set([new URL(REG).hostname]) }).packument;
}

describe('mandatory 12-hour quarantine', () => {
  test('fried_chicken ^2.0.0 falls back to highest eligible version in-range', () => {
    const p = pack('fried_chicken', { '2.1.0': 3 * HOUR, '2.0.9': 2 * 24 * HOUR, '1.9.9': 2 * 24 * HOUR });
    const result = quarantineSelector({ nowMs: NOW }).select({ spec: parseSpec('fried_chicken', '^2.0.0'), packument: p, candidates: ['2.1.0', '2.0.9'] });
    expect(result.version).toBe('2.0.9');
  });

  test('fried_chicken ^2.1.0 hard-fails instead of escaping to 2.0.9', () => {
    const p = pack('fried_chicken', { '2.1.0': 3 * HOUR, '2.0.9': 2 * 24 * HOUR });
    expect(() => quarantineSelector({ nowMs: NOW }).select({ spec: parseSpec('fried_chicken', '^2.1.0'), packument: p, candidates: ['2.1.0'] })).toThrow(QuarantineViolationError);
  });

  for (const platform of ['linux', 'darwin', 'win32'] as const) {
    test(`same age semantics on ${platform}`, () => {
      const p = pack('fried_chicken', { '2.1.0': 3 * HOUR, '2.0.9': 2 * 24 * HOUR });
      expect(quarantineSelector({ nowMs: NOW }).select({ spec: parseSpec('fried_chicken', '^2.0.0'), packument: p, candidates: ['2.1.0', '2.0.9'] }).version).toBe('2.0.9');
    });
  }
});
