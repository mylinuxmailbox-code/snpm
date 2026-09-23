import { describe, expect, test } from 'bun:test';
import { encodePackageName, parsePackument } from '../../src/core/manifest.ts';
import { InvalidPackageNameError, MalformedMetadataError } from '../../src/utils/errors.ts';
import { packument, REG } from '../helpers/mock-registry.ts';

const opts = { allowedTarballHosts: new Set([new URL(REG).hostname]) };

describe('parsePackument', () => {
  test('extracts versions, deps and publish times', () => {
    const { packument: p, warnings } = parsePackument('a', packument('a', { '1.0.0': { deps: { b: '^1' } }, '1.1.0': {} }), opts);
    expect([...p.versions.keys()]).toEqual(['1.0.0', '1.1.0']);
    expect(p.versions.get('1.0.0')?.dependencies.get('b')).toBe('^1');
    expect(typeof p.time.get('1.1.0')).toBe('number');
    expect(p.distTags.get('latest')).toBe('1.1.0');
    expect(warnings).toHaveLength(0);
  });

  test('drops malformed versions, keeps the rest (fail closed per version)', () => {
    const doc = packument('a', { '1.0.0': {}, '2.0.0': {} });
    if (typeof doc === 'object' && doc !== null && 'versions' in doc && typeof doc.versions === 'object' && doc.versions !== null) {
      Reflect.set(doc.versions, '2.0.0', { name: 'evil', version: '2.0.0' });
    }
    const { packument: p, warnings } = parsePackument('a', doc, opts);
    expect(p.versions.has('2.0.0')).toBe(false);
    expect(p.distTags.has('latest')).toBe(false); // tag pointed at the dropped version
    expect(warnings[0]).toBeInstanceOf(MalformedMetadataError);
  });

  test('refuses tarballs on foreign hosts or plain http', () => {
    const doc = JSON.parse(JSON.stringify(packument('a', { '1.0.0': {} })));
    doc.versions['1.0.0'].dist.tarball = 'https://evil.example/a.tgz';
    expect(parsePackument('a', doc, opts).packument.versions.size).toBe(0);
    doc.versions['1.0.0'].dist.tarball = 'http://registry.test/a.tgz';
    expect(parsePackument('a', doc, opts).packument.versions.size).toBe(0);
  });

  test('__proto__ keys cannot pollute', () => {
    const raw = `{"name":"a","versions":{"1.0.0":{"name":"a","version":"1.0.0","dependencies":{"__proto__":"1.0.0"},"dist":{"tarball":"${REG}/a.tgz","shasum":"${'b'.repeat(40)}"}}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}`;
    const { packument: p } = parsePackument('a', JSON.parse(raw), opts);
    expect(p.versions.get('1.0.0')?.dependencies.get('__proto__')).toBe('1.0.0');
    const probe: Record<string, unknown> = {};
    expect(probe['1.0.0']).toBeUndefined();
  });

  test('legacy shasum becomes sha1 SRI; strongest SRI wins', () => {
    const doc = JSON.parse(JSON.stringify(packument('a', { '1.0.0': {}, '2.0.0': {} })));
    delete doc.versions['1.0.0'].dist.integrity;
    doc.versions['2.0.0'].dist.integrity = `sha1-AAAA ${doc.versions['2.0.0'].dist.integrity}`;
    const { packument: p } = parsePackument('a', doc, opts);
    expect(p.versions.get('1.0.0')?.dist.integrityAlgo).toBe('sha1');
    expect(p.versions.get('2.0.0')?.dist.integrityAlgo).toBe('sha512');
  });

  test('truncated SRI digests are ignored (falls back to shasum)', () => {
    const doc = JSON.parse(JSON.stringify(packument('a', { '1.0.0': {} })));
    doc.versions['1.0.0'].dist.integrity = 'sha512-AAAA';
    expect(parsePackument('a', doc, opts).packument.versions.get('1.0.0')?.dist.integrityAlgo).toBe('sha1');
  });

  test('detects install scripts', () => {
    const { packument: p } = parsePackument('a', packument('a', { '1.0.0': { scripts: { postinstall: 'node x.js' } } }), opts);
    expect(p.versions.get('1.0.0')?.hasInstallScript).toBe(true);
  });

  test('missing time block warns, versions have no timestamps', () => {
    const doc = JSON.parse(JSON.stringify(packument('a', { '1.0.0': {} })));
    delete doc.time;
    const r = parsePackument('a', doc, opts);
    expect(r.packument.time.size).toBe(0);
    expect(r.warnings.length).toBeGreaterThan(0);
  });

  test('document name mismatch throws', () => {
    expect(() => parsePackument('a', packument('b', {}), opts)).toThrow(MalformedMetadataError);
  });
});

describe('encodePackageName', () => {
  test('scoped names', () => expect(encodePackageName('@types/node')).toBe('@types%2Fnode'));
  test('rejects path tricks', () => {
    for (const bad of ['../etc', 'a/b', '@x/../y', '', 'a b']) expect(() => encodePackageName(bad)).toThrow(InvalidPackageNameError);
  });
});
