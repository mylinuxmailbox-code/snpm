import { gunzipSync } from 'node:zlib';
import { TarballTooLargeError, PathTraversalError, MalformedMetadataError } from './errors.ts';
export interface TarFile { readonly path: string; readonly data: Uint8Array; }
export interface TarLimits { readonly maxUnpackedBytes: number; readonly maxFiles: number; readonly maxPathBytes: number; }
export const DEFAULT_TAR_LIMITS: TarLimits = { maxUnpackedBytes: 256 * 1024 * 1024, maxFiles: 20_000, maxPathBytes: 1024 };
const zeroBlock = (buf: Uint8Array, at: number): boolean => { for (let i = at; i < at + 512; i++) if (buf[i] !== 0) return false; return true; };
function field(buf: Uint8Array, start: number, len: number): string { let end = start; while (end < start + len && buf[end] !== 0) end++; return new TextDecoder().decode(buf.subarray(start, end)); }
function octal(buf: Uint8Array, start: number, len: number): number {
  const raw = field(buf, start, len).trim().replace(/\0/g, ''); if (raw === '') return 0;
  if (!/^[0-7]+$/.test(raw)) throw new MalformedMetadataError('tarball', `invalid octal size ${raw}`);
  const n = Number.parseInt(raw, 8); if (!Number.isSafeInteger(n) || n < 0) throw new MalformedMetadataError('tarball', 'invalid file size'); return n;
}
function verifyHeaderChecksum(buf: Uint8Array, offset: number): void {
  const expected = octal(buf, offset + 148, 8); let sum = 0;
  for (let i = offset; i < offset + 512; i++) sum += i >= offset + 148 && i < offset + 156 ? 32 : (buf[i] ?? 0);
  if (sum !== expected) throw new MalformedMetadataError('tarball', `header checksum mismatch (expected ${expected}, got ${sum})`);
}
function safeEntryName(path: string): string {
  const normalized = path.replaceAll('\\', '/').replace(/^package\//, '').replace(/\/$/, '');
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || normalized.includes('\0')) throw new PathTraversalError(path);
  const parts = normalized.split('/'); if (parts.some((p) => p === '..' || p === '.' || p === '')) throw new PathTraversalError(path); return parts.join('/');
}
export function unpackTarball(gzip: Uint8Array, spec: string, limits: TarLimits = DEFAULT_TAR_LIMITS): readonly TarFile[] {
  let raw: Uint8Array;
  try { raw = gunzipSync(gzip, { maxOutputLength: limits.maxUnpackedBytes }); }
  catch (cause) { if (String(cause).includes('maxOutputLength')) throw new TarballTooLargeError(spec, limits.maxUnpackedBytes + 1, limits.maxUnpackedBytes); throw new MalformedMetadataError(spec, `invalid gzip stream: ${String(cause)}`); }
  if (raw.byteLength > limits.maxUnpackedBytes) throw new TarballTooLargeError(spec, raw.byteLength, limits.maxUnpackedBytes);
  const files: TarFile[] = []; let offset = 0; let unpacked = 0;
  while (offset + 512 <= raw.byteLength) {
    if (zeroBlock(raw, offset)) break; verifyHeaderChecksum(raw, offset);
    const name = field(raw, offset, 100); const prefix = field(raw, offset + 345, 155); const full = prefix ? `${prefix}/${name}` : name;
    const size = octal(raw, offset + 124, 12); const type = String.fromCharCode(raw[offset + 156] ?? 0); const dataStart = offset + 512; const dataEnd = dataStart + size;
    if (dataEnd > raw.byteLength) throw new MalformedMetadataError(spec, 'truncated tar entry');
    if (full.length > limits.maxPathBytes) throw new PathTraversalError(full);
    if (type === '0' || type === '\0' || type === '7') {
      const safe = safeEntryName(full); unpacked += size;
      if (unpacked > limits.maxUnpackedBytes) throw new TarballTooLargeError(spec, unpacked, limits.maxUnpackedBytes);
      files.push({ path: safe, data: raw.subarray(dataStart, dataEnd) });
      if (files.length > limits.maxFiles) throw new TarballTooLargeError(spec, files.length, limits.maxFiles);
    } else if (type === '5') { const directory = full.replaceAll('\\', '/').replace(/\/$/, ''); if (directory !== 'package') safeEntryName(full); }
    else throw new MalformedMetadataError(spec, `unsupported tar entry type ${JSON.stringify(type)} at ${full}`);
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}
