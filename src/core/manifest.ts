/**
 * Registry packument parser. Input is untrusted JSON from the network, so:
 *  - no type assertions: every field is narrowed with guards
 *  - all key/value maps are `Map`s, never plain objects (a `__proto__` key can't pollute anything)
 *  - a malformed *version* is dropped with a warning (fail closed for that version only)
 *  - a malformed *document* throws MalformedMetadataError
 */
import { InvalidPackageNameError, MalformedMetadataError } from '../utils/errors.ts';

export type DepMap = ReadonlyMap<string, string>;

export interface Dist {
  readonly tarball: string;
  /** SRI string. Synthesized as `sha1-...` from `shasum` for legacy packages. */
  readonly integrity: string;
  readonly integrityAlgo: 'sha512' | 'sha384' | 'sha256' | 'sha1';
  readonly unpackedSize?: number;
  readonly fileCount?: number;
  readonly hasSignatures: boolean;
  readonly attestationsUrl?: string;
}

export interface VersionManifest {
  readonly name: string;
  readonly version: string;
  readonly dependencies: DepMap;
  readonly optionalDependencies: DepMap;
  readonly peerDependencies: DepMap;
  readonly optionalPeers: ReadonlySet<string>;
  readonly scripts: DepMap;
  /** true if any lifecycle script runs at install time (the #1 npm attack vector). */
  readonly hasInstallScript: boolean;
  readonly deprecated?: string;
  readonly os?: readonly string[];
  readonly cpu?: readonly string[];
  readonly dist: Dist;
}

export interface Packument {
  readonly name: string;
  readonly distTags: DepMap;
  readonly versions: ReadonlyMap<string, VersionManifest>;
  /** version -> publish time (epoch ms). Only finite, parseable timestamps land here. */
  readonly time: ReadonlyMap<string, number>;
  readonly created?: number;
  readonly modified?: number;
}

export interface ParseResult {
  readonly packument: Packument;
  readonly warnings: readonly MalformedMetadataError[];
}

export interface ParseOptions {
  /** Hostnames tarballs may be served from. Defaults to the registry host only. */
  readonly allowedTarballHosts: ReadonlySet<string>;
}

// npm's validate-npm-package-name rules, legacy-uppercase tolerant.
const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'] as const;
const SRI_RE = /^(sha512|sha384|sha256|sha1)-[A-Za-z0-9+/]+={0,2}$/;
// Base64 digest length per algorithm; a truncated hash is as good as no hash.
const SRI_B64_LEN = { sha512: 88, sha384: 64, sha256: 44, sha1: 28 } as const;
const SHA1_HEX_RE = /^[0-9a-f]{40}$/i;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export function assertValidName(name: string): void {
  if (name.length === 0 || name.length > 214 || !NAME_RE.test(name) || name.includes('..')) {
    throw new InvalidPackageNameError(name);
  }
}

/** `@scope/pkg` -> `@scope%2Fpkg`, which is what the registry expects in the path. */
export function encodePackageName(name: string): string {
  assertValidName(name);
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const optString = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

const optFiniteNumber = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined;

function stringMap(v: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (!isRecord(v)) return out;
  for (const [k, x] of Object.entries(v)) if (typeof x === 'string') out.set(k, x);
  return out;
}

function stringArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const x of v) if (typeof x === 'string') out.push(x);
  return out;
}

function parseTime(v: unknown): number | undefined {
  if (typeof v !== 'string') return undefined;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
}

function parseDist(pkg: string, raw: unknown, opts: ParseOptions): Dist {
  if (!isRecord(raw)) throw new MalformedMetadataError(pkg, 'dist missing');

  const tarball = optString(raw['tarball']);
  if (tarball === undefined) throw new MalformedMetadataError(pkg, 'dist.tarball missing');
  let url: URL;
  try {
    url = new URL(tarball);
  } catch {
    throw new MalformedMetadataError(pkg, `dist.tarball is not a URL: ${tarball}`);
  }
  const loopback = LOOPBACK.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new MalformedMetadataError(pkg, `dist.tarball must be https: ${tarball}`);
  }
  if (!opts.allowedTarballHosts.has(url.hostname)) {
    throw new MalformedMetadataError(pkg, `dist.tarball host ${url.hostname} not in allowlist`);
  }
  if (url.username !== '' || url.password !== '') {
    throw new MalformedMetadataError(pkg, 'dist.tarball must not embed credentials');
  }

  let integrity: string;
  let integrityAlgo: Dist['integrityAlgo'];
  const sri = optString(raw['integrity']);
  // SRI may list several hashes separated by spaces; keep the strongest.
  const candidates = (sri ?? '').split(/\s+/).filter((s) => SRI_RE.test(s));
  const rank = { sha512: 4, sha384: 3, sha256: 2, sha1: 1 } as const;
  let best: { s: string; algo: Dist['integrityAlgo'] } | undefined;
  for (const s of candidates) {
    const m = SRI_RE.exec(s);
    const algo = m?.[1];
    if (algo !== 'sha512' && algo !== 'sha384' && algo !== 'sha256' && algo !== 'sha1') continue;
    if (s.length - algo.length - 1 !== SRI_B64_LEN[algo]) continue;
    if (best === undefined || rank[algo] > rank[best.algo]) best = { s, algo };
  }
  if (best !== undefined) {
    integrity = best.s;
    integrityAlgo = best.algo;
  } else {
    const shasum = optString(raw['shasum']);
    if (shasum === undefined || !SHA1_HEX_RE.test(shasum)) {
      throw new MalformedMetadataError(pkg, 'no usable integrity or shasum');
    }
    integrity = `sha1-${Buffer.from(shasum, 'hex').toString('base64')}`;
    integrityAlgo = 'sha1';
  }

  const unpackedSize = optFiniteNumber(raw['unpackedSize']);
  const fileCount = optFiniteNumber(raw['fileCount']);
  const att = raw['attestations'];
  const attestationsUrl = isRecord(att) ? optString(att['url']) : undefined;
  const sigs = raw['signatures'];

  return {
    tarball,
    integrity,
    integrityAlgo,
    hasSignatures: Array.isArray(sigs) && sigs.length > 0,
    ...(unpackedSize !== undefined ? { unpackedSize } : {}),
    ...(fileCount !== undefined ? { fileCount } : {}),
    ...(attestationsUrl !== undefined ? { attestationsUrl } : {}),
  };
}

function parseVersion(pkgName: string, key: string, raw: unknown, opts: ParseOptions): VersionManifest {
  const spec = `${pkgName}@${key}`;
  if (!isRecord(raw)) throw new MalformedMetadataError(spec, 'version entry is not an object');
  const name = optString(raw['name']);
  const version = optString(raw['version']);
  if (name !== pkgName) throw new MalformedMetadataError(spec, `name mismatch (${String(name)})`);
  if (version !== key) throw new MalformedMetadataError(spec, `version mismatch (${String(version)})`);

  const scripts = stringMap(raw['scripts']);
  const peerMeta = raw['peerDependenciesMeta'];
  const optionalPeers = new Set<string>();
  if (isRecord(peerMeta)) {
    for (const [peer, meta] of Object.entries(peerMeta)) {
      if (isRecord(meta) && meta['optional'] === true) optionalPeers.add(peer);
    }
  }
  // node-gyp builds (binding.gyp) also run at install; npm sets gypfile / hasInstallScript for it.
  const hasInstallScript =
    raw['hasInstallScript'] === true || raw['gypfile'] === true || INSTALL_SCRIPTS.some((s) => scripts.has(s));

  const deprecated = optString(raw['deprecated']);
  const os = stringArray(raw['os']);
  const cpu = stringArray(raw['cpu']);
  const optionalDependencies = stringMap(raw['optionalDependencies']);
  // npm semantics: optionalDependencies override same-named dependencies.
  const dependencies = stringMap(raw['dependencies']);
  for (const k of optionalDependencies.keys()) dependencies.delete(k);

  return {
    name,
    version,
    dependencies,
    optionalDependencies,
    peerDependencies: stringMap(raw['peerDependencies']),
    optionalPeers,
    scripts,
    hasInstallScript,
    dist: parseDist(spec, raw['dist'], opts),
    ...(deprecated !== undefined ? { deprecated } : {}),
    ...(os !== undefined ? { os } : {}),
    ...(cpu !== undefined ? { cpu } : {}),
  };
}

export function parsePackument(expectedName: string, json: unknown, opts: ParseOptions): ParseResult {
  if (!isRecord(json)) throw new MalformedMetadataError(expectedName, 'document is not an object');
  if (json['name'] !== expectedName) {
    throw new MalformedMetadataError(expectedName, `document name mismatch (${String(json['name'])})`);
  }
  const rawVersions = json['versions'];
  if (!isRecord(rawVersions)) throw new MalformedMetadataError(expectedName, 'versions block missing');

  const warnings: MalformedMetadataError[] = [];
  const versions = new Map<string, VersionManifest>();
  for (const [key, raw] of Object.entries(rawVersions)) {
    try {
      versions.set(key, parseVersion(expectedName, key, raw, opts));
    } catch (err: unknown) {
      if (err instanceof MalformedMetadataError) warnings.push(err);
      else throw err;
    }
  }

  const time = new Map<string, number>();
  const rawTime = json['time'];
  if (!isRecord(rawTime)) {
    warnings.push(new MalformedMetadataError(expectedName, 'time block missing (all versions will fail the quarantine gate)'));
  } else {
    for (const v of versions.keys()) {
      const t = parseTime(rawTime[v]);
      if (t === undefined) warnings.push(new MalformedMetadataError(`${expectedName}@${v}`, 'publish time missing or unparseable'));
      else time.set(v, t);
    }
  }
  const created = isRecord(rawTime) ? parseTime(rawTime['created']) : undefined;
  const modified = isRecord(rawTime) ? parseTime(rawTime['modified']) : undefined;

  // dist-tags pointing at versions we dropped are themselves dropped.
  const distTags = new Map<string, string>();
  for (const [tag, v] of stringMap(json['dist-tags'])) if (versions.has(v)) distTags.set(tag, v);

  return {
    packument: {
      name: expectedName,
      distTags,
      versions,
      time,
      ...(created !== undefined ? { created } : {}),
      ...(modified !== undefined ? { modified } : {}),
    },
    warnings,
  };
}
