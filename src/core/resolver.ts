/**
 * Recursive, level-parallel dependency resolver.
 *
 * Frontier BFS: every edge in a level is resolved concurrently; the RegistryClient's pool is
 * what bounds actual network concurrency. Nodes are keyed by `name@version`, so cycles and
 * diamonds terminate naturally (check-then-set happens with no `await` in between).
 *
 * Version choice is delegated to a VersionSelector. Phase 3 plugs the quarantine gate in there;
 * the resolver itself stays policy-free.
 */
import { DependencyGraphTooLargeError, NoMatchingVersionError, SnpmError } from '../utils/errors.ts';
import type { Packument, VersionManifest } from './manifest.ts';
import type { RegistryClient } from './registry.ts';
import { parseSpec, type RegistrySpec } from './spec.ts';

export type EdgeKind = 'prod' | 'dev' | 'optional' | 'peer';

export interface SelectionContext {
  readonly spec: RegistrySpec;
  readonly packument: Packument;
  /** Versions satisfying the range, newest first. Never empty. */
  readonly candidates: readonly string[];
}

export interface Selection {
  readonly version: string;
  /** Newer satisfying versions the selector refused, with a reason (for audit/UX). */
  readonly rejected: ReadonlyArray<{ readonly version: string; readonly reason: string }>;
}

export interface VersionSelector {
  select(ctx: SelectionContext): Selection;
}

/** npm-compatible default: prefer `latest` if it satisfies, else highest match. No security policy. */
export const latestSatisfying: VersionSelector = {
  select({ packument, candidates }) {
    const latest = packument.distTags.get('latest');
    const version = latest !== undefined && candidates.includes(latest) ? latest : candidates[0];
    if (version === undefined) throw new Error('unreachable: empty candidate list');
    return { version, rejected: [] };
  },
};

export type NodeKey = `${string}@${string}`;

export interface ResolvedNode {
  readonly key: NodeKey;
  readonly name: string;
  readonly version: string;
  readonly tarball: string;
  readonly integrity: string;
  readonly integrityAlgo: VersionManifest['dist']['integrityAlgo'];
  readonly publishedAt: number | undefined;
  readonly hasInstallScript: boolean;
  readonly deprecated: string | undefined;
  /** alias -> resolved node key */
  readonly dependencies: ReadonlyMap<string, NodeKey>;
  /** true only if every path from a root reaches this node via an optional edge */
  readonly optional: boolean;
  readonly unpackedSize: number | undefined;
}

export interface ResolveWarning {
  readonly kind: 'optional-failed' | 'deprecated' | 'peer-unmet' | 'selector-rejected' | 'install-script' | 'weak-integrity';
  readonly subject: string;
  readonly detail: string;
}

export interface ResolvedGraph {
  readonly roots: ReadonlyMap<string, NodeKey>;
  readonly nodes: ReadonlyMap<NodeKey, ResolvedNode>;
  readonly warnings: readonly ResolveWarning[];
}

export interface RootManifest {
  readonly dependencies?: ReadonlyMap<string, string>;
  readonly devDependencies?: ReadonlyMap<string, string>;
  readonly optionalDependencies?: ReadonlyMap<string, string>;
}

export interface ResolverOptions {
  readonly includeDev: boolean;
  readonly maxNodes: number;
  readonly platform: string;
  readonly arch: string;
}

export const DEFAULT_RESOLVER_OPTIONS: ResolverOptions = {
  includeDev: true,
  maxNodes: 20_000,
  platform: process.platform,
  arch: process.arch,
};

interface Edge {
  readonly parent: NodeKey | null;
  readonly alias: string;
  readonly raw: string;
  readonly kind: EdgeKind;
}

interface Picked {
  readonly manifest: VersionManifest;
  readonly publishedAt: number | undefined;
}

interface MutableNode extends Omit<ResolvedNode, 'dependencies' | 'optional'> {
  dependencies: Map<string, NodeKey>;
  optional: boolean;
}

export function candidatesFor(p: Packument, range: string): string[] {
  const tagged = p.distTags.get(range);
  if (tagged !== undefined) return [tagged];
  const r = range === 'latest' ? '*' : range;
  const out: string[] = [];
  for (const v of p.versions.keys()) if (Bun.semver.satisfies(v, r)) out.push(v);
  out.sort((a, b) => Bun.semver.order(b, a));
  return out;
}

/** os/cpu fields: ['darwin'], ['!win32'], etc. Empty/absent = any. */
function platformOk(list: readonly string[] | undefined, current: string): boolean {
  if (list === undefined || list.length === 0) return true;
  const deny = list.filter((x) => x.startsWith('!')).map((x) => x.slice(1));
  const allow = list.filter((x) => !x.startsWith('!'));
  if (deny.includes(current)) return false;
  return allow.length === 0 || allow.includes(current);
}

export class Resolver {
  constructor(
    private readonly registry: RegistryClient,
    private readonly selector: VersionSelector = latestSatisfying,
    private readonly opts: ResolverOptions = DEFAULT_RESOLVER_OPTIONS,
  ) {}

  async resolve(root: RootManifest): Promise<ResolvedGraph> {
    const nodes = new Map<NodeKey, MutableNode>();
    const roots = new Map<string, NodeKey>();
    const warnings: ResolveWarning[] = [];
    const edgeMemo = new Map<string, Promise<Picked>>(); // `${name}@${range}` -> chosen version
    const peers: Array<{ from: NodeKey; alias: string; range: string; optional: boolean }> = [];

    let frontier: Edge[] = [];
    const pushRoots = (m: ReadonlyMap<string, string> | undefined, kind: EdgeKind): void => {
      for (const [alias, raw] of m ?? []) frontier.push({ parent: null, alias, raw, kind });
    };
    pushRoots(root.dependencies, 'prod');
    if (this.opts.includeDev) pushRoots(root.devDependencies, 'dev');
    pushRoots(root.optionalDependencies, 'optional');

    const pick = (spec: RegistrySpec): Promise<Picked> => {
      const memoKey = `${spec.name}@${spec.range}`;
      const hit = edgeMemo.get(memoKey);
      if (hit !== undefined) return hit;
      const p = (async () => {
        const { packument } = this.registry.peek(spec.name) ?? (await this.registry.packument(spec.name));
        const candidates = candidatesFor(packument, spec.range);
        if (candidates.length === 0) throw new NoMatchingVersionError(spec.name, spec.range);
        const sel = this.selector.select({ spec, packument, candidates });
        for (const r of sel.rejected) {
          warnings.push({ kind: 'selector-rejected', subject: `${spec.name}@${r.version}`, detail: r.reason });
        }
        const m = packument.versions.get(sel.version);
        if (m === undefined) throw new NoMatchingVersionError(spec.name, spec.range);
        return { manifest: m, publishedAt: packument.time.get(sel.version) };
      })();
      edgeMemo.set(memoKey, p);
      return p;
    };

    while (frontier.length > 0) {
      const level = frontier;
      frontier = [];
      await Promise.all(
        level.map(async (edge) => {
          const edgeOptional = edge.kind === 'optional' || (edge.parent !== null && nodes.get(edge.parent)?.optional === true);
          let m: VersionManifest;
          let publishedAt: number | undefined;
          try {
            const spec = parseSpec(edge.alias, edge.raw);
            ({ manifest: m, publishedAt } = await pick(spec));
            if (!platformOk(m.os, this.opts.platform) || !platformOk(m.cpu, this.opts.arch)) {
              if (edgeOptional) {
                warnings.push({ kind: 'optional-failed', subject: `${m.name}@${m.version}`, detail: 'platform mismatch, skipped' });
                return;
              }
            }
          } catch (err: unknown) {
            if (edgeOptional && err instanceof SnpmError) {
              warnings.push({ kind: 'optional-failed', subject: `${edge.alias}@${edge.raw}`, detail: err.message });
              return;
            }
            throw err;
          }

          const key: NodeKey = `${m.name}@${m.version}`;
          if (edge.parent === null) roots.set(edge.alias, key);
          else nodes.get(edge.parent)?.dependencies.set(edge.alias, key);

          const existing = nodes.get(key);
          if (existing !== undefined) {
            if (!edgeOptional) existing.optional = false; // a required path wins
            return;
          }
          if (nodes.size >= this.opts.maxNodes) throw new DependencyGraphTooLargeError(this.opts.maxNodes);

          nodes.set(key, {
            key,
            name: m.name,
            version: m.version,
            tarball: m.dist.tarball,
            integrity: m.dist.integrity,
            integrityAlgo: m.dist.integrityAlgo,
            publishedAt,
            hasInstallScript: m.hasInstallScript,
            deprecated: m.deprecated,
            dependencies: new Map(),
            optional: edgeOptional,
            unpackedSize: m.dist.unpackedSize,
          });
          if (m.deprecated !== undefined) warnings.push({ kind: 'deprecated', subject: key, detail: m.deprecated });
          if (m.hasInstallScript) warnings.push({ kind: 'install-script', subject: key, detail: 'has install-time scripts (blocked by default)' });
          if (m.dist.integrityAlgo === 'sha1') warnings.push({ kind: 'weak-integrity', subject: key, detail: 'only sha1 shasum available' });

          for (const [alias, raw] of m.dependencies) frontier.push({ parent: key, alias, raw, kind: 'prod' });
          for (const [alias, raw] of m.optionalDependencies) frontier.push({ parent: key, alias, raw, kind: 'optional' });
          for (const [alias, range] of m.peerDependencies) {
            peers.push({ from: key, alias, range, optional: m.optionalPeers.has(alias) });
          }
        }),
      );
    }

    // Peers: npm 7+ auto-installs them; we only verify here and report. Phase 4 linker decides.
    const byName = new Map<string, string[]>();
    for (const n of nodes.values()) byName.set(n.name, [...(byName.get(n.name) ?? []), n.version]);
    for (const p of peers) {
      const satisfied = (byName.get(p.alias) ?? []).some((v) => Bun.semver.satisfies(v, p.range));
      if (!satisfied && !p.optional) {
        warnings.push({ kind: 'peer-unmet', subject: p.from, detail: `wants ${p.alias}@${p.range}` });
      }
    }

    return { roots, nodes, warnings };
  }
}
