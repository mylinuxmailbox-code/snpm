import type { VersionManifest } from '../core/manifest.ts';
/** Lifecycle hooks are never executed by this release; report hooks needing a future policy. */
export function blockedLifecycleScripts(manifest: VersionManifest, allowed: ReadonlySet<string>): readonly string[] {
  if (allowed.has(`${manifest.name}@${manifest.version}`)) return [];
  return ['preinstall', 'install', 'postinstall', 'prepare'].filter((name) => manifest.scripts.has(name));
}
