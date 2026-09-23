import { mkdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { installProject } from '../core/installer.ts';
import { InvalidPackageNameError, NoMatchingVersionError, UnsupportedSpecError } from '../utils/errors.ts';
import { assertValidName } from '../core/manifest.ts';

/** Minimal safe npx analogue: snpx <package>[@range] [args...], no shell-string execution. */
export async function runSnpx(root: string, argv: readonly string[]): Promise<number> {
  const [rawSpec, ...args] = argv;
  if (rawSpec === undefined || rawSpec.startsWith('-')) throw new UnsupportedSpecError('snpx', 'usage: snpx <package>[@range] [args...]');
  const split = parsePackageSpec(rawSpec);
  const base = resolve(root, '.snpm', 'snpx');
  const hash = createHash('sha256').update(rawSpec).digest('hex').slice(0, 20);
  const work = join(base, hash);
  await mkdir(work, { recursive: true });
  await Bun.write(join(work, 'package.json'), JSON.stringify({ name: `snpx-${hash}`, private: true, dependencies: { [split.name]: split.range } }, null, 2));
  await installProject({ root: work, production: true });
  const installedManifest = join(work, 'node_modules', ...split.name.split('/'), 'package.json');
  let json: unknown;
  try { json = JSON.parse(await readFile(installedManifest, 'utf8')); }
  catch { throw new NoMatchingVersionError(split.name, split.range); }
  const bin = resolveBin(json, split.name);
  if (bin === undefined) throw new InvalidPackageNameError(`${split.name} has no executable bin`);
  const packageDir = dirname(installedManifest);
  if (isAbsolute(bin) || relative(packageDir, resolve(packageDir, bin)).startsWith('..')) throw new UnsupportedSpecError(split.name, `unsafe bin path ${bin}`);
  const executable = resolve(packageDir, bin);
  // Invoke via Bun directly: supports Windows and avoids evaluating a shell command string.
  const child = Bun.spawn([process.execPath, executable, ...args], { cwd: root, stdin: 'inherit', stdout: 'inherit', stderr: 'inherit' });
  return await child.exited;
}
function parsePackageSpec(raw: string): { readonly name: string; readonly range: string } {
  if (/^(?:git\+|github:|https?:|file:|workspace:)/i.test(raw)) throw new UnsupportedSpecError('snpx', raw);
  let name = raw; let range = '*';
  if (raw.startsWith('@')) { const slash = raw.indexOf('/'); const at = raw.indexOf('@', slash + 1); if (at > 0) { name = raw.slice(0, at); range = raw.slice(at + 1); } }
  else { const at = raw.lastIndexOf('@'); if (at > 0) { name = raw.slice(0, at); range = raw.slice(at + 1); } }
  assertValidName(name); return { name, range: range || '*' };
}
function resolveBin(json: unknown, packageName: string): string | undefined {
  if (typeof json !== 'object' || json === null || !('bin' in json)) return undefined;
  const bin = json.bin;
  if (typeof bin === 'string') return bin;
  if (typeof bin !== 'object' || bin === null || Array.isArray(bin)) return undefined;
  const preferred = packageName.split('/').pop() ?? packageName;
  const candidate = Reflect.get(bin, preferred) ?? Object.values(bin)[0];
  return typeof candidate === 'string' ? candidate : undefined;
}
