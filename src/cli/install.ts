import { installProject } from '../core/installer.ts';
import { c, Spinner } from './render.ts';
export async function runInstall(root: string, production: boolean): Promise<number> {
  const spinner = new Spinner().start('resolving, verifying, scanning, and staging packages');
  try { const result = await installProject({ root, production }); spinner.stop(`${c.green('✔')} installed ${result.packages} packages; lifecycle scripts were not run`); return 0; }
  catch (err: unknown) { spinner.stop(); throw err; }
}
