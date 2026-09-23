import { homedir, join } from 'node:path';

export type SupportedPlatform = 'linux' | 'darwin' | 'win32';
export const hostPlatform: SupportedPlatform = process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'darwin' : 'linux';

/** ClamAV defaults are platform policy, not scattered literals. Windows uses a configured
 * named pipe or TCP endpoint because Unix-domain socket paths are not portable there. */
export function defaultClamdEndpoints(platform: SupportedPlatform): readonly string[] {
  switch (platform) {
    case 'linux': return ['/var/run/clamav/clamd.ctl', '/run/clamav/clamd.ctl', '/run/clamd.scan/clamd.sock'];
    case 'darwin': return ['/opt/homebrew/var/run/clamav/clamd.sock', '/usr/local/var/run/clamav/clamd.sock', '/var/run/clamav/clamd.ctl'];
    case 'win32': return [];
  }
}

export interface RuntimeSignals {
  readonly interrupt: NodeJS.Signals;
  readonly terminate?: NodeJS.Signals;
}

export const runtimeSignals = (platform: SupportedPlatform): RuntimeSignals =>
  platform === 'win32' ? { interrupt: 'SIGINT' } : { interrupt: 'SIGINT', terminate: 'SIGTERM' };

export const hermeticUserState = (root: string): string => join(root, '.snpm');
export const userHome = (): string => homedir();
