import { describe, expect, test } from 'bun:test';
import { defaultClamdSockets, parseConfig } from '../../src/core/config.ts';

describe('platform configuration', () => {
  test('Linux/macOS have daemon defaults; Windows does not assume Unix sockets', () => {
    expect(defaultClamdSockets('linux').length).toBeGreaterThan(0);
    expect(defaultClamdSockets('darwin').length).toBeGreaterThan(0);
    expect(defaultClamdSockets('win32')).toEqual([]);
  });
  test('configured Windows named pipe and TCP endpoints are accepted', () => {
    const pipe = parseConfig({ platform: 'win32', scanner: { clamdSockets: ['\\\\.\\pipe\\clamd'] } });
    const tcp = parseConfig({ platform: 'win32', scanner: { clamdSockets: ['tcp://127.0.0.1:3310'] } });
    expect(pipe.scanner.clamdSockets[0]).toBe('\\\\.\\pipe\\clamd'); expect(tcp.scanner.clamdSockets[0]).toBe('tcp://127.0.0.1:3310');
  });
  test('12-hour quarantine cannot be disabled via config', () => { expect(() => parseConfig({ quarantine: { minAgeHours: 0 } })).toThrow(); });
  test('platform is explicit for deterministic testing', () => {
    for (const platform of ['linux', 'darwin', 'win32'] as const) expect(parseConfig({ platform }).platform).toBe(platform);
  });
});
