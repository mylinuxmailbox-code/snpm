import { describe, expect, test } from 'bun:test';
import { defaultClamdEndpoints, runtimeSignals } from '../../src/utils/platform.ts';

describe('cross-platform runtime policy', () => {
  test('Linux and macOS use configurable Unix socket candidates', () => {
    expect(defaultClamdEndpoints('linux').length).toBeGreaterThan(0);
    expect(defaultClamdEndpoints('darwin').length).toBeGreaterThan(0);
  });
  test('Windows avoids Unix-only defaults and uses configured endpoint support', () => {
    expect(defaultClamdEndpoints('win32')).toEqual([]);
    expect(runtimeSignals('win32')).toEqual({ interrupt: 'SIGINT' });
  });
  test('POSIX gets SIGTERM cleanup while Windows stays portable', () => {
    expect(runtimeSignals('linux').terminate).toBe('SIGTERM');
    expect(runtimeSignals('darwin').terminate).toBe('SIGTERM');
  });
});
