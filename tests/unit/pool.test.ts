import { describe, expect, test } from 'bun:test';
import { BoundedPool, SingleFlight } from '../../src/utils/pool.ts';

describe('BoundedPool', () => {
  test('never exceeds slot limit', async () => {
    const pool = new BoundedPool(3);
    let live = 0;
    let peak = 0;
    await Promise.all(
      Array.from({ length: 50 }, () =>
        pool.run(async () => {
          live += 1;
          peak = Math.max(peak, live);
          await Bun.sleep(1);
          live -= 1;
        }),
      ),
    );
    expect(peak).toBe(3);
    expect(pool.stats()).toMatchObject({ active: 0, bytesInFlight: 0, queued: 0 });
  });

  test('byte budget throttles below slot limit', async () => {
    const pool = new BoundedPool(10, 100);
    await Promise.all(Array.from({ length: 20 }, () => pool.run(() => Bun.sleep(1), 40)));
    expect(pool.stats().peakActive).toBe(2); // 40+40 <= 100 < 40*3
    expect(pool.stats().peakBytes).toBeLessThanOrEqual(100);
  });

  test('oversize job is clamped and still runs', async () => {
    const pool = new BoundedPool(4, 100);
    expect(await pool.run(async () => 'ok', 10_000)).toBe('ok');
  });

  test('releases slot when job throws', async () => {
    const pool = new BoundedPool(1);
    await expect(pool.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(await pool.run(async () => 42)).toBe(42);
  });

  test('FIFO: large head job is not starved by small ones', async () => {
    const pool = new BoundedPool(10, 100);
    const order: string[] = [];
    const a = pool.run(async () => { await Bun.sleep(5); order.push('a'); }, 60);
    const big = pool.run(async () => { order.push('big'); }, 100);
    const small = pool.run(async () => { order.push('small'); }, 10);
    await Promise.all([a, big, small]);
    expect(order.indexOf('big')).toBeLessThan(order.indexOf('small'));
  });

  test('rejects bad limits', () => {
    expect(() => new BoundedPool(0)).toThrow(RangeError);
    expect(() => new BoundedPool(1, 0)).toThrow(RangeError);
  });
});

describe('SingleFlight', () => {
  test('dedups concurrent loads and peeks settled values synchronously', async () => {
    const sf = new SingleFlight<string, number>();
    let calls = 0;
    const load = async (): Promise<number> => { calls += 1; await Bun.sleep(1); return 7; };
    const [x, y] = await Promise.all([sf.get('k', load), sf.get('k', load)]);
    expect([x, y, calls]).toEqual([7, 7, 1]);
    expect(sf.peek('k')).toBe(7);
    expect(sf.peek('missing')).toBeUndefined();
  });

  test('evicts failures so retries can succeed', async () => {
    const sf = new SingleFlight<string, number>();
    await expect(sf.get('k', async () => { throw new Error('x'); })).rejects.toThrow('x');
    expect(await sf.get('k', async () => 1)).toBe(1);
  });
});
