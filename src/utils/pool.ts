/**
 * Bounded async pool with two independent limits:
 *  - slots: max concurrently running jobs (protects file descriptors / sockets)
 *  - bytes: max estimated bytes in flight (protects RSS on large tarballs)
 * Strict FIFO: a big job at the head blocks smaller ones behind it, so nothing starves.
 * A single job larger than the whole budget is clamped so it can still run alone.
 */
interface Waiter {
  readonly bytes: number;
  readonly resolve: () => void;
}

export interface PoolStats {
  readonly active: number;
  readonly bytesInFlight: number;
  readonly queued: number;
  readonly peakActive: number;
  readonly peakBytes: number;
}

export class BoundedPool {
  private active = 0;
  private bytes = 0;
  private peakActive = 0;
  private peakBytes = 0;
  private readonly queue: Waiter[] = [];

  constructor(
    readonly maxConcurrent: number,
    readonly maxBytes: number = Number.POSITIVE_INFINITY,
  ) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
      throw new RangeError(`maxConcurrent must be a positive integer, got ${maxConcurrent}`);
    }
    if (!(maxBytes > 0)) throw new RangeError(`maxBytes must be > 0, got ${maxBytes}`);
  }

  async run<T>(job: () => Promise<T>, estimatedBytes = 0): Promise<T> {
    const cost = Math.min(Math.max(0, estimatedBytes), this.maxBytes);
    await this.acquire(cost);
    try {
      return await job();
    } finally {
      this.release(cost);
    }
  }

  stats(): PoolStats {
    return {
      active: this.active,
      bytesInFlight: this.bytes,
      queued: this.queue.length,
      peakActive: this.peakActive,
      peakBytes: this.peakBytes,
    };
  }

  private fits(cost: number): boolean {
    return this.active < this.maxConcurrent && this.bytes + cost <= this.maxBytes;
  }

  private take(cost: number): void {
    this.active += 1;
    this.bytes += cost;
    if (this.active > this.peakActive) this.peakActive = this.active;
    if (this.bytes > this.peakBytes) this.peakBytes = this.bytes;
  }

  private acquire(cost: number): Promise<void> {
    if (this.queue.length === 0 && this.fits(cost)) {
      this.take(cost);
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.queue.push({ bytes: cost, resolve });
    });
  }

  private release(cost: number): void {
    this.active -= 1;
    this.bytes -= cost;
    for (;;) {
      const head = this.queue[0];
      if (head === undefined || !this.fits(head.bytes)) break;
      this.queue.shift();
      this.take(head.bytes);
      head.resolve();
    }
  }
}

/**
 * Promise memo with single-flight semantics: concurrent callers for the same key share
 * one in-flight request. Failures are evicted so a transient error isn't cached forever.
 * `peek` returns an already-settled value synchronously (no microtask hop). Settlement is
 * recorded explicitly instead of via Bun.peek, so correctness never depends on engine
 * promise internals and the same code runs under any test harness.
 */
export class SingleFlight<K, V> {
  private readonly inflight = new Map<K, Promise<V>>();
  private readonly settled = new Map<K, V>();

  get(key: K, load: () => Promise<V>): Promise<V> {
    const hit = this.inflight.get(key);
    if (hit !== undefined) return hit;
    const p = load().then(
      (v) => {
        this.settled.set(key, v);
        return v;
      },
      (err: unknown) => {
        this.inflight.delete(key);
        throw err;
      },
    );
    this.inflight.set(key, p);
    return p;
  }

  peek(key: K): V | undefined {
    return this.settled.get(key);
  }

  get size(): number {
    return this.inflight.size;
  }
}
