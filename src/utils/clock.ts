/** Injectable time source. Tests pass a fixed clock; prod uses the system clock. */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

export const fixedClock = (epochMs: number): Clock => ({ now: () => epochMs });
