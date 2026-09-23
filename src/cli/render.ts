/** stdout = operational chatter; stderr = security alerts + fatals. Spinner only on a TTY. */
const tty = process.stdout.isTTY === true;
const errTty = process.stderr.isTTY === true;
const noColor = process.env['NO_COLOR'] !== undefined;

const paint = (on: boolean, code: string) => (s: string): string => (on && !noColor ? `\x1b[${code}m${s}\x1b[0m` : s);
export const c = {
  dim: paint(tty, '2'),
  green: paint(tty, '32'),
  yellow: paint(tty, '33'),
  bold: paint(tty, '1'),
  alert: paint(errTty, '1;31'),
  warn: paint(errTty, '33'),
};

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export class Spinner {
  private timer: ReturnType<typeof setInterval> | undefined;
  private frame = 0;
  private text = '';

  start(text: string): this {
    this.text = text;
    if (!tty) {
      process.stdout.write(`${text}\n`);
      return this;
    }
    this.timer = setInterval(() => {
      this.frame = (this.frame + 1) % FRAMES.length;
      process.stdout.write(`\r\x1b[2K${c.dim(FRAMES[this.frame] ?? '')} ${this.text}`);
    }, 80);
    this.timer.unref?.();
    return this;
  }

  update(text: string): void {
    this.text = text;
  }

  stop(final?: string): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
    if (tty) process.stdout.write('\r\x1b[2K');
    if (final !== undefined) process.stdout.write(`${final}\n`);
  }
}

/** Grep-able one-liner on stderr. Never animated, never interleaved with the spinner line. */
export function securityAlert(event: string, fields: Readonly<Record<string, string | number>>): void {
  const kv = Object.entries(fields).map(([k, v]) => `${k}=${v}`).join(' ');
  process.stderr.write(`${c.alert('[SNPM-SECURITY]')} ${event} ${kv}\n`);
}

export function securityWarn(event: string, fields: Readonly<Record<string, string | number>>): void {
  const kv = Object.entries(fields).map(([k, v]) => `${k}=${v}`).join(' ');
  process.stderr.write(`${c.warn('[SNPM-WARN]')} ${event} ${kv}\n`);
}
