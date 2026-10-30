import { randomBytes, randomUUID } from 'node:crypto';

export function newId(): string {
  return randomUUID();
}

/** High-entropy token for ownership verification / API keys. */
export function createToken(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

/** Safe text fractions to avoid very long string columns overflowing. */
export function clip(value: string, max = 9000): string {
  return value.length > max ? `${value.slice(0, max)}\n...[truncated]` : value;
}