import { randomUUID } from 'node:crypto';
import { MAX_BACKEND_PROFILES, SafeError } from './policy.js';

export type TrafficCounts = Readonly<{
  catalogRequests: number;
  toolAttempts: number;
  toolSuccesses: number;
  toolFailures: number;
}>;
export type TrafficSnapshot = Readonly<{
  generation: string;
  profiles: Readonly<Record<string, TrafficCounts>>;
}>;
type MutableCounts = {
  catalogRequests: number;
  toolAttempts: number;
  toolSuccesses: number;
  toolFailures: number;
};

const zero = (): MutableCounts => ({ catalogRequests: 0, toolAttempts: 0, toolSuccesses: 0, toolFailures: 0 });

export class TrafficCounters {
  readonly generation = randomUUID();
  readonly #profiles = new Map<string, MutableCounts>();

  constructor(profileIds: Iterable<string>) {
    for (const id of profileIds) {
      if (this.#profiles.has(id) || this.#profiles.size >= MAX_BACKEND_PROFILES) {
        throw new SafeError('invalid_traffic_counter_config');
      }
      this.#profiles.set(id, zero());
    }
  }

  private increment(counts: MutableCounts, field: keyof MutableCounts): void {
    if (counts[field] < Number.MAX_SAFE_INTEGER) counts[field]++;
  }

  recordCatalogRequest(profileId: string): void {
    const counts = this.#profiles.get(profileId);
    if (counts) this.increment(counts, 'catalogRequests');
  }

  beginToolCall(profileId: string): (success: boolean) => void {
    const counts = this.#profiles.get(profileId);
    if (!counts) return () => {};
    this.increment(counts, 'toolAttempts');
    let settled = false;
    return success => {
      if (settled) return;
      settled = true;
      this.increment(counts, success ? 'toolSuccesses' : 'toolFailures');
    };
  }

  snapshot(): TrafficSnapshot {
    const profiles = Object.fromEntries(
      [...this.#profiles].map(([id, counts]) => [id, Object.freeze({ ...counts })]),
    ) as Record<string, TrafficCounts>;
    return Object.freeze({ generation: this.generation, profiles: Object.freeze(profiles) });
  }
}
