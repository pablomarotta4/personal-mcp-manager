import { types } from 'node:util';
import { SafeError } from './policy.js';

export type ProfileBackendCounts = Readonly<{
  backendLive: number | null;
  retained: number | null;
}>;
export type ProfileBackendSnapshot = Readonly<Record<string, ProfileBackendCounts>>;

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && !types.isProxy(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactDataKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!plainRecord(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length
    && actual.every(key => typeof key === 'string' && keys.includes(key))
    && keys.every(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && Object.hasOwn(descriptor, 'value') && descriptor.enumerable === true;
    });
}

/** Validate and copy only the bounded backend counts accepted by control status. */
export function projectProfileBackendCounts(value: unknown, profileIds: readonly string[]): ProfileBackendSnapshot {
  const invalid = (): never => { throw new SafeError('monitoring_counts_invalid'); };
  try {
    if (!exactDataKeys(value, profileIds)) return invalid();
    const profiles = Object.fromEntries(profileIds.map(id => {
      const rawRow = Object.getOwnPropertyDescriptor(value, id)!.value;
      if (!exactDataKeys(rawRow, ['backendLive', 'retained'])) return invalid();
      const count = (field: 'backendLive' | 'retained'): number | null => {
        const item = Object.getOwnPropertyDescriptor(rawRow, field)!.value;
        if (item === null) return null;
        if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0) return invalid();
        return item;
      };
      return [id, { backendLive: count('backendLive'), retained: count('retained') }] as const;
    }));
    return profiles;
  } catch { return invalid(); }
}

export function unavailableProfileBackendCounts(profileIds: readonly string[]): ProfileBackendSnapshot {
  return Object.fromEntries(profileIds.map(id => [id, { backendLive: null, retained: null }]));
}
