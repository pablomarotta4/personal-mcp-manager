import test from 'node:test';
import assert from 'node:assert/strict';
import { loadDist } from './helpers/private-dist.mjs';

const api = await loadDist('traffic-counters.js').catch(() => ({}));
const {MAX_BACKEND_PROFILES} = await loadDist('policy.js');
test('traffic counter module is implemented', () => {
  assert.equal(typeof api.TrafficCounters, 'function', 'traffic counters are implemented');
});

if (typeof api.TrafficCounters === 'function') {
  const { TrafficCounters } = api;
  const fields = ['catalogRequests', 'toolAttempts', 'toolSuccesses', 'toolFailures'];

  test('seeds only known profiles with zero safe integer counters', () => {
    const counters = new TrafficCounters(['alpha', 'beta']);
    const snapshot = counters.snapshot();
    assert.deepEqual(Object.keys(snapshot.profiles), ['alpha', 'beta']);
    assert.deepEqual(snapshot.profiles.alpha, {
      catalogRequests: 0, toolAttempts: 0, toolSuccesses: 0, toolFailures: 0,
    });
    assert.deepEqual(Object.keys(snapshot.profiles.alpha), fields);
    for (const row of Object.values(snapshot.profiles)) {
      for (const count of Object.values(row)) assert(Number.isSafeInteger(count) && count >= 0);
    }
  });

  test('rejects duplicate and over-limit profile sets', () => {
    assert.throws(() => new TrafficCounters(['alpha', 'alpha']), { code: 'invalid_traffic_counter_config' });
    const overLimit = Array.from({ length: MAX_BACKEND_PROFILES+1 }, (_, index) => `profile-${index}`);
    assert.throws(() => new TrafficCounters(overLimit), { code: 'invalid_traffic_counter_config' });
  });

  test('counts catalog requests and settles each tool outcome at most once', () => {
    const counters = new TrafficCounters(['alpha']);
    counters.recordCatalogRequest('alpha');
    const success = counters.beginToolCall('alpha');
    assert.equal(counters.snapshot().profiles.alpha.toolAttempts, 1);
    success(true);
    success(false);
    const failure = counters.beginToolCall('alpha');
    failure(false);
    assert.deepEqual(counters.snapshot().profiles.alpha, {
      catalogRequests: 1, toolAttempts: 2, toolSuccesses: 1, toolFailures: 1,
    });
  });

  test('unknown profile updates do not add rows or change known counters', () => {
    const counters = new TrafficCounters(['alpha']);
    counters.recordCatalogRequest('unknown');
    counters.beginToolCall('unknown')(true);
    assert.deepEqual(Object.keys(counters.snapshot().profiles), ['alpha']);
    assert.deepEqual(counters.snapshot().profiles.alpha, {
      catalogRequests: 0, toolAttempts: 0, toolSuccesses: 0, toolFailures: 0,
    });
  });

  test('returns detached frozen snapshots and resets only with a new generation', () => {
    const first = new TrafficCounters(['alpha']);
    const original = first.snapshot();
    assert(Object.isFrozen(original));
    assert(Object.isFrozen(original.profiles));
    assert(Object.isFrozen(original.profiles.alpha));
    assert.match(original.generation, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.throws(() => { original.profiles.alpha.toolAttempts = 9; }, TypeError);
    first.beginToolCall('alpha')(true);
    assert.equal(original.profiles.alpha.toolAttempts, 0);
    assert.equal(first.snapshot().profiles.alpha.toolAttempts, 1);

    const next = new TrafficCounters(['alpha']);
    assert.notEqual(next.generation, first.generation);
    assert.equal(next.snapshot().profiles.alpha.toolAttempts, 0);
  });
}
