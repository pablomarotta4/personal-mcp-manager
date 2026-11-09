import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CallToolResultSchema, ErrorCode, ToolListChangedNotificationSchema, ResourceListChangedNotificationSchema,
  PromptListChangedNotificationSchema, EmptyResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadDist } from './helpers/private-dist.mjs';

const { CompletedBackendError } = await loadDist('pool.js');
const api = await loadDist('facade.js').catch(() => ({}));
const manifestApi = await loadDist('manifest.js');
const trafficApi = await loadDist('traffic-counters.js').catch(() => ({}));
test('completed native JSON-RPC errors preserve their code and data',async()=>{
  const state=await connect({call:async()=>{throw new CompletedBackendError(-32602,'synthetic_invalid',{field:'query'});}});
  try{await assert.rejects(state.client.callTool({name:'read',arguments:{}}),error=>{
    assert.equal(error.code,-32602);assert.deepEqual(error.data,{field:'query'});
    assert.equal(error.message,'MCP error -32602: synthetic_invalid');return true;
  });}finally{await state.close();}
});
function fixture() {
  const description = { serverInfo: { name: 'native-fixture', version: '1.2', title: 'Native' },
    capabilities: { tools: {} }, instructions: 'Original instructions.', tools: [
      { name: 'read', description: 'Original description', inputSchema: { type: 'object' },
        outputSchema: { type: 'object' }, annotations: { readOnlyHint: true }, _meta: { sample: 1 } },
      { name: 'unannotated', inputSchema: { type: 'object' } },
    ] };
  return manifestApi.parseManifest({ version: 1, backendId: 'demo', allowedTools: ['read', 'unannotated'],
    provenance: { sourceIdentity: 'fixture:synthetic-v1', artifactSha256: 'a'.repeat(64),
      policyDigest: 'b'.repeat(64), reviewedAt: '2026-10-13T00:00:00.000Z' },
    description, fingerprint: manifestApi.fingerprintDescription(description) });
}
async function connect(pool, manifest = fixture(), counters) {
  assert.equal(typeof api.createFacade, 'function', 'transparent facade is implemented');
  const server = api.createFacade(manifest, { assertManifestValid: () => {}, onManifestInvalidated: () => () => {}, ...pool }, counters);
  const client = new Client({ name: 'synthetic-client', version: '1' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a); await client.connect(b);
  return { server, client, manifest, serverTransport: a, close: async () => { await client.close(); await server.close(); } };
}

test('cold initialize and list are identical to reviewed native metadata and never start a backend', async () => {
  let calls = 0;
  const state = await connect({ call: async () => { calls++; throw Error('must stay cold'); } });
  try {
    assert.deepEqual(state.client.getServerVersion(), state.manifest.description.serverInfo);
    assert.deepEqual(state.client.getServerCapabilities(), state.manifest.description.capabilities);
    assert.equal(state.client.getInstructions(), state.manifest.description.instructions);
    assert.deepEqual((await state.client.listTools()).tools, state.manifest.description.tools);
    assert.equal(calls, 0); assert.equal(state.server.activeCalls, 0);
  } finally { await state.close(); }
});

function catalogFixture(id = 'demo') {
  const value = structuredClone(fixture());
  value.backendId = id;
  value.description.capabilities = { tools: { listChanged: true }, resources: { listChanged: true }, prompts: { listChanged: true } };
  value.description.resources = [{ uri: 'synthetic://docs/readme', name: 'Readme', title: 'Native resource',
    mimeType: 'text/plain', annotations: { audience: ['user'], priority: 0.5 }, _meta: { preserved: true } }];
  value.description.resourceTemplates = [];
  value.description.prompts = [];
  value.fingerprint = manifestApi.fingerprintDescription(value.description);
  return manifestApi.parseManifest(value);
}

test('cold resource, template, and prompt catalogs match native metadata and only check manifest validity', async () => {
  let dispatches = 0;
  const checks = [];
  const state = await connect({ assertManifestValid: id => checks.push(id),
    call: async () => { dispatches++; throw Error('stay cold'); },
    readResource: async () => { dispatches++; throw Error('stay cold'); },
  }, catalogFixture());
  try {
    assert.deepEqual((await state.client.listResources()).resources, state.manifest.description.resources);
    assert.deepEqual(await state.client.listResourceTemplates(), { resourceTemplates: [] });
    assert.deepEqual(await state.client.listPrompts(), { prompts: [] });
    assert.equal(dispatches, 0); assert.deepEqual(checks, ['demo', 'demo', 'demo']);
  } finally { await state.close(); }
});

test('validated catalog handlers count one request each and ignore invalid cursors', async () => {
  const counters = new trafficApi.TrafficCounters(['demo']);
  const state = await connect({ call: async () => ({ content: [] }) }, catalogFixture(), counters);
  try {
    await state.client.listTools();
    await state.client.listResources();
    await state.client.listResourceTemplates();
    await state.client.listPrompts();
    assert.equal(counters.snapshot().profiles.demo.catalogRequests, 4);
    await assert.rejects(state.client.listTools({ cursor: 'unreviewed' }), error => error.code === ErrorCode.InvalidParams);
    assert.equal(counters.snapshot().profiles.demo.catalogRequests, 4);
  } finally { await state.close(); }
});

test('allowed tool outcomes are aggregated without counting rejected tool requests', async () => {
  const counters = new trafficApi.TrafficCounters(['demo']);
  let mode = 'success';
  const state = await connect({ call: async () => {
    if (mode === 'throw') throw Error('synthetic backend failure');
    return mode === 'tool-error' ? { content: [{ type: 'text', text: 'Synthetic tool error.' }], isError: true } : { content: [] };
  } }, fixture(), counters);
  try {
    await state.client.callTool({ name: 'read', arguments: {} });
    mode = 'tool-error';
    await state.client.callTool({ name: 'read', arguments: {} });
    mode = 'throw';
    await assert.rejects(state.client.callTool({ name: 'read', arguments: {} }), error => error.code === ErrorCode.InternalError);
    await assert.rejects(state.client.callTool({ name: 'unknown', arguments: {} }), error => error.code === ErrorCode.InvalidParams);
    await assert.rejects(state.client.request({ method: 'tools/call', params: { name: 'read', task: { ttl: 1000 } } }, CallToolResultSchema));
    assert.deepEqual(counters.snapshot().profiles.demo, {
      catalogRequests: 0, toolAttempts: 3, toolSuccesses: 1, toolFailures: 2,
    });
  } finally { await state.close(); }
});

test('resource reads bind an exact reviewed URI and preserve text/blob/meta results and call context', async () => {
  const result = { contents: [
    { uri: 'synthetic://docs/readme', text: 'Synthetic resource.', mimeType: 'text/plain', _meta: { original: 1 } },
    { uri: 'synthetic://docs/readme', blob: 'AAEC', mimeType: 'application/octet-stream' },
  ], _meta: { native: 'preserved' } };
  const seen = [], progress = [];
  const state = await connect({ readResource: async (...args) => {
    seen.push(args); args[2].onProgress({ progress: 1, total: 1 }); return result;
  } }, catalogFixture());
  try {
    assert.deepEqual(await state.client.readResource({ uri: 'synthetic://docs/readme', _meta: { original: 'retained' } },
      { onprogress: value => progress.push(value) }), result);
    assert.deepEqual(seen[0].slice(0, 2), ['demo', 'synthetic://docs/readme']);
    assert.equal(seen[0][2].meta.original, 'retained'); assert(seen[0][2].signal instanceof AbortSignal);
    assert.equal(progress.length, 1); assert.equal(state.server.activeCalls, 0);
    for (const uri of ['synthetic://docs/other', 'synthetic://docs/readme?other=1', 'synthetic://docs/../docs/readme']) {
      await assert.rejects(state.client.readResource({ uri }), error => error.code === ErrorCode.InvalidParams);
    }
    assert.equal(seen.length, 1);
  } finally { await state.close(); }
});

test('resource cancellation reaches the facade pool contract without discarding another session\'s read', { timeout: 2000 }, async () => {
  let entered, observed;
  const started = new Promise(resolve => { entered = resolve; });
  const cancelled = new Promise(resolve => { observed = resolve; });
  const pool = { readResource: async (id, uri, context) => {
    if (context.meta?.cancel) {
      entered(); await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }));
      observed(); throw Error('cancelled');
    }
    return { contents: [{ uri, text: 'Independent read.' }] };
  } };
  const first = await connect(pool, catalogFixture()), second = await connect(pool, catalogFixture());
  const controller = new AbortController();
  try {
    const pending = first.client.readResource({ uri: 'synthetic://docs/readme', _meta: { cancel: true } }, { signal: controller.signal });
    const rejected = assert.rejects(pending);
    await started; assert.equal(first.server.activeCalls, 1);
    const other = await second.client.readResource({ uri: 'synthetic://docs/readme' });
    assert.equal(other.contents[0].text, 'Independent read.');
    controller.abort(); await rejected; await cancelled; await new Promise(resolve => setImmediate(resolve));
    assert.equal(first.server.activeCalls, 0); assert.equal(second.server.activeCalls, 0);
  } finally { await first.close(); await second.close(); }
});

test('resource completion preserves native protocol errors and sanitizes malformed local results', async () => {
  let malformed = false;
  const state = await connect({ readResource: async () => {
    if (malformed) return { contents: [{ uri: 'synthetic://docs/readme', text: { credential: 'SYNTHETIC_CREDENTIAL' } }] };
    throw new CompletedBackendError(-32602, 'synthetic_resource_invalid', { field: 'uri' });
  } }, catalogFixture());
  try {
    await assert.rejects(state.client.readResource({ uri: 'synthetic://docs/readme' }), error => {
      assert.equal(error.code, -32602); assert.deepEqual(error.data, { field: 'uri' }); return true;
    });
    malformed = true;
    await assert.rejects(state.client.readResource({ uri: 'synthetic://docs/readme' }), error => {
      assert.equal(error.code, ErrorCode.InternalError); assert(!error.message.includes('SYNTHETIC_CREDENTIAL')); return true;
    });
    assert.equal(state.server.activeCalls, 0);
  } finally { await state.close(); }
});

test('catalog invalidation notifies only its backend, blocks every operation, and safely unsubscribes on close', async () => {
  const listeners = new Map(), invalid = new Set();
  let dispatches = 0, unsubscribed = 0;
  const pool = { assertManifestValid: id => { if (invalid.has(id)) throw Error('synthetic invalid'); },
    onManifestInvalidated: (id, callback) => { listeners.set(id, callback); return () => { unsubscribed++; listeners.delete(id); }; },
    call: async () => { dispatches++; return { content: [] }; }, readResource: async () => { dispatches++; return { contents: [] }; },
  };
  const first = await connect(pool, catalogFixture('one')), second = await connect(pool, catalogFixture('two'));
  const notifications = [[], []];
  for (const [index, state] of [first, second].entries()) {
    for (const schema of [ToolListChangedNotificationSchema, ResourceListChangedNotificationSchema, PromptListChangedNotificationSchema]) {
      state.client.setNotificationHandler(schema, notification => { notifications[index].push(notification); });
    }
  }
  let closes = 0; first.server.onclose = () => { closes++; };
  try {
    invalid.add('one'); listeners.get('one')('resources');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(notifications[0], [{ method: 'notifications/resources/list_changed' }]);
    assert.deepEqual(notifications[1], []);
    for (const invoke of [() => first.client.listTools(), () => first.client.listResources(),
      () => first.client.listResourceTemplates(), () => first.client.listPrompts(),
      () => first.client.callTool({ name: 'read', arguments: {} }),
      () => first.client.readResource({ uri: 'synthetic://docs/readme' })]) await assert.rejects(invoke(), /manifest_invalidated/);
    assert.equal(dispatches, 0);
    assert.deepEqual((await second.client.listResources()).resources, second.manifest.description.resources);
    await first.close(); assert.equal(closes, 1); assert.equal(unsubscribed, 1); assert(!listeners.has('one'));
  } finally { await first.close(); await second.close(); }
  assert.equal(unsubscribed, 2);
});

test('failed transport startup releases the manifest listener and preserves SDK cleanup callbacks', async () => {
  let unsubscribed = 0, transportClosed = 0, serverClosed = 0;
  const server = api.createFacade(fixture(), { assertManifestValid: () => {},
    onManifestInvalidated: () => () => { unsubscribed++; } });
  server.onclose = () => { serverClosed++; };
  const transport = { start: async () => { throw Error('synthetic_start_failed'); }, send: async () => {},
    close: async () => { transport.onclose?.(); }, onclose: () => { transportClosed++; } };
  await assert.rejects(server.connect(transport), /synthetic_start_failed/);
  assert.equal(unsubscribed, 1);
  await server.close();
  assert.equal(unsubscribed, 1); assert.equal(transportClosed, 1); assert.equal(serverClosed, 1);
});

test('reviewed silent-backend logging levels are validated per frontend without touching the pool', async () => {
  const input = structuredClone(fixture()); input.description.capabilities.logging = {};
  input.provenance.logging = 'no-backend-notifications'; input.fingerprint = manifestApi.fingerprintDescription(input.description);
  const manifest = manifestApi.parseManifest(input);
  let calls = 0;
  const pool = { call: async () => { calls++; throw Error('must stay cold'); } };
  const first = await connect(pool, manifest), second = await connect(pool, manifest);
  try {
    assert.deepEqual(await first.client.setLoggingLevel('debug'), {});
    assert.deepEqual(await second.client.setLoggingLevel('error'), {});
    assert.deepEqual(await first.client.setLoggingLevel('warning'), {});
    await assert.rejects(first.client.request({ method: 'logging/setLevel', params: { level: 'invalid' } }, EmptyResultSchema));
    assert.equal(calls, 0);
  } finally { await first.close(); await second.close(); }
});

test('native tool calls bind the backend and preserve all result fields including tool errors', async () => {
  const result = { content: [{ type: 'text', text: 'Synthetic error.' }], structuredContent: { ok: false },
    isError: true, _meta: { trace: 'synthetic' } };
  const seen = [];
  const state = await connect({ call: async (...args) => { seen.push(args); return result; } });
  try {
    assert.deepEqual(await state.client.callTool({ name: 'read', arguments: { query: 'synthetic' } }), result);
    assert.deepEqual(seen[0].slice(0, 3), ['demo', 'read', { query: 'synthetic' }]);
    assert.equal(state.server.activeCalls, 0);
  } finally { await state.close(); }
});

test('omitted arguments stay absent instead of becoming an empty object', async () => {
  const seen = [];
  const state = await connect({ call: async (...args) => { seen.push(args); return { content: [] }; } });
  try {
    await state.client.callTool({ name: 'unannotated' });
    assert.equal(seen[0][2], undefined);
  } finally { await state.close(); }
});

test('unknown tools and unsupported cursor fail before backend dispatch', async () => {
  let calls = 0;
  const state = await connect({ call: async () => { calls++; return { content: [] }; } });
  try {
    await assert.rejects(state.client.callTool({ name: 'write', arguments: {} }), error => error.code === ErrorCode.InvalidParams);
    await assert.rejects(state.client.listTools({ cursor: 'unreviewed' }), error => error.code === ErrorCode.InvalidParams);
    assert.equal(calls, 0);
  } finally { await state.close(); }
});

test('active call accounting lasts until backend completion and internal errors expose no credentials', async () => {
  let finish;
  const started = new Promise(resolve => { finish = resolve; });
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const state = await connect({ call: async () => { finish(); await pending; throw Error('SYNTHETIC_CREDENTIAL'); } });
  try {
    const result = state.client.callTool({ name: 'read', arguments: {} });
    await started; assert.equal(state.server.activeCalls, 1); release();
    await assert.rejects(result, error => error.code === ErrorCode.InternalError && !error.message.includes('SYNTHETIC_CREDENTIAL'));
    assert.equal(state.server.activeCalls, 0);
  } finally { release(); await state.close(); }
});

test('facade pool contract carries metadata, cancellation signal, and session-bound progress', async () => {
  const seen = [], progress = [];
  const state = await connect({ call: async (id, name, args, context) => {
    seen.push(context); await context.onProgress({ progress: 1, total: 2, message: 'Synthetic progress' });
    return { content: [{ type: 'text', text: 'done' }], structuredContent: { ok: true } };
  } });
  try {
    await state.client.callTool({ name: 'read', arguments: {}, _meta: { custom: 'retained' } }, CallToolResultSchema,
      { onprogress: value => progress.push(value) });
    assert.equal(seen[0].meta.custom, 'retained');
    assert(seen[0].signal instanceof AbortSignal);
    assert.equal(progress.length, 1); assert.equal(progress[0].progress, 1);
  } finally { await state.close(); }
});

test('two sessions with coincident progress tokens never receive one another\'s progress', { timeout: 2000 }, async () => {
  let entered = 0, bothEntered;
  const barrier = new Promise(resolve => { bothEntered = resolve; });
  const pool = { call: async (id, name, args, context) => {
    if (++entered === 2) bothEntered();
    await barrier;
    await context.onProgress({ progress: 1, message: args.session });
    return { content: [], structuredContent: { ok: true } };
  } };
  const first = await connect(pool), second = await connect(pool);
  const one = [], two = [];
  try {
    await Promise.all([
      first.client.callTool({ name: 'read', arguments: { session: 'one' } }, CallToolResultSchema, { onprogress: value => one.push(value) }),
      second.client.callTool({ name: 'read', arguments: { session: 'two' } }, CallToolResultSchema, { onprogress: value => two.push(value) }),
    ]);
    assert.deepEqual(one.map(value => value.message), ['one']);
    assert.deepEqual(two.map(value => value.message), ['two']);
  } finally { await first.close(); await second.close(); }
});

test('client cancellation reaches the facade pool contract and its active accounting drains', { timeout: 2000 }, async () => {
  let entered, observed;
  const started = new Promise(resolve => { entered = resolve; });
  const cancelled = new Promise(resolve => { observed = resolve; });
  const state = await connect({ call: async (id, name, args, context) => {
    entered();
    await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }));
    observed();
    throw Error('cancelled');
  } });
  const controller = new AbortController();
  try {
    const pending = state.client.callTool({ name: 'read', arguments: {} }, CallToolResultSchema, { signal: controller.signal });
    const rejected = assert.rejects(pending);
    await started; controller.abort(); await rejected; await cancelled;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(state.server.activeCalls, 0);
  } finally { await state.close(); }
});

test('fire-and-forget progress handles a rejecting client transport without an unhandled rejection', { timeout: 2000 }, async () => {
  const unhandled = [];
  const observe = error => unhandled.push(error);
  process.on('unhandledRejection', observe);
  let notificationAttempts = 0;
  const state = await connect({ call: async (id, name, args, context) => {
    // SDK progress callbacks are not awaited; deliberately model that contract here.
    context.onProgress({ progress: 1, message: 'synthetic' });
    return { content: [], structuredContent: { ok: true } };
  } });
  const originalSend = state.serverTransport.send.bind(state.serverTransport);
  state.serverTransport.send = async message => {
    if (message.method === 'notifications/progress') {
      notificationAttempts++;
      throw Error('synthetic_disconnected_transport');
    }
    return originalSend(message);
  };
  try {
    const result = await state.client.callTool({ name: 'read', arguments: {} }, CallToolResultSchema, { onprogress: () => {} });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(notificationAttempts, 1);
    assert.deepEqual(unhandled, []);
    assert.equal(result.structuredContent.ok, true);
    assert.equal(state.server.activeCalls, 0);
  } finally {
    process.off('unhandledRejection', observe);
    await state.close();
  }
});
