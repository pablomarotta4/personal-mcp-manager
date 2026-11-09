import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, chmodSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const api = await import('../dist/manifest.js').catch(() => ({}));
function fixture() {
  const description = {
    serverInfo: { name: 'fixture', version: '1', title: 'Synthetic MCP' },
    capabilities: { tools: {} },
    instructions: 'Use synthetic data only.',
    tools: [{ name: 'read', title: 'Read', inputSchema: { type: 'object', additionalProperties: false },
      outputSchema: { type: 'object' }, _meta: { custom: { preserved: true } } }],
  };
  return { version: 1, backendId: 'demo', allowedTools: ['read'],
    provenance: { sourceIdentity: 'fixture:synthetic-v1', artifactSha256: 'a'.repeat(64),
      policyDigest: 'b'.repeat(64), reviewedAt: '2026-10-13T00:00:00.000Z' },
    description, fingerprint: api.fingerprintDescription?.(description) };
}

test('manifest supports a full immutable original description without synthesizing annotations', () => {
  assert.equal(typeof api.parseManifest, 'function', 'reviewed manifest parser is implemented');
  const input = fixture(), value = api.parseManifest(input);
  assert.deepEqual(value, input);
  assert.equal(Object.hasOwn(value.description.tools[0], 'annotations'), false);
  input.description.tools[0].name = 'mutated';
  assert.equal(value.description.tools[0].name, 'read');
  assert.throws(() => { value.description.tools[0].name = 'mutated'; }, TypeError);
});

test('fingerprint ignores object key order but covers capability, instruction, version, and complete schema changes', () => {
  assert.equal(typeof api.fingerprintDescription, 'function');
  const { description } = fixture();
  const reversed = Object.fromEntries(Object.entries(description).reverse());
  assert.equal(api.fingerprintDescription(description), api.fingerprintDescription(reversed));
  for (const mutate of [
    v => { v.serverInfo.version = '2'; },
    v => { v.instructions += ' changed'; },
    v => { v.tools[0].annotations = { readOnlyHint: true }; },
    v => { v.tools[0]._meta.custom.preserved = false; },
    v => { v.tools[0].outputSchema.additionalProperties = false; },
    v => { v.capabilities.tools.listChanged = false; },
  ]) {
    const changed = structuredClone(description); mutate(changed);
    assert.notEqual(api.fingerprintDescription(description), api.fingerprintDescription(changed));
  }
});

test('manifest refuses unsupported advertised behavior, unknown credentials, malformed schema, and drift', () => {
  assert.equal(typeof api.parseManifest, 'function');
  for (const mutate of [
    v => { v.description.capabilities.resources = {}; },
    v => { v.description.capabilities.prompts = {}; },
    v => { v.description.capabilities.logging = {}; },
    v => { v.description.capabilities.tasks = {}; },
    v => { v.description.capabilities.experimental = { unreviewed: {} }; },
    v => { v.description.capabilities.completions = {}; },
    v => { v.description.capabilities.extensions = {}; },
    v => { v.description.tools[0].execution = { taskSupport: 'optional' }; },
    v => { v.description.tools[0].inputSchema.type = 'string'; },
    v => { v.env = { TOKEN: 'SYNTHETIC' }; },
    v => { v.provenance.env = {}; },
    v => { delete v.provenance.policyDigest; },
  ]) {
    const value = fixture(); mutate(value);
    value.fingerprint = api.fingerprintDescription(value.description);
    assert.throws(() => api.parseManifest(value), /invalid_manifest/);
  }
  const drift = fixture(); drift.fingerprint = '0'.repeat(64);
  assert.throws(() => api.parseManifest(drift), /invalid_manifest/);
});
test('empty native experimental capability is preserved without admitting any extension',()=>{
 const value=fixture();value.description.capabilities.experimental={};value.fingerprint=api.fingerprintDescription(value.description);
 assert.deepEqual(api.parseManifest(value).description.capabilities.experimental,{});
 for(const experimental of [{unreviewed:{}},null,[],true]){value.description.capabilities.experimental=experimental;value.fingerprint=api.fingerprintDescription(value.description);assert.throws(()=>api.parseManifest(value),/invalid_manifest/)}
});

function catalogFixture() {
  const value = fixture();
  value.description.capabilities = { tools: { listChanged: true }, resources: { listChanged: true, subscribe: false }, prompts: { listChanged: true } };
  value.description.resources = [{ uri: 'synthetic://docs/readme', name: 'Readme', title: 'Synthetic resource',
    mimeType: 'text/plain', size: 42, annotations: { audience: ['user'], priority: 0.5 }, _meta: { preserved: true } }];
  value.description.resourceTemplates = [];
  value.description.prompts = [];
  value.fingerprint = api.fingerprintDescription(value.description);
  return value;
}

test('reviewed complete resource catalog and empty template/prompt catalogs preserve native capabilities', () => {
  const input = catalogFixture();
  assert.deepEqual(api.parseManifest(input), input);
  const changed = structuredClone(input.description); changed.resources[0]._meta.preserved = false;
  assert.notEqual(api.fingerprintDescription(changed), input.fingerprint);
});

test('resource eligibility rejects dynamic templates, prompts, subscriptions, duplicate URI, or missing catalogs', () => {
  for (const mutate of [
    v => { v.description.resourceTemplates = [{ name: 'dynamic', uriTemplate: 'synthetic://docs/{name}' }]; },
    v => { v.description.prompts = [{ name: 'dynamic' }]; },
    v => { v.description.capabilities.resources.subscribe = true; },
    v => { v.description.resources.push(structuredClone(v.description.resources[0])); },
    v => { v.description.resources[0].uri = ''; },
    v => { v.description.resources[0].uri = 'synthetic:\0secret'; },
    v => { v.description.resources[0].mimeType = 42; },
    v => { delete v.description.resources; },
    v => { delete v.description.resourceTemplates; },
    v => { delete v.description.prompts; },
    v => { delete v.description.capabilities.resources; },
    v => { delete v.description.capabilities.prompts; },
  ]) {
    const value = catalogFixture(); mutate(value); value.fingerprint = api.fingerprintDescription(value.description);
    assert.throws(() => api.parseManifest(value), /invalid_manifest/);
  }
});

test('logging capability requires an explicit reviewed no-notification provenance mode', () => {
  const input = fixture();
  input.description.capabilities.logging = {};
  input.provenance.logging = 'no-backend-notifications';
  input.fingerprint = api.fingerprintDescription(input.description);
  assert.deepEqual(api.parseManifest(input), input);
  for (const mutate of [
    v => { delete v.provenance.logging; },
    v => { v.provenance.logging = 'shared'; },
    v => { delete v.description.capabilities.logging; },
    v => { v.description.capabilities.logging.unreviewed = true; },
  ]) {
    const changed = structuredClone(input); mutate(changed); changed.fingerprint = api.fingerprintDescription(changed.description);
    assert.throws(() => api.parseManifest(changed), /invalid_manifest/);
  }
});

test('manifest refuses silently narrowed, duplicated, or widened effective tool sets', () => {
  assert.equal(typeof api.parseManifest, 'function');
  for (const mutate of [
    v => { v.allowedTools = []; },
    v => { v.allowedTools.push('write'); },
    v => { v.allowedTools.push('read'); },
    v => { v.description.tools.push(structuredClone(v.description.tools[0])); },
  ]) {
    const value = fixture(); mutate(value);
    value.fingerprint = api.fingerprintDescription(value.description);
    assert.throws(() => api.parseManifest(value), /invalid_manifest/);
  }
});

test('private manifest file must have exact 0600 mode inside owner-only 0700 directory, never a symlink', () => {
  assert.equal(typeof api.readManifest, 'function');
  const dir = mkdtempSync(join(tmpdir(), 'mcp-manifest-test-'));
  const path = join(dir, 'manifest.json');
  try {
    chmodSync(dir, 0o700); writeFileSync(path, JSON.stringify(fixture()), { mode: 0o600 });
    assert.equal(api.readManifest(path).backendId, 'demo');
    for (const mode of [0o644, 0o400, 0o660]) {
      chmodSync(path, mode); assert.throws(() => api.readManifest(path), /invalid_manifest/);
    }
    chmodSync(path, 0o600); chmodSync(dir, 0o755);
    assert.throws(() => api.readManifest(path), /invalid_manifest/);
    chmodSync(dir, 0o700);
    const link = join(dir, 'link.json'); symlinkSync(path, link);
    assert.throws(() => api.readManifest(link), /invalid_manifest/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('manifest rejects non-JSON values and excessive input without echoing source content', () => {
  assert.equal(typeof api.parseManifest, 'function');
  for (const marker of [NaN, undefined, 1n, () => {}, Infinity]) {
    const value = fixture(); value.description.tools[0]._meta.marker = marker;
    assert.throws(() => api.parseManifest(value), /^Error: invalid_manifest$/);
  }
  const value = fixture(); value.description.tools[0]._meta.self = value;
  assert.throws(() => api.parseManifest(value), /^Error: invalid_manifest$/);
  assert.throws(() => api.parseManifest({ credential: 'SYNTHETIC_CREDENTIAL' }), /^Error: invalid_manifest$/);
  const huge = fixture(); huge.description.instructions = 'a'.repeat(2 * 1024 * 1024 + 1);
  assert.throws(() => api.parseManifest(huge), /^Error: invalid_manifest$/);
});
