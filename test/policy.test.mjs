import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig, readToken } from '../dist/policy.js';

const good = () => ({mcpServers: {demo: {command: process.execPath, args: [],
  env: {SYNTHETIC: 'quote"\\value${LITERAL}'}, cwd: process.cwd(), shared: true,
  allowedTools: ['read'], instruction: 'Synthetic'}}});
test('config retains literal data and rejects unsafe scope', () => {
  assert.equal(parseConfig(good()).servers.get('demo').env.SYNTHETIC, 'quote"\\value${LITERAL}');
  for (const mutate of [x => {x.mcpServers.demo.url='https://example.invalid'},
    x => {x.mcpServers.demo.shared=false}, x => {x.mcpServers.demo.allowedTools=[]},
    x => {x.mcpServers.demo.favorite=true}, x => {x.mcpServers.demo.command='node'},
    x => {x.extra=true}, x => {x.mcpServers=JSON.parse('{"__proto__":{}}')}]) {
    const x=good(); mutate(x); assert.throws(() => parseConfig(x), /invalid_config/);
  }
});
test('token requires exact private file and directory modes and rejects symlinks', () => {
  const dir=mkdtempSync(join(tmpdir(),'mcp-token-')); chmodSync(dir,0o700);
  try {
    const path=join(dir,'token'); writeFileSync(path,'a'.repeat(64),{mode:0o600});
    assert.equal(readToken(path),'a'.repeat(64));
    for(const mode of [0o644,0o400,0o700]) {
      chmodSync(path,mode); assert.throws(() => readToken(path), /invalid_token_file/);
    }
    chmodSync(path,0o600); chmodSync(dir,0o755);
    assert.throws(() => readToken(path), /invalid_token_file/); chmodSync(dir,0o700);
    symlinkSync(path,join(dir,'link')); assert.throws(() => readToken(join(dir,'link')));
    symlinkSync(dir,join(dir,'parent-link')); assert.throws(() => readToken(join(dir,'parent-link/token')));
    writeFileSync(path,'short'); assert.throws(() => readToken(path));
  } finally {rmSync(dir,{recursive:true,force:true});}
});
