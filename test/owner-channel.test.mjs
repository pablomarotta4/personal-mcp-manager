import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import { delay } from './helpers.mjs';
const api=await import('../dist/owner-channel.js').catch(()=>({}));
function pair(){let a,b; a=new Duplex({read(){},write(c,e,cb){b.push(c);cb()}});b=new Duplex({read(){},write(c,e,cb){a.push(c);cb()}});return [a,b]}
const capability=(counter,nonce='a')=>BigInt(counter).toString(16).padStart(16,'0')+nonce.repeat(48);
const owner=capability(1),requestId='b'.repeat(32);
test('owner channel acknowledges registered profile capability and rejects wrong profile',async()=>{
 assert.equal(typeof api.OwnerChannel,'function','owner channel is implemented');
 const [node,parent]=pair(),messages=[];parent.on('data',c=>messages.push(...c.toString().trim().split('\n').map(JSON.parse)));
 const channel=new api.OwnerChannel(node,new Set(['demo','other']));
 parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await delay(10);
 assert.deepEqual(messages,[{v:1,type:'ready'},{v:1,type:'ack',requestId}]);
 channel.assertOwner(owner,'demo');assert.throws(()=>channel.assertOwner(owner,'other'),/owner_not_registered/);
 const exits=[];channel.onExit(value=>exits.push(value));parent.write(JSON.stringify({v:1,type:'exit',owner})+'\n');await delay(10);
 assert.deepEqual(exits,[owner]);assert.throws(()=>channel.assertOwner(owner,'demo'),/owner_not_registered/);
 channel.close();parent.destroy();
});
for(const kind of ['unknown_fields','oversized','eof'])test(`owner channel fails closed on ${kind}`,async()=>{
 assert.equal(typeof api.OwnerChannel,'function');const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));
 let failed=0;channel.onFailure(()=>failed++);
 parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await delay(5);
 if(kind==='unknown_fields')parent.write(JSON.stringify({v:1,type:'exit',owner,pid:123})+'\n');
 else if(kind==='oversized')parent.write('x'.repeat(4097));else node.push(null);
 await delay(10);assert.equal(failed,1);assert.throws(()=>channel.assertOwner(owner,'demo'),/owner_channel_failed/);
 channel.close();parent.destroy();
});
test('split/coalesced frames preserve ACK order, duplicate keys and owner resurrection fail closed',async()=>{
 assert.equal(typeof api.OwnerChannel,'function');const [node,parent]=pair(),messages=[];parent.on('data',c=>messages.push(...c.toString().trim().split('\n').map(JSON.parse)));
 const channel=new api.OwnerChannel(node,new Set(['demo']));const registration=JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n';
 parent.write(registration.slice(0,13));parent.write(registration.slice(13)+registration.replace(requestId,'c'.repeat(32)).replace(owner,capability(2)));await delay(5);assert.equal(messages.filter(x=>x.type==='ack').length,2);
 parent.write(JSON.stringify({v:1,type:'exit',owner})+'\n'+registration);await delay(5);assert.equal(channel.isHealthy,false);channel.close();parent.destroy();
 const [second,peer]=pair(),duplicate=new api.OwnerChannel(second,new Set(['demo']));peer.on('data',()=>{});peer.write('{"v":1,"v":1,"type":"exit","owner":"'+owner+'"}\n');await delay(5);assert.equal(duplicate.isHealthy,false);duplicate.close();peer.destroy();
});
test('capability limit rejects admission without evicting registered owners',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']),1);parent.on('data',()=>{});
 parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await delay(5);channel.assertOwner(owner,'demo');
 parent.write(JSON.stringify({v:1,type:'register',requestId:'c'.repeat(32),owner:capability(2,'d'),backend:'demo'})+'\n');await delay(5);assert.equal(channel.isHealthy,false);channel.close();parent.destroy();
});
test('future owner EXIT fails closed before any registration',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});
 parent.write(JSON.stringify({v:1,type:'exit',owner})+'\n');parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await delay(5);
 assert.equal(channel.isHealthy,false);channel.close();parent.destroy();
});
test('duplicate registration request ID while its ACK is pending fails the channel',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});const frame=JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n';parent.write(frame+frame);await delay(5);assert.equal(channel.isHealthy,false);channel.close();parent.destroy();
});
test('intentional channel close does not report an infrastructure failure',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});let failed=0;channel.onFailure(()=>failed++);channel.close();await delay(5);assert.equal(failed,0);parent.destroy();
});
test('more than 1024 owner lifetimes fit a small active-capability budget without replay admission',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']),2);parent.on('data',()=>{});
 try{for(let count=1;count<=1100;count++){
 const value=capability(count),id=BigInt(count).toString(16).padStart(32,'0');parent.write(JSON.stringify({v:1,type:'register',requestId:id,owner:value,backend:'demo'})+'\n');await new Promise(setImmediate);channel.assertOwner(value,'demo');
 parent.write(JSON.stringify({v:1,type:'exit',owner:value})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,true);assert.throws(()=>channel.assertOwner(value,'demo'),/owner_not_registered/);
 }
 parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,false);
 }finally{channel.close();parent.destroy()}
});
for(const counters of [[1,1],[2,1]])test(`registration counters ${counters.join(',')} reject replay or out of order`,async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});
 try{parent.write(JSON.stringify({v:1,type:'register',requestId,owner:capability(counters[0]),backend:'demo'})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,true);
 parent.write(JSON.stringify({v:1,type:'register',requestId:'c'.repeat(32),owner:capability(counters[1],'b'),backend:'demo'})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,false);
 }finally{channel.close();parent.destroy()}
});
test('unknown old EXIT compares the full token and preserves every active owner',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});let exits=0;channel.onExit(()=>exits++);
 try{parent.write(JSON.stringify({v:1,type:'register',requestId,owner:capability(2),backend:'demo'})+'\n');await new Promise(setImmediate);
 for(const value of [capability(1),capability(2,'b')])parent.write(JSON.stringify({v:1,type:'exit',owner:value})+'\n');await new Promise(setImmediate);assert.equal(exits,0);channel.assertOwner(capability(2),'demo');
 parent.write(JSON.stringify({v:1,type:'exit',owner:capability(2)})+'\n');parent.write(JSON.stringify({v:1,type:'exit',owner:capability(2)})+'\n');await new Promise(setImmediate);assert.equal(exits,1);assert.equal(channel.isHealthy,true);
 }finally{channel.close();parent.destroy()}
});
for(const value of [capability(0),'10000000000000000'+'a'.repeat(48),capability(3)])test(`invalid zero, overflow, or future EXIT counter fails closed (${value.length})`,async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});
 try{parent.write(JSON.stringify({v:1,type:'register',requestId,owner:capability(2),backend:'demo'})+'\n');await new Promise(setImmediate);parent.write(JSON.stringify({v:1,type:'exit',owner:value})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,false);
 }finally{channel.close();parent.destroy()}
});
test('zero or overflowing REGISTER counter cannot be admitted',async()=>{
 for(const value of [capability(0),'10000000000000000'+'a'.repeat(48)]){
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});
 try{parent.write(JSON.stringify({v:1,type:'register',requestId,owner:value,backend:'demo'})+'\n');await new Promise(setImmediate);assert.equal(channel.isHealthy,false)}finally{channel.close();parent.destroy()}
 }
});
test('u64 counters remain exact above Number precision and admit the maximum value',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});
 try{for(const counter of [(1n<<53n)+1n,(1n<<53n)+2n,(1n<<64n)-1n]){const value=capability(counter);parent.write(JSON.stringify({v:1,type:'register',requestId:counter.toString(16).padStart(32,'0'),owner:value,backend:'demo'})+'\n');await new Promise(setImmediate);channel.assertOwner(value,'demo');}
 }finally{channel.close();parent.destroy()}
});
test('incomplete incoming frame fails within five seconds and trickle bytes do not extend its lifetime',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});let failed=0;channel.onFailure(()=>failed++);
 try{parent.write(JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n');await new Promise(setImmediate);channel.assertOwner(owner,'demo');
 parent.write('{');await delay(3000);assert.equal(channel.isHealthy,true);parent.write('"');await delay(2200);
 assert.equal(channel.isHealthy,false);assert.equal(failed,1);assert.equal(node.destroyed,true);assert.throws(()=>channel.assertOwner(owner,'demo'),/owner_channel_failed/);
 }finally{channel.close();parent.destroy()}
});
test('completing a partial incoming frame cancels its assembly deadline',async()=>{
 const [node,parent]=pair(),channel=new api.OwnerChannel(node,new Set(['demo']));parent.on('data',()=>{});let failed=0;channel.onFailure(()=>failed++);
 try{const frame=JSON.stringify({v:1,type:'register',requestId,owner,backend:'demo'})+'\n';parent.write(frame.slice(0,1));await delay(10);parent.write(frame.slice(1));await delay(5100);assert.equal(channel.isHealthy,true);assert.equal(failed,0);channel.assertOwner(owner,'demo');
 }finally{channel.close();parent.destroy()}
});
