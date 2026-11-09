import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { InitializeRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { types } from 'node:util';
import { SafeError, MAX_BACKEND_PROFILES } from './policy.js';
import type { OwnerChannel } from './owner-channel.js';
import { projectProfileBackendCounts, unavailableProfileBackendCounts, type ProfileBackendSnapshot } from './monitoring.js';

export interface HttpServerOptions {
  host: string;
  port: number;
  expectedToken: string;
  buildServer: (path?: string,owner?:string) => McpServer | Promise<McpServer>;
  statefulRoutes?:Set<string>;
  owners?:OwnerChannel;
  getRetained?:()=>number;
  routes?: Set<string>;
  sessionIdleTimeoutMs?: number;
  maxSessions?: number;
  maxRequests?: number;
  bodyTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  maintenanceTimeoutMs?: number;
  getActive?: () => number;
  getBackendCounts?: () => Readonly<{ starts: number; live: number }>;
  getTrafficCounts?: () => unknown;
  getProfileMonitoringCounts?: () => unknown;
  onShutdown?: () => Promise<void>;
}
type TrafficRow = { catalogRequests: number; toolAttempts: number; toolSuccesses: number; toolFailures: number };
type TrafficProjection = { generation: string; profiles: Record<string, TrafficRow> };
const trafficFields = ['catalogRequests', 'toolAttempts', 'toolSuccesses', 'toolFailures'] as const;
const trafficGeneration = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

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
function projectTraffic(value: unknown, profileIds: readonly string[]): TrafficProjection {
  const invalid = (): never => { throw new SafeError('traffic_counts_invalid'); };
  try {
    if (!exactDataKeys(value, ['generation', 'profiles'])) return invalid();
    const generation = Object.getOwnPropertyDescriptor(value, 'generation')!.value;
    const rawProfiles = Object.getOwnPropertyDescriptor(value, 'profiles')!.value;
    if (typeof generation !== 'string' || !trafficGeneration.test(generation)
        || !exactDataKeys(rawProfiles, profileIds)) return invalid();
    const profiles = Object.fromEntries(profileIds.map(id => {
      const rawRow = Object.getOwnPropertyDescriptor(rawProfiles, id)!.value;
      if (!exactDataKeys(rawRow, trafficFields)) return invalid();
      const row = Object.fromEntries(trafficFields.map(field => {
        const count = Object.getOwnPropertyDescriptor(rawRow, field)!.value;
        if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) return invalid();
        return [field, count] as const;
      })) as TrafficRow;
      return [id, row] as const;
    }));
    return { generation, profiles };
  } catch { return invalid(); }
}
type Session = {
  server: McpServer & { activeCalls?: number;retained?:()=>boolean;disposeLease?:()=>Promise<void> };
  owner?:string;
  stateful:boolean;
  disposal?:Promise<void>;
  transport: StreamableHTTPServerTransport;
  path: string;
  last: number;
  requests: number;
  subscribed: boolean;
};
const LIMIT = 256 * 1024;
function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new SafeError('invalid_listener_config');
  return value;
}
function reply(res: ServerResponse, status: number, code: string, close = false): void {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) { res.destroy(); return; }
  if (close) res.once('finish', () => res.socket?.destroy());
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(close ? { Connection: 'close' } : {}) });
  res.end(JSON.stringify({ error: code }));
}
function body(req: IncomingMessage, timeout: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const cleanup = () => {
      clearTimeout(timer);
      req.off('data', data); req.off('end', end); req.off('error', bad); req.off('aborted', bad);
    };
    const fail = (code: string) => { cleanup(); req.pause(); reject(new SafeError(code)); };
    const bad = () => fail('invalid_request');
    const data = (chunk: Buffer) => {
      size += chunk.length;
      if (size > LIMIT) { fail('body_too_large'); return; }
      chunks.push(chunk);
    };
    const end = () => {
      cleanup();
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new SafeError('invalid_request')); }
    };
    const timer = setTimeout(() => fail('body_timeout'), timeout);
    timer.unref();
    req.on('data', data); req.once('end', end); req.once('error', bad); req.once('aborted', bad);
  });
}
function initialization(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  return request.jsonrpc === '2.0'
    && (typeof request.id === 'string' || (typeof request.id === 'number' && Number.isFinite(request.id)))
    && InitializeRequestSchema.safeParse(value).success;
}
export async function startHttpServer(opts: HttpServerOptions) {
  if (opts.host !== '127.0.0.1' || !/^[0-9a-f]{64}$/.test(opts.expectedToken)) throw new SafeError('invalid_listener_config');
  bounded(opts.port, 0, 65535);
  const statefulRoutes=new Set(opts.statefulRoutes??[]);
  if(statefulRoutes.size&&!opts.owners)throw new SafeError('owner_channel_required');
  opts.owners?.assertHealthy();
  const max = bounded(opts.maxSessions ?? (statefulRoutes.size?512:128), 1, 512);
  const capacity = bounded(opts.maxRequests ?? 64, 1, 128);
  const idle = bounded(opts.sessionIdleTimeoutMs ?? 300000, 10, 300000);
  const bodyDeadline = bounded(opts.bodyTimeoutMs ?? 15000, 10, 30000);
  const shutdownDeadline = bounded(opts.shutdownTimeoutMs ?? 10000, 10, 30000);
  const maintenanceDeadline = bounded(opts.maintenanceTimeoutMs ?? 660000, 10, 660000);
  const routes = new Set(opts.routes ?? ['/mcp']);
  if (!routes.size || routes.size > MAX_BACKEND_PROFILES + 1 || [...routes].some(path => !/^\/mcp(?:\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})?$/.test(path))) throw new SafeError('invalid_listener_config');
  const profileIds = [...routes].filter(path => path !== '/mcp').map(path => path.slice('/mcp/'.length));
  if (profileIds.length > MAX_BACKEND_PROFILES) throw new SafeError('invalid_listener_config');
  if([...statefulRoutes].some(path=>!routes.has(path)))throw new SafeError('invalid_listener_config');
  const expected = Buffer.from(opts.expectedToken, 'ascii');
  const disposals=new Set<Promise<void>>();let cleanupFailed=false;
  const sessions = new Map<string, Session>();
  const requestsByProfile = new Map(profileIds.map(id => [id, 0]));
  let pending = 0, bodies = 0, requests = 0, controls = 0, stopping = false, draining = false, actualPort = opts.port;
  let lastObservedStarts = 0;
  let maintenanceTimer: NodeJS.Timeout | undefined;
  const maintenanceStatus = () => {
    const active = Math.max(opts.getActive?.() ?? 0, [...sessions.values()].reduce((total, session) => total + (session.server.activeCalls ?? 0), 0));
    const waiting = pending + bodies;
    const retained=opts.getRetained?.()??0;
    return { draining, quiescent: waiting === 0 && requests === 0 && active === 0 && retained===0 && disposals.size===0 && !cleanupFailed, pending: waiting, requests, active,...(statefulRoutes.size?{retained}: {}) };
  };
  const monitoringStatus = () => {
    const profiles = new Map(profileIds.map(id => [id, {
      sessions: 0, idleSessions: 0, busySessions: 0, subscriptions: 0, requests: requestsByProfile.get(id)!, active: 0,
    }]));
    let idleSessions = 0, busySessions = 0, subscriptions = 0;
    try {
      for (const session of sessions.values()) {
        const active = session.server.activeCalls ?? 0;
        if (!Number.isSafeInteger(active) || active < 0 || !Number.isSafeInteger(session.requests) || session.requests < 0) {
          throw new SafeError('monitoring_counts_invalid');
        }
        const inFlight = session.requests - (session.subscribed ? 1 : 0);
        if (inFlight < 0) throw new SafeError('monitoring_counts_invalid');
        const busy = active > 0 || inFlight > 0;
        if (busy) busySessions++; else idleSessions++;
        if (session.subscribed) subscriptions++;
        const id = session.path === '/mcp' ? undefined : session.path.slice('/mcp/'.length);
        const row = id === undefined ? undefined : profiles.get(id);
        if (row) {
          row.sessions++;
          if (busy) row.busySessions++; else row.idleSessions++;
          if (session.subscribed) row.subscriptions++;
          row.active += active;
        }
      }
    } catch { throw new SafeError('monitoring_counts_invalid'); }
    let backend: ProfileBackendSnapshot;
    if (opts.getProfileMonitoringCounts === undefined) backend = unavailableProfileBackendCounts(profileIds);
    else {
      try { backend = projectProfileBackendCounts(opts.getProfileMonitoringCounts(), profileIds); }
      catch { throw new SafeError('monitoring_counts_invalid'); }
    }
    const projected = Object.fromEntries(profileIds.map(id => {
      const row = profiles.get(id)!;
      return [id, { ...row, ...backend[id] }];
    }));
    return {
      version: 1,
      uptimeSeconds: Math.max(0, process.uptime()),
      sessions: sessions.size,
      idleSessions,
      busySessions,
      subscriptions,
      profiles: projected,
    };
  };
  const resume = () => { draining = false; clearTimeout(maintenanceTimer); maintenanceTimer = undefined; };
  async function control(req: IncomingMessage, res: ServerResponse, path: string) {
    const operation = path.slice('/_control/'.length);
    if (!(['status', 'drain', 'resume'].includes(operation)) || req.method !== (operation === 'status' ? 'GET' : 'POST')) {
      reply(res, 404, 'not_found', true); return;
    }
    if (Number(req.headers['content-length'] ?? 0) > LIMIT) { reply(res, 413, 'body_too_large', true); return; }
    if (operation === 'status' && (Number(req.headers['content-length'] ?? 0) > 0 || req.headers['transfer-encoding'] !== undefined)) {
      reply(res, 400, 'invalid_request', true); return;
    }
    if (operation !== 'status' && !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(String(req.headers['content-type'] ?? ''))) {
      reply(res, 415, 'unsupported_media_type', true); return;
    }
    if (controls >= 4) { reply(res, 429, 'busy', true); return; }
    controls++;
    try {
      if (operation !== 'status') {
        const parsed = await body(req, bodyDeadline);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length !== 0) throw new SafeError('invalid_request');
        if (operation === 'resume') resume();
        else if (!draining) {
          draining = true;
          maintenanceTimer = setTimeout(resume, maintenanceDeadline); maintenanceTimer.unref();
        }
      }
      const state = maintenanceStatus();
      let counts: { backendStarts: number; backendLive: number } | undefined;
      if (operation === 'status' && opts.getBackendCounts !== undefined) {
        try {
          const value = opts.getBackendCounts();
          if (!Number.isSafeInteger(value.starts) || !Number.isSafeInteger(value.live)
              || value.starts < lastObservedStarts || value.live < 0 || value.live > value.starts) {
            throw new SafeError('backend_counts_invalid');
          }
          counts = { backendStarts: value.starts, backendLive: value.live };
          lastObservedStarts = value.starts;
        } catch { throw new SafeError('backend_counts_invalid'); }
      }
      const traffic = operation === 'status' && opts.getTrafficCounts !== undefined
        ? projectTraffic(opts.getTrafficCounts(), profileIds) : undefined;
      const monitoring = operation === 'status' ? monitoringStatus() : undefined;
      const serialized = JSON.stringify({ ...state, ...counts, ...(traffic === undefined ? {} : { trafficCounters: traffic }), ...(monitoring === undefined ? {} : { monitoring }) });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(serialized);
    } catch (error) {
      const code = error instanceof SafeError ? error.code : 'request_failed';
      reply(res, code === 'body_too_large' ? 413 : code === 'body_timeout' ? 408 : 400, code, true);
    } finally { controls--; }
  }
  async function evict(id: string, session: Session) {
    if (sessions.get(id) !== session) return;
    sessions.delete(id);
    await dispose(session);
  }
  function dispose(session:Session):Promise<void>{
    if(session.disposal)return session.disposal;
    const operation=Promise.resolve().then(async()=>{
      let failed=false;try{await session.server.close();}catch{failed=true;}
      try{await session.server.disposeLease?.();}catch{failed=true;}
      if(failed){cleanupFailed=true;throw new SafeError('cleanup_unproven');}
    });
    session.disposal=operation;disposals.add(operation);
    void operation.then(()=>disposals.delete(operation),()=>{disposals.delete(operation);cleanupFailed=true;});
    return operation;
  }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    const match = typeof req.headers.authorization === 'string' ? /^Bearer ([0-9a-f]{64})$/.exec(req.headers.authorization) : null;
    if (!match || !timingSafeEqual(Buffer.from(match[1], 'ascii'), expected)) { reply(res, 401, 'unauthorized', true); return; }
    if (req.headers.host !== `127.0.0.1:${actualPort}` || req.headers.origin !== undefined) { reply(res, 403, 'forbidden', true); return; }
    if (stopping || (opts.owners && !opts.owners.isHealthy)) { reply(res, 503, 'shutting_down', true); return; }
    const path = req.url ?? '';
    if (path.startsWith('/_control/')) { await control(req, res, path); return; }
    if (!routes.has(path) || !['POST', 'GET', 'DELETE'].includes(req.method ?? '')) { reply(res, 404, 'not_found', true); return; }
    const stateful=statefulRoutes.has(path);
    const owner=req.headers['x-personal-mcp-owner'];
    if(stateful){try{opts.owners!.assertOwner(owner,path.slice('/mcp/'.length));}catch{reply(res,403,'owner_not_registered',true);return;}}
    if (draining && !(stateful&&req.method==='DELETE')) { reply(res, 503, 'draining', true); return; }
    if (req.method === 'POST' && !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(String(req.headers['content-type'] ?? ''))) { reply(res, 415, 'unsupported_media_type', true); return; }
    const counted = req.method !== 'GET';
    const profileId = path === '/mcp' ? undefined : path.slice('/mcp/'.length);
    if (counted && !(stateful&&req.method==='DELETE') && requests >= capacity) { reply(res, 429, 'busy', true); return; }
    if (Number(req.headers['content-length'] ?? 0) > LIMIT) { reply(res, 413, 'body_too_large', true); return; }
    if (req.method !== 'POST' && (Number(req.headers['content-length'] ?? 0) > 0 || req.headers['transfer-encoding'] !== undefined)) {
      reply(res, 400, 'invalid_request', true); return;
    }
    let requestReleased = !counted;
    const releaseRequest = () => {
      if (requestReleased) return;
      requestReleased = true; requests--;
      if (profileId !== undefined) requestsByProfile.set(profileId, requestsByProfile.get(profileId)! - 1);
      res.off('finish', releaseRequest); res.off('close', releaseRequest);
    };
    if (counted) {
      requests++;
      if (profileId !== undefined) requestsByProfile.set(profileId, requestsByProfile.get(profileId)! + 1);
      res.once('finish', releaseRequest); res.once('close', releaseRequest);
    }
    try {
      let parsed: unknown;
      if (req.method === 'POST') {
        bodies++;
        try { parsed = await body(req, bodyDeadline); } finally { bodies--; }
      }
      if (stopping || (opts.owners && !opts.owners.isHealthy)) { reply(res, 503, 'shutting_down', true); return; }
      const sid = req.headers['mcp-session-id'];
      if (sid !== undefined) {
        const entry = typeof sid === 'string' ? sessions.get(sid) : undefined;
        if (!entry || entry.path !== path || (entry.stateful && entry.owner!==owner)) { reply(res, 404, 'session_not_found'); return; }
        if (req.method === 'GET' && entry.subscribed) { reply(res, 429, 'subscription_limit', true); return; }
        entry.requests++; entry.last = Date.now();
        if (req.method === 'GET') {
          entry.subscribed = true;
          let released = false;
          const releaseSubscription = () => {
            if (released) return;
            released = true; entry.subscribed = false; entry.requests--; entry.last = Date.now();
            res.off('finish', releaseSubscription); res.off('close', releaseSubscription);
          };
          res.once('finish', releaseSubscription); res.once('close', releaseSubscription);
          try { await entry.transport.handleRequest(req, res); }
          finally { if (res.writableEnded || res.destroyed) releaseSubscription(); }
          return;
        }
        try { await entry.transport.handleRequest(req, res, parsed); }
        finally { entry.requests--; entry.last = Date.now(); }
        return;
      }
      if (req.method !== 'POST' || !initialization(parsed)) { reply(res, 400, 'invalid_request'); return; }
      if (sessions.size + pending >= max) { reply(res, 429, 'session_limit'); return; }
      pending++;
      let server: Session['server'] | undefined;
      let transport: StreamableHTTPServerTransport | undefined;
      let entry: Session | undefined;
      let id: string | undefined;
      let completed = false;
      // Enclose both constructors and connect: every failure releases capacity.
      try {
        server = await opts.buildServer(path,typeof owner==='string'?owner:undefined);
        transport = new StreamableHTTPServerTransport({
          // Request-bound progress must use the caller's SSE response stream.
          // JSON response mode silently drops these SDK notifications.
          sessionIdGenerator: () => randomUUID(), enableJsonResponse: false,
          onsessioninitialized: value => {
            id = value;
            if(stateful)opts.owners!.assertOwner(owner,path.slice('/mcp/'.length));
            if (entry && !stopping) sessions.set(value, entry);
          },
        });
        entry = { server, transport, path,stateful,...(stateful?{owner:owner as string}:{}), last: Date.now(), requests: 1, subscribed: false };
        server.onclose = () => { if (id && sessions.get(id) === entry) sessions.delete(id);if(entry)void dispose(entry).catch(()=>{}); };
        server.onerror = () => {};
        await server.connect(transport);
        if(stateful)opts.owners!.assertOwner(owner,path.slice('/mcp/'.length));
        await transport.handleRequest(req, res, parsed);
        completed = !stopping && Boolean(id) && res.statusCode >= 200 && res.statusCode < 300;
      } finally {
        pending--;
        if (entry) { entry.requests--; entry.last = Date.now(); }
        if (!completed) {
          if (id) sessions.delete(id);
          if(entry)await dispose(entry).catch(()=>{});else await server?.close().catch(()=>{});
          await transport?.close().catch(() => {});
        }
      }
    } catch (error) {
      const code = error instanceof SafeError ? error.code : 'request_failed';
      const status = code === 'body_too_large' ? 413 : code === 'body_timeout' ? 408 : code === 'invalid_request' ? 400 : 500;
      reply(res, status, code, code === 'body_too_large' || code === 'body_timeout');
    } finally { if (res.writableEnded || res.destroyed) releaseRequest(); }
  }
  const server = createServer({ maxHeaderSize: 8192, connectionsCheckingInterval: 1000 }, (req, res) => {
    void handle(req, res).catch(() => reply(res, 500, 'request_failed', true));
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000;
  // One SSE connection and one reusable POST connection per session, plus
  // bounded concurrent work and a small pre-auth/header-handshake margin.
  server.maxConnections = 2 * max + capacity + 16;
  server.on('clientError', (_error, socket) => socket.destroy());
  await new Promise<void>((resolve, reject) => {
    const fail = () => reject(new SafeError('listener_failed'));
    server.once('error', fail);
    server.listen(opts.port, opts.host, () => { server.off('error', fail); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new SafeError('listener_failed');
  actualPort = address.port;
  server.on('error', () => {});
  const sweep = setInterval(() => {
    const cutoff = Date.now() - idle;
    for (const [id, session] of sessions) {
      if (!session.stateful && !session.requests && !session.server.activeCalls && session.last < cutoff) void evict(id, session).catch(()=>{});
    }
  }, Math.min(idle, 30000));
  sweep.unref();
  let closing: Promise<void> | undefined;
  const close = () => {
      closing ??= (async () => {
        stopping = true; clearInterval(sweep); clearTimeout(maintenanceTimer);
        const closed = new Promise<void>(resolve => server.close(() => resolve()));
        const deadline = Date.now() + shutdownDeadline;
        while ((pending > 0 || [...sessions.values()].some(session => session.server.activeCalls)) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
        let failed=false;try { await opts.onShutdown?.(); }catch{failed=true;}
        const results=await Promise.allSettled([...sessions].map(([id, session]) => evict(id, session)));
        await Promise.allSettled([...disposals]);
        server.closeAllConnections(); await closed;
        if(failed||cleanupFailed||results.some(result=>result.status==='rejected'))throw new SafeError('cleanup_unproven');
      })();return closing;
  };
  const offExit=opts.owners?.onExit(owner=>{for(const [id,session] of sessions)if(session.owner===owner)void evict(id,session).catch(()=>{});});
  const offFailure=opts.owners?.onFailure(()=>{void close().catch(()=>{});});
  return {
    server,
    getPort: () => actualPort,
    snapshot: () => ({ sessions: sessions.size, pending, requests }),
    close: async()=>{try{await close();}finally{offExit?.();offFailure?.();}},
  };
}
