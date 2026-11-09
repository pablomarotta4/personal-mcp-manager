import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, CallToolResultSchema, ErrorCode, ListPromptsRequestSchema, ListResourcesRequestSchema, ListResourcesResultSchema,
  ListResourceTemplatesRequestSchema, ListToolsRequestSchema, McpError, ReadResourceRequestSchema,
  ReadResourceResultSchema, SetLevelRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ListResourcesResult, CallToolResult, LoggingLevel, Progress, ReadResourceResult, ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import { parseManifest } from "./manifest.js";
import type { ReviewedManifest } from "./manifest.js";
import { CompletedBackendError } from "./pool.js";
import type { TrafficCounters } from "./traffic-counters.js";

export interface FacadeCallContext {
  signal?: AbortSignal;
  meta?: Record<string, unknown>;
  onProgress?: (progress: Progress) => void | Promise<void>;
}
export interface FacadePool {
  listResources?(id:string,cursor?:string,context?:FacadeCallContext):Promise<ListResourcesResult>;
  call(id: string, tool: string, args: Record<string, unknown> | undefined, context?: FacadeCallContext): Promise<CallToolResult>;
  readResource(id: string, uri: string, context?: FacadeCallContext): Promise<ReadResourceResult>;
  assertManifestValid(id: string): void;
  onManifestInvalidated(id: string, callback: (kind: "tools" | "resources" | "prompts" | "logging" | "drift") => void): () => void;
}
export type FacadeServer = Server & { activeCalls: number;retained?:()=>boolean;disposeLease?:()=>Promise<void> };

function callContext(meta: Record<string, unknown> | undefined,
  extra: RequestHandlerExtra<ServerRequest, ServerNotification>): FacadeCallContext {
  const progressToken = meta?.progressToken;
  return { signal: extra.signal,
    ...(meta === undefined ? {} : { meta }),
    ...(typeof progressToken !== "string" && typeof progressToken !== "number" ? {} : { onProgress: async (progress: Progress) => {
      if (extra.signal.aborted) return;
      try {
        await extra.sendNotification({ method: "notifications/progress", params: { ...progress, progressToken } });
      } catch {
        // A disconnected client must not reject an SDK fire-and-forget callback.
      }
    } }),
  };
}

/** Each session is bound to one reviewed backend; discovery does no backend I/O. */
export function createFacade(input: ReviewedManifest, pool: FacadePool, traffic?: TrafficCounters): FacadeServer {
  const manifest = parseManifest(input);
  const { description } = manifest;
  const mysql=manifest.provenance.catalogMode==="mysql-session";
  if(mysql&&!pool.listResources)throw new Error("mysql_resources_dispatch_required");
  const allowed = new Set(manifest.allowedTools);
  const server = Object.assign(new Server(description.serverInfo, {
    capabilities: description.capabilities,
    ...(description.instructions === undefined ? {} : { instructions: description.instructions }),
  }), { activeCalls: 0 });
  server.onerror = () => {};
  let invalidated = false;
  const assertValid = () => {
    try {
      pool.assertManifestValid(manifest.backendId);
      if (invalidated) throw new Error("manifest_invalidated");
    } catch { throw new McpError(ErrorCode.InternalError, "manifest_invalidated"); }
  };
  const listCheck = (cursor: string | undefined) => {
    assertValid();
    if (cursor !== undefined) throw new McpError(ErrorCode.InvalidParams, "invalid_cursor");
  };
  const operation = async <T>(run: () => Promise<T>, validate: (input: unknown) => boolean): Promise<T> => {
    server.activeCalls++;
    try {
      const result = await run();
      if (!validate(result)) throw new Error("invalid_backend_result");
      return result;
    } catch (error) {
      if (error instanceof CompletedBackendError) throw error;
      throw new McpError(ErrorCode.InternalError, "backend_unavailable");
    } finally { server.activeCalls--; }
  };
  server.setRequestHandler(ListToolsRequestSchema, async request => {
    listCheck(request.params?.cursor);
    traffic?.recordCatalogRequest(manifest.backendId);
    return { tools: structuredClone(description.tools) };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    assertValid();
    if (!allowed.has(request.params.name)) throw new McpError(ErrorCode.InvalidParams, "unknown_tool");
    if (request.params.task !== undefined) throw new McpError(ErrorCode.InvalidParams, "unsupported_task");
    const settle = traffic?.beginToolCall(manifest.backendId);
    try {
      const result = await operation(() => pool.call(manifest.backendId, request.params.name, request.params.arguments,
        callContext(request.params._meta, extra)), value => CallToolResultSchema.safeParse(value).success);
      settle?.(result.isError !== true);
      return result;
    } catch (error) {
      settle?.(false);
      throw error;
    }
  });
  if (description.capabilities.resources) {
    const resources = description.resources!;
    const uris = new Set(resources.map(resource => resource.uri));
    server.setRequestHandler(ListResourcesRequestSchema, async (request,extra) => {
      if(mysql){
        assertValid();traffic?.recordCatalogRequest(manifest.backendId);
        return operation(()=>pool.listResources!(manifest.backendId,request.params?.cursor,callContext(request.params?._meta,extra)),result=>ListResourcesResultSchema.safeParse(result).success);
      }
      listCheck(request.params?.cursor);
      traffic?.recordCatalogRequest(manifest.backendId);
      return { resources: structuredClone(resources) };
    });
    if(!mysql)server.setRequestHandler(ListResourceTemplatesRequestSchema, async request => {
      listCheck(request.params?.cursor);
      traffic?.recordCatalogRequest(manifest.backendId);
      return { resourceTemplates: structuredClone(description.resourceTemplates!) };
    });
    server.setRequestHandler(ReadResourceRequestSchema, async (request, extra) => {
      assertValid();
      if (!mysql&&!uris.has(request.params.uri)) throw new McpError(ErrorCode.InvalidParams, "unknown_resource");
      return operation(() => pool.readResource(manifest.backendId, request.params.uri,
        callContext(request.params._meta, extra)), result => ReadResourceResultSchema.safeParse(result).success);
    });
  }
  if (description.capabilities.prompts) {
    server.setRequestHandler(ListPromptsRequestSchema, async request => {
      listCheck(request.params?.cursor);
      traffic?.recordCatalogRequest(manifest.backendId);
      return { prompts: structuredClone(description.prompts!) };
    });
  }
  if (description.capabilities.logging) {
    let sessionLoggingLevel: LoggingLevel | undefined;
    server.setRequestHandler(SetLevelRequestSchema, async request => {
      assertValid();
      // Reviewed artifacts never emit MCP logs; settings remain local to this frontend.
      sessionLoggingLevel = request.params.level;
      return {};
    });
  }

  const unsubscribe = pool.onManifestInvalidated(manifest.backendId, kind => {
    invalidated = true;
    const kinds = kind === "logging" || kind === "drift" ? ["tools", "resources", "prompts"] as const : [kind];
    for (const catalog of kinds) {
      if (!description.capabilities[catalog as "tools" | "resources" | "prompts"]?.listChanged) continue;
      void server.notification({ method: `notifications/${catalog}/list_changed` as
        "notifications/tools/list_changed" | "notifications/resources/list_changed" | "notifications/prompts/list_changed" }).catch(() => {});
    }
  });
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    try { unsubscribe(); } catch { /* Listener cleanup must not prevent SDK transport cleanup. */ }
  };
  const close = server.close.bind(server);
  server.close = async () => { dispose(); await close(); };
  const connect = server.connect.bind(server);
  server.connect = async transport => {
    // Install before SDK connect so its own close handler still runs, including any
    // server.onclose callback the HTTP session manager installs afterwards.
    const previousClose = transport.onclose;
    transport.onclose = () => { dispose(); previousClose?.(); };
    try { await connect(transport); }
    catch (error) { dispose(); throw error; }
  };
  return server;
}
