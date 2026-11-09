import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { ImplementationSchema, ResourceSchema, ServerCapabilitiesSchema, ToolSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Implementation, Prompt, Resource, ResourceTemplate, ServerCapabilities, Tool } from "@modelcontextprotocol/sdk/types.js";

export interface BackendDescription {
  serverInfo: Implementation;
  capabilities: ServerCapabilities;
  instructions?: string;
  tools: Tool[];
  resources?: Resource[];
  resourceTemplates?: ResourceTemplate[];
  prompts?: Prompt[];
}

export interface ReviewedManifest {
  version: 1;
  backendId: string;
  allowedTools: string[];
  provenance: {
    catalogMode?: "mysql-session";
    sourceIdentity: string;
    artifactSha256: string;
    policyDigest: string;
    reviewedAt: string;
    logging?: "no-backend-notifications";
    closureDigest?: string;
    dependencyReportSha256?: string;
  };
  description: BackendDescription;
  fingerprint: string;
}

const MAX_BYTES = 2 * 1024 * 1024;
const fail = (): never => { throw new Error("invalid_manifest"); };
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail();
  return value as Record<string, unknown>;
};
const exactKeys = (value: Record<string, unknown>, allowed: readonly string[]) => {
  if (Object.keys(value).some(key => !allowed.includes(key))) fail();
};
const identifier = (value: unknown): value is string => typeof value === "string"
  && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)
  && !["__proto__", "prototype", "constructor"].includes(value);
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

// Only JSON values are fingerprinted; object key order has no semantic significance.
// Arrays retain order so the reviewed cold tools/list response remains reproducible.
function canonical(value: unknown): string {
  const ancestors = new Set<object>();
  let nodes = 0;
  const visit = (item: unknown, depth: number): string => {
    if (++nodes > 100_000 || depth > 64) return fail();
    if (item === null || typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "string") {
      if (item.length > MAX_BYTES) return fail();
      return JSON.stringify(item);
    }
    if (typeof item === "number") return Number.isFinite(item) ? JSON.stringify(item) : fail();
    if (typeof item !== "object" || ancestors.has(item)) return fail();
    if (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null && !Array.isArray(item)) return fail();
    ancestors.add(item);
    let result: string;
    if (Array.isArray(item)) {
      if (Object.keys(item).length !== item.length) return fail();
      result = `[${item.map(child => visit(child, depth + 1)).join(",")}]`;
    } else {
      result = `{${Object.keys(item).sort().map(key => `${JSON.stringify(key)}:${visit((item as Record<string, unknown>)[key], depth + 1)}`).join(",")}}`;
    }
    ancestors.delete(item);
    if (Buffer.byteLength(result, "utf8") > MAX_BYTES) return fail();
    return result;
  };
  return visit(value, 0);
}

export function fingerprintDescription(description: BackendDescription): string {
  try { return createHash("sha256").update(canonical(description)).digest("hex"); }
  catch { return fail(); }
}

/** Only reviewed MySQL input-derived catalog fields vary across client contexts. */
export function mysqlInvariantDescription(description: BackendDescription): BackendDescription {
  const projected=structuredClone(description);
  projected.serverInfo.version="contextual";
  if(projected.tools.length!==1||projected.tools[0].name!=="mysql_query")return fail();
  projected.tools[0].description="contextual";
  const annotations=projected.tools[0].annotations;
  if(!annotations)return fail();
  annotations.readOnlyHint=true;annotations.idempotentHint=true;annotations.destructiveHint=false;
  return projected;
}

function validateDescription(input: unknown, silentLogging: boolean): BackendDescription {
  const value = record(input);
  exactKeys(value, ["serverInfo", "capabilities", "instructions", "tools", "resources", "resourceTemplates", "prompts"]);
  if (!ImplementationSchema.safeParse(value.serverInfo).success
      || !ServerCapabilitiesSchema.safeParse(value.capabilities).success
      || (value.instructions !== undefined && typeof value.instructions !== "string")) fail();
  const capabilities = record(value.capabilities);
  exactKeys(capabilities, ["tools", "resources", "prompts", "logging", "experimental"]);
  if(capabilities.experimental!==undefined)exactKeys(record(capabilities.experimental),[]);
  const toolCapability = record(capabilities.tools);
  exactKeys(toolCapability, ["listChanged"]);
  if (!Array.isArray(value.tools) || value.tools.length === 0 || value.tools.length > 2048) fail();
  const seen = new Set<string>();
  for (const item of value.tools as unknown[]) {
    const tool = record(item);
    if (!identifier(tool.name) || seen.has(tool.name) || !ToolSchema.safeParse(tool).success) fail();
    seen.add(tool.name as string);
    if (tool.execution !== undefined) {
      const execution = record(tool.execution);
      exactKeys(execution, ["taskSupport"]);
      if (execution.taskSupport !== undefined && execution.taskSupport !== "forbidden") fail();
    }
  }
  if (capabilities.resources !== undefined) {
    const resourceCapability = record(capabilities.resources);
    exactKeys(resourceCapability, ["listChanged", "subscribe"]);
    if (resourceCapability.subscribe === true || !Array.isArray(value.resources) || value.resources.length > 2048
        || !Array.isArray(value.resourceTemplates) || value.resourceTemplates.length !== 0) fail();
    const uris = new Set<string>();
    for (const item of value.resources as unknown[]) {
      const resource = record(item);
      if (!ResourceSchema.safeParse(resource).success || typeof resource.uri !== "string"
          || resource.uri.length === 0 || resource.uri.length > 4096 || resource.uri.includes("\0")
          || uris.has(resource.uri)) fail();
      uris.add(resource.uri as string);
    }
  } else if (value.resources !== undefined || value.resourceTemplates !== undefined) fail();
  if (capabilities.prompts !== undefined) {
    exactKeys(record(capabilities.prompts), ["listChanged"]);
    if (!Array.isArray(value.prompts) || value.prompts.length !== 0) fail();
  } else if (value.prompts !== undefined) fail();
  if (silentLogging) {
    exactKeys(record(capabilities.logging), []);
  } else if (capabilities.logging !== undefined) fail();
  return value as unknown as BackendDescription;
}

function freeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Validate caller-reviewed provenance; this does not infer or attest source trust. */
export function parseManifest(input: unknown): ReviewedManifest {
  try {
    const value = record(JSON.parse(canonical(input)));
    exactKeys(value, ["version", "backendId", "allowedTools", "provenance", "description", "fingerprint"]);
    if (value.version !== 1 || !identifier(value.backendId) || !digest(value.fingerprint)) fail();
    const provenance = record(value.provenance);
    exactKeys(provenance, ["sourceIdentity", "artifactSha256", "policyDigest", "reviewedAt", "logging", "closureDigest", "dependencyReportSha256", "catalogMode"]);
    if((provenance.closureDigest!==undefined||provenance.dependencyReportSha256!==undefined)
        &&(!digest(provenance.closureDigest)||!digest(provenance.dependencyReportSha256)))fail();
    if (typeof provenance.sourceIdentity !== "string"
        || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/.test(provenance.sourceIdentity)
        || !digest(provenance.artifactSha256) || !digest(provenance.policyDigest)
        || typeof provenance.reviewedAt !== "string"
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(provenance.reviewedAt)
        || new Date(provenance.reviewedAt).toISOString() !== provenance.reviewedAt) fail();
    if (provenance.logging !== undefined && provenance.logging !== "no-backend-notifications") fail();
    const description = validateDescription(value.description, provenance.logging === "no-backend-notifications");
    if(provenance.catalogMode!==undefined){
      if(provenance.catalogMode!=="mysql-session"||!/^mysql-[a-z0-9-]+$/.test(value.backendId as string)
          ||!digest(provenance.closureDigest)||!digest(provenance.dependencyReportSha256)
          ||description.serverInfo.name!=="MySQL MCP Server"
          ||description.tools.length!==1||description.tools[0].name!=="mysql_query"
          ||!description.capabilities.resources||Object.keys(description.capabilities.resources).length!==0
          ||description.resources?.length!==0||description.resourceTemplates?.length!==0
          ||description.capabilities.prompts!==undefined||description.capabilities.logging!==undefined)fail();
    }
    const allowed = value.allowedTools;
    if (!Array.isArray(allowed) || !allowed.every(identifier)
        || new Set(allowed).size !== allowed.length || allowed.length !== description.tools.length
        || description.tools.some(tool => !allowed.includes(tool.name))) fail();
    if (fingerprintDescription(description) !== value.fingerprint) fail();
    return freeze(value as unknown as ReviewedManifest);
  } catch { return fail(); }
}

/** Open a bounded, owner-only file without following its final symlink. */
export function readManifest(path: string): ReviewedManifest {
  let fd: number | undefined;
  try {
    if (!isAbsolute(path)) fail();
    const uid = process.getuid?.();
    const parent = lstatSync(dirname(path));
    if (uid === undefined || !parent.isDirectory() || parent.isSymbolicLink()
        || parent.uid !== uid || (parent.mode & 0o7777) !== 0o700) fail();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o7777) !== 0o600 || stat.size > MAX_BYTES) fail();
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(fd, bytes, length, bytes.length - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length > MAX_BYTES) fail();
    return parseManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, length))));
  } catch { return fail(); }
  finally { if (fd !== undefined) closeSync(fd); }
}
