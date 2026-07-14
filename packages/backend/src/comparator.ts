import { createHash } from "crypto";

import type { ComparisonDTO } from "./types";

const IGNORED_HEADERS = new Set(["date", "age", "expires", "content-length"]);
const VOLATILE =
  /(?:timestamp|time|request.?id|trace.?id|nonce|csrf|token|expires?|generated.?at)/i;
const SENSITIVE =
  /(?:password|passwd|secret|token|cookie|authorization|api.?key)/i;

type ParsedMessage = {
  startLine: string;
  body: string;
  status: number;
  headers: Record<string, string>;
};

export function compareMessages(
  baselineRequest: string,
  baselineResponse: string,
  variantRequest: string,
  variantResponse: string,
): ComparisonDTO {
  const aResponse = parseMessage(baselineResponse);
  const bResponse = parseMessage(variantResponse);
  const aRequest = parseMessage(baselineRequest);
  const bRequest = parseMessage(variantRequest);
  const similarity = dice(
    normalizeBody(aResponse.body),
    normalizeBody(bResponse.body),
  );
  const identityDifferent =
    identity(aRequest.headers) !== identity(bRequest.headers);
  const identitiesPresent =
    identity(aRequest.headers) !== "" && identity(bRequest.headers) !== "";
  const sameResource =
    requestTarget(aRequest.startLine) === requestTarget(bRequest.startLine);
  const headerChanges = changedHeaders(aResponse.headers, bResponse.headers);
  const jsonChanges: string[] = [];
  const jsonCompared = compareJSON(aResponse.body, bResponse.body, jsonChanges);
  const substantiveJSONSame = jsonCompared && jsonChanges.length === 0;
  const aSuccess = successful(aResponse.status);
  const bSuccess = successful(bResponse.status);
  let outcome: ComparisonDTO["outcome"] = "INCONCLUSIVE";
  if (aSuccess && [401, 403].includes(bResponse.status))
    outcome = "ACCESS_DENIED";
  else if (
    identitiesPresent &&
    identityDifferent &&
    sameResource &&
    aSuccess &&
    bSuccess &&
    (substantiveJSONSame || similarity >= 0.9)
  )
    outcome = "POSSIBLE_AUTHORIZATION_BYPASS";
  else if (
    aResponse.status === bResponse.status &&
    (substantiveJSONSame || similarity >= 0.98)
  )
    outcome = "SAME_CONTENT";
  const label = outcome.replaceAll("_", " ").toLowerCase();
  const summary =
    `${label}\nHTTP: ${aResponse.status} → ${bResponse.status}\n` +
    `Body length: ${aResponse.body.length} → ${bResponse.body.length}\n` +
    `Similarity: ${(similarity * 100).toFixed(1)}%\n` +
    `Different identity material: ${identitiesPresent && identityDifferent}\n` +
    `Same request target: ${sameResource}` +
    (headerChanges.length === 0
      ? ""
      : `\nChanged headers: ${headerChanges.join(", ")}`) +
    (jsonChanges.length === 0
      ? ""
      : `\nJSON changes:\n- ${jsonChanges.join("\n- ")}`);
  return {
    outcome,
    baselineStatus: aResponse.status,
    variantStatus: bResponse.status,
    baselineLength: aResponse.body.length,
    variantLength: bResponse.body.length,
    similarity,
    identityDifferent: identitiesPresent && identityDifferent,
    sameResource,
    jsonCompared,
    headerChanges,
    jsonChanges,
    summary,
  };
}

export function dice(left: string, right: string): number {
  if (left === right) return 1;
  if (left.length < 2 || right.length < 2) return 0;
  const grams = bigrams(left);
  let matches = 0;
  for (const [gram, count] of bigrams(right))
    matches += Math.min(count, grams.get(gram) ?? 0);
  return (2 * matches) / Math.max(1, left.length - 1 + (right.length - 1));
}

function parseMessage(raw: string): ParsedMessage {
  let split = raw.indexOf("\r\n\r\n");
  let separator = 4;
  if (split < 0) {
    split = raw.indexOf("\n\n");
    separator = 2;
  }
  const head = split < 0 ? raw : raw.slice(0, split);
  const body = split < 0 ? "" : raw.slice(split + separator);
  const lines = head.split(/\r?\n/);
  const startLine = lines[0] ?? "";
  const status = startLine.startsWith("HTTP/")
    ? Number(startLine.split(/\s+/)[1] ?? 0)
    : 0;
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers[name] =
      headers[name] === undefined ? value : `${headers[name]}; ${value}`;
  }
  return {
    startLine,
    body,
    status: Number.isFinite(status) ? status : 0,
    headers,
  };
}

function identity(headers: Record<string, string>): string {
  const material = `${headers.authorization ?? ""}\n${headers.cookie ?? ""}`;
  return material.trim() === ""
    ? ""
    : createHash("sha256").update(material).digest("hex");
}

function requestTarget(line: string): string {
  const parts = line.trim().split(/\s+/);
  return parts.length >= 2
    ? `${parts[0]?.toUpperCase()} ${parts[1]}`
    : line.trim();
}

function changedHeaders(
  left: Record<string, string>,
  right: Record<string, string>,
): string[] {
  const names = [
    ...new Set([...Object.keys(left), ...Object.keys(right)]),
  ].sort();
  return names.filter(
    (name) => !IGNORED_HEADERS.has(name) && left[name] !== right[name],
  );
}

function compareJSON(left: string, right: string, changes: string[]): boolean {
  try {
    const a = new Map<string, string>();
    const b = new Map<string, string>();
    flattenJSON("$", JSON.parse(left) as unknown, a);
    flattenJSON("$", JSON.parse(right) as unknown, b);
    const paths = [...new Set([...a.keys(), ...b.keys()])].sort();
    for (const path of paths) {
      const key =
        path
          .split(".")
          .at(-1)
          ?.replace(/\[\d+]$/, "") ?? path;
      if (VOLATILE.test(key) || a.get(path) === b.get(path)) continue;
      if (changes.length >= 100) break;
      changes.push(
        `${path}: ${safeValue(key, a.get(path))} → ${safeValue(key, b.get(path))}`,
      );
    }
    return true;
  } catch {
    return false;
  }
}

function flattenJSON(
  path: string,
  value: unknown,
  output: Map<string, string>,
): void {
  if (value === null || typeof value !== "object") {
    output.set(path, JSON.stringify(value));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      flattenJSON(`${path}[${index}]`, item, output),
    );
    return;
  }
  for (const [key, child] of Object.entries(value))
    flattenJSON(`${path}.${key}`, child, output);
}

function safeValue(key: string, value: string | undefined): string {
  if (value === undefined) return "[missing]";
  if (SENSITIVE.test(key)) return "[REDACTED]";
  const compact = value.replace(/[\r\n]+/g, " ");
  return compact.length > 80 ? `${compact.slice(0, 80)}…` : compact;
}

function normalizeBody(value: string): string {
  return value
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "[uuid]")
    .replace(/\b\d{10,13}\b/g, "[time]")
    .replace(/\s+/g, " ")
    .trim();
}

function bigrams(value: string): Map<string, number> {
  const output = new Map<string, number>();
  for (let index = 0; index + 1 < value.length; index += 1) {
    const gram = value.slice(index, index + 2);
    output.set(gram, (output.get(gram) ?? 0) + 1);
  }
  return output;
}

function successful(status: number): boolean {
  return status >= 200 && status < 300;
}
