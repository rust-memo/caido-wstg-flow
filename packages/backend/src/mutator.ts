import type { RequestSpec } from "caido:utils";

import type { ParameterLocation } from "./types";

export function mutateRequest(
  spec: RequestSpec,
  name: string,
  location: ParameterLocation,
  payload: string,
): RequestSpec {
  if (location === "QUERY") {
    const value = replaceEncodedValue(spec.getQuery(), name, payload);
    if (value === undefined) throw missingParameter(name);
    spec.setQuery(value);
    return spec;
  }
  if (location === "FORM") {
    const value = replaceEncodedValue(
      spec.getBody()?.toText() ?? "",
      name,
      payload,
    );
    if (value === undefined) throw missingParameter(name);
    spec.setBody(value, { updateContentLength: true });
    return spec;
  }
  if (location === "JSON") {
    const value = replaceJSONValue(
      spec.getBody()?.toText() ?? "",
      name,
      payload,
    );
    if (value === undefined) throw missingParameter(name);
    spec.setBody(value, { updateContentLength: true });
    return spec;
  }
  if (location === "COOKIE") {
    const values = spec.getHeader("Cookie") ?? [];
    let replaced = false;
    const updated = values.map((value) => {
      const result = replaceCookieValue(value, name, payload);
      if (result !== undefined) {
        replaced = true;
        return result;
      }
      return value;
    });
    if (!replaced) throw missingParameter(name);
    spec.setHeader("Cookie", updated.join("; "));
    return spec;
  }
  throw new Error("This parameter location must be edited manually in Replay");
}

export function replaceEncodedValue(
  raw: string,
  name: string,
  payload: string,
): string | undefined {
  let replaced = false;
  const value = raw
    .split("&")
    .map((pair) => {
      const separator = pair.indexOf("=");
      const rawName = separator < 0 ? pair : pair.slice(0, separator);
      if (!replaced && safeDecode(rawName) === name) {
        replaced = true;
        return `${rawName}=${encodeURIComponent(payload)}`;
      }
      return pair;
    })
    .join("&");
  return replaced ? value : undefined;
}

export function replaceCookieValue(
  raw: string,
  name: string,
  payload: string,
): string | undefined {
  let replaced = false;
  const value = raw
    .split(";")
    .map((part) => {
      const separator = part.indexOf("=");
      if (
        !replaced &&
        (separator < 0 ? part : part.slice(0, separator)).trim() === name
      ) {
        replaced = true;
        return `${name}=${payload}`;
      }
      return part.trim();
    })
    .join("; ");
  return replaced ? value : undefined;
}

export function replaceJSONValue(
  raw: string,
  name: string,
  payload: string,
): string | undefined {
  let root: unknown;
  try {
    root = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  let replaced = false;
  const walk = (value: unknown, depth: number): void => {
    if (replaced || depth > 25 || value === null || typeof value !== "object")
      return;
    if (Array.isArray(value)) {
      value.forEach((item) => walk(item, depth + 1));
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      if (key === name) {
        (value as Record<string, unknown>)[key] = payload;
        replaced = true;
        return;
      }
      walk(child, depth + 1);
    }
  };
  walk(root, 0);
  return replaced ? JSON.stringify(root) : undefined;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function missingParameter(name: string): Error {
  return new Error(
    `Parameter '${name}' is no longer present in the source request`,
  );
}
