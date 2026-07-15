import type { RequestSpec } from "caido:utils";
import { describe, expect, it } from "vitest";

import {
  mutateRequest,
  replaceCookieValue,
  replaceEncodedValue,
  replaceJSONValue,
} from "./mutator";

describe("Replay request mutation", () => {
  it("replaces only the first matching encoded parameter", () => {
    expect(replaceEncodedValue("id=1&id=2", "id", "../ 3")).toBe(
      "id=..%2F%203&id=2",
    );
  });

  it("matches encoded parameter names", () => {
    expect(replaceEncodedValue("user%5Fid=1", "user_id", "2")).toBe(
      "user%5Fid=2",
    );
  });

  it("returns undefined when an encoded parameter disappeared", () => {
    expect(replaceEncodedValue("id=1", "missing", "2")).toBeUndefined();
  });

  it("replaces one cookie without rewriting unrelated cookies", () => {
    expect(replaceCookieValue("sid=a; theme=dark", "sid", "b c")).toBe(
      "sid=b c; theme=dark",
    );
    expect(replaceCookieValue("sid=a", "other", "x")).toBeUndefined();
  });

  it("replaces a bounded nested JSON property", () => {
    expect(replaceJSONValue('{"user":{"id":1}}', "id", "2")).toBe(
      '{"user":{"id":"2"}}',
    );
    expect(replaceJSONValue("not json", "id", "2")).toBeUndefined();
    expect(replaceJSONValue("{}", "id", "2")).toBeUndefined();
  });

  it("mutates query, form, JSON, and cookie request specs", () => {
    const query = spec({ query: "id=1" });
    expect(mutateRequest(query.value, "id", "QUERY", "2")).toBe(query.value);
    expect(query.state.query).toBe("id=2");

    const form = spec({ body: "id=1" });
    mutateRequest(form.value, "id", "FORM", "2");
    expect(form.state.body).toBe("id=2");

    const json = spec({ body: '{"id":1}' });
    mutateRequest(json.value, "id", "JSON", "2");
    expect(json.state.body).toBe('{"id":"2"}');

    const cookie = spec({ cookies: ["sid=a", "theme=dark"] });
    mutateRequest(cookie.value, "sid", "COOKIE", "b");
    expect(cookie.state.cookie).toBe("sid=b; theme=dark");
  });

  it("rejects stale and unsupported parameter locations", () => {
    expect(() => mutateRequest(spec().value, "id", "QUERY", "2")).toThrow(
      "no longer present",
    );
    expect(() =>
      mutateRequest(spec().value, "id", "RESPONSE_HEADER", "2"),
    ).toThrow("edited manually");
  });
});

function spec(
  initial: {
    query?: string;
    body?: string;
    cookies?: string[];
  } = {},
) {
  const state = {
    query: initial.query ?? "",
    body: initial.body ?? "",
    cookie: "",
  };
  const value = {
    getQuery: () => state.query,
    setQuery: (query: string) => {
      state.query = query;
    },
    getBody: () => ({ toText: () => state.body }),
    setBody: (body: string) => {
      state.body = body;
    },
    getHeader: () => initial.cookies ?? [],
    setHeader: (_name: string, value: string) => {
      state.cookie = value;
    },
  } as unknown as RequestSpec;
  return { value, state };
}
