import { describe, expect, it } from "vitest";

import { analyze, parseParameters } from "./detector";
import type { AnalyzerInput } from "./types";

describe("WSTG passive detector", () => {
  it("discovers object references and renders payload suggestions", () => {
    const result = analyze(input({ query: "user_id=42" }));
    const candidate = result.candidates.find(
      (value) => value.ruleId === "param.object_reference",
    );
    expect(candidate?.wstgId).toBe("WSTG-ATHZ-04");
    expect(candidate?.payloads.length).toBeGreaterThan(0);
    expect(candidate?.url).toContain("[REDACTED]");
  });

  it("requires an observed external redirect", () => {
    const result = analyze(
      input({
        query: "next=https%3A%2F%2Fevil.test%2F",
        statusCode: 302,
        responseHeaders: { Location: ["https://evil.test/"] },
      }),
    );
    expect(
      result.candidates.some((value) => value.ruleId === "param.redirect"),
    ).toBe(true);
  });

  it("extracts JavaScript endpoints without fetching them", () => {
    const result = analyze(
      input({
        path: "/app.js",
        responseContentType: "application/javascript",
        responseBody: 'fetch("/api/users"); //# sourceMappingURL=app.js.map',
      }),
    );
    expect(
      result.assets.some((asset) => asset.kind === "JavaScript endpoint"),
    ).toBe(true);
    expect(result.assets.some((asset) => asset.kind === "Source map")).toBe(
      true,
    );
  });

  it("parses bounded JSON parameters", () => {
    const values = parseParameters(
      "",
      '{"role":"admin"}',
      "application/json",
      [],
    );
    expect(values).toContainEqual({
      name: "role",
      value: "admin",
      location: "JSON",
    });
  });

  it("classifies common parameter review families", () => {
    const query = [
      "__proto__=x",
      "callback=https%3A%2F%2Fexample.org",
      "file=README.txt",
      "search=test",
      "command=echo",
      "comment=hello",
      "role=user",
    ].join("&");
    const result = analyze(
      input({ query, parameters: parseParameters(query, "", "", []) }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toEqual(
      expect.arrayContaining([
        "param.prototype_pollution",
        "param.url",
        "param.path",
        "param.query",
        "param.command",
        "param.rendered",
        "param.privileged",
      ]),
    );
  });

  it("flags session material in a query URL", () => {
    const query = "session=abcdefghijklmnop";
    const result = analyze(
      input({ query, parameters: parseParameters(query, "", "", []) }),
    );
    const candidate = result.candidates.find(
      (value) => value.ruleId === "param.session_url",
    );
    expect(candidate?.payloads).toEqual([]);
    expect(candidate?.evidence).not.toContain("abcdefghijklmnop");
  });

  it("discovers sensitive and GraphQL routes", () => {
    const sensitive = analyze(input({ path: "/admin/debug" }));
    expect(
      sensitive.candidates.some(
        (candidate) => candidate.ruleId === "url.sensitive_path",
      ),
    ).toBe(true);
    const graphql = analyze(input({ path: "/graphql" }));
    expect(
      graphql.candidates.some(
        (candidate) => candidate.ruleId === "api.graphql",
      ),
    ).toBe(true);
  });

  it("reviews response headers and session cookie attributes", () => {
    const result = analyze(
      input({
        headers: { Origin: ["https://attacker.test"] },
        responseContentType: "text/html",
        responseHeaders: {
          "Access-Control-Allow-Origin": ["https://attacker.test"],
          "Access-Control-Allow-Credentials": ["true"],
          Server: ["Example/1.2.3"],
          "Set-Cookie": ["sessionid=abc"],
        },
      }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toEqual(
      expect.arrayContaining([
        "header.hsts",
        "header.cors",
        "header.server_version",
        "header.clickjacking",
        "cookie.secure",
        "cookie.httponly",
        "cookie.samesite",
      ]),
    );
  });

  it("detects secrets, stack traces, and internal addresses without storing them", () => {
    const secret = "AKIAABCDEFGHIJKLMNOP";
    const result = analyze(
      input({
        responseBody: `${secret} stack trace at demo(App.java:10) 10.20.30.40`,
      }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toEqual(
      expect.arrayContaining([
        "secret.aws_access_key",
        "response.stack_trace",
        "response.internal_address",
      ]),
    );
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("detects verbose errors and high-entropy generic tokens", () => {
    const result = analyze(
      input({
        responseBody:
          'api_key="a8F4kP9zQ2mN7xR5tV1cL6wY3uJ0sD" fatal error happened on line 42',
      }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toContain("secret.high_entropy");
    expect(rules).toContain("response.verbose_error");
  });

  it("inventories JavaScript URLs and dangerous sinks", () => {
    const result = analyze(
      input({
        path: "/bundle.js",
        responseContentType: "text/javascript",
        responseBody:
          'const api="https://api.example.test/v1"; el.innerHTML = value; fetch("/admin/users")',
      }),
    );
    expect(result.assets.some((asset) => asset.kind === "Absolute URL")).toBe(
      true,
    );
    expect(
      result.candidates.some((candidate) => candidate.ruleId === "js.dom_sink"),
    ).toBe(true);
  });

  it("parses form and cookie values and tolerates malformed encoding", () => {
    const values = parseParameters(
      "%E0%A4%A=x",
      "role=admin",
      "application/x-www-form-urlencoded",
      ["sid=abc; theme=dark"],
    );
    expect(values).toEqual(
      expect.arrayContaining([
        { name: "role", value: "admin", location: "FORM" },
        { name: "sid", value: "abc", location: "COOKIE" },
      ]),
    );
  });
});

function input(overrides: Partial<AnalyzerInput> = {}): AnalyzerInput {
  const query = overrides.query ?? "";
  const requestBody = overrides.requestBody ?? "";
  const requestContentType = overrides.requestContentType ?? "";
  return {
    requestId: "request-1",
    responseId: "response-1",
    method: "GET",
    url: `https://example.test/api/users${query === "" ? "" : `?${query}`}`,
    host: "example.test",
    path: "/api/users",
    query,
    headers: {},
    parameters: parseParameters(query, requestBody, requestContentType, []),
    requestRaw: "GET /api/users HTTP/1.1\r\nHost: example.test\r\n\r\n",
    requestBody,
    requestContentType,
    statusCode: 200,
    responseHeaders: { "Content-Type": ["application/json"] },
    responseRaw: "HTTP/1.1 200 OK\r\n\r\n{}",
    responseBody: "{}",
    responseContentType: "application/json",
    ...overrides,
  };
}
