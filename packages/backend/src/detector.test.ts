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
    ].join("&");
    const requestBody = '{"role":"user"}';
    const result = analyze(
      input({
        query,
        method: "POST",
        requestBody,
        requestContentType: "application/json",
        responseBody: "<html>hello</html>",
        responseContentType: "text/html",
        parameters: parseParameters(query, requestBody, "application/json", []),
      }),
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
    const token = "s8Dk29Lm4Pq7Vx1Z";
    const query = `session=${token}`;
    const result = analyze(
      input({ query, parameters: parseParameters(query, "", "", []) }),
    );
    const candidate = result.candidates.find(
      (value) => value.ruleId === "param.session_url",
    );
    expect(candidate?.payloads).toEqual([]);
    expect(candidate?.evidence).not.toContain(token);
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
        responseBody: "<form><button>Transfer</button></form>",
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
    expect(JSON.stringify(result)).not.toContain("10.20.30.40");
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
          'const api="https://api.example.test/v1"; const value=location.search; el.innerHTML = value; fetch("/admin/users")',
      }),
    );
    expect(result.assets.some((asset) => asset.kind === "Absolute URL")).toBe(
      true,
    );
    expect(
      result.candidates.some((candidate) => candidate.ruleId === "js.dom_sink"),
    ).toBe(true);
  });

  it("suppresses broad name-only parameter heuristics", () => {
    const query = "quantity=5&page=2&status=active&host=example.test";
    const result = analyze(input({ query }));
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).not.toContain("param.query");
    expect(rules).not.toContain("param.path");
    expect(rules).not.toContain("param.privileged");
    expect(rules).not.toContain("param.command");
  });

  it("detects conflicting duplicate query parameters", () => {
    const query = "role=user&role=admin";
    const result = analyze(input({ query }));
    expect(
      result.candidates.some(
        (candidate) => candidate.ruleId === "param.parameter_pollution",
      ),
    ).toBe(true);
  });

  it("detects path object references and legacy API inventory signals", () => {
    const result = analyze(
      input({ path: "/api/v0/accounts/4b2f96d4-1272-4b4f-91ad-c15abf785e31" }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toContain("path.object_reference");
    expect(rules).toContain("api.deprecated_version");
  });

  it("inspects successful JWT metadata without storing the token", () => {
    const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.";
    const result = analyze(
      input({ headers: { Authorization: [`Bearer ${token}`] } }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toContain("auth.jwt_none");
    expect(rules).not.toContain("auth.jwt_no_expiry");
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("keeps signed JWT expiry policy as a tentative review lead", () => {
    const token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmno";
    const result = analyze(
      input({ headers: { Authorization: [`Bearer ${token}`] } }),
    );
    const candidate = result.candidates.find(
      (value) => value.ruleId === "auth.jwt_no_expiry",
    );
    expect(candidate?.confidence).toBe("Tentative");
  });

  it("does not report an expected JWT in a successful JSON token response", () => {
    const token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmno";
    const result = analyze(
      input({
        path: "/auth/token",
        responseBody: JSON.stringify({ access_token: token }),
      }),
    );
    expect(
      result.candidates.some((candidate) => candidate.ruleId === "secret.jwt"),
    ).toBe(false);
  });

  it("reports cleartext credentials only when HTTP content is served", () => {
    const served = analyze(
      input({
        url: "http://example.test/api/users",
        headers: { Authorization: ["Basic dXNlcjpwYXNz"] },
      }),
    );
    expect(
      served.candidates.some(
        (candidate) => candidate.ruleId === "header.cleartext_credentials",
      ),
    ).toBe(true);

    const redirected = analyze(
      input({
        url: "http://example.test/api/users",
        statusCode: 308,
        headers: { Authorization: ["Basic dXNlcjpwYXNz"] },
        responseHeaders: { Location: ["https://example.test/api/users"] },
      }),
    );
    expect(
      redirected.candidates.some(
        (candidate) => candidate.ruleId === "header.cleartext_credentials",
      ),
    ).toBe(false);

    const issuedCookie = analyze(
      input({
        url: "http://example.test/login",
        path: "/login",
        responseHeaders: { "Set-Cookie": ["sessionid=abc"] },
      }),
    );
    expect(
      issuedCookie.candidates.some(
        (candidate) => candidate.ruleId === "header.cleartext_session_cookie",
      ),
    ).toBe(true);
  });

  it("parses compact cookie attributes without false missing-attribute reports", () => {
    const result = analyze(
      input({
        responseHeaders: {
          "Set-Cookie": ["sessionid=abc;Secure;HttpOnly;SameSite=Lax"],
        },
      }),
    );
    expect(
      result.candidates.some((candidate) =>
        candidate.ruleId.startsWith("cookie."),
      ),
    ).toBe(false);
  });

  it("detects API response-shape and definition inventory signals", () => {
    const wideItem = Object.fromEntries(
      Array.from({ length: 21 }, (_, index) => [`field_${index}`, index]),
    );
    const arrayResult = analyze(
      input({ responseBody: JSON.stringify(Array(101).fill(wideItem)) }),
    );
    const arrayRules = arrayResult.candidates.map(
      (candidate) => candidate.ruleId,
    );
    expect(arrayRules).toContain("api.unbounded_array");
    expect(arrayRules).toContain("api.excessive_fields");

    const definition = analyze(
      input({
        path: "/openapi.json",
        responseBody: JSON.stringify({ openapi: "3.1.0", paths: {} }),
      }),
    );
    expect(
      definition.assets.some((asset) => asset.kind === "OpenAPI definition"),
    ).toBe(true);
    expect(
      definition.candidates.some(
        (candidate) => candidate.ruleId === "api.definition_exposed",
      ),
    ).toBe(true);
  });

  it("suppresses unbounded-array noise when pagination is visible", () => {
    const result = analyze(
      input({
        query: "page=1&limit=200",
        responseBody: JSON.stringify(Array(101).fill({ id: 1 })),
      }),
    );
    expect(
      result.candidates.some(
        (candidate) => candidate.ruleId === "api.unbounded_array",
      ),
    ).toBe(false);
  });

  it("detects business-flow, webhook, and bounded resource review leads", () => {
    const business = analyze(input({ method: "POST", path: "/api/checkout" }));
    expect(
      business.candidates.some(
        (candidate) => candidate.ruleId === "api.sensitive_business_flow",
      ),
    ).toBe(true);

    const webhook = analyze(input({ method: "POST", path: "/api/webhooks" }));
    expect(
      webhook.candidates.some(
        (candidate) => candidate.ruleId === "api.webhook_receiver",
      ),
    ).toBe(true);

    const resource = analyze(
      input({ path: "/api/export", responseBytes: 2 * 1024 * 1024 }),
    );
    expect(
      resource.candidates.some(
        (candidate) => candidate.ruleId === "api.resource_intensive_no_limit",
      ),
    ).toBe(true);
  });

  it("confirms TRACE only when the saved response echoes the request", () => {
    const requestRaw =
      "TRACE /api/users HTTP/1.1\r\nHost: example.test\r\nX-Probe: marker\r\n\r\n";
    const result = analyze(
      input({
        method: "TRACE",
        requestRaw,
        responseBody: requestRaw,
        responseContentType: "message/http",
      }),
    );
    const candidate = result.candidates.find(
      (value) => value.ruleId === "header.trace_echo",
    );
    expect(candidate?.confidence).toBe("Confirmed");
  });

  it("inventories GraphQL introspection and batch capabilities", () => {
    const introspection = analyze(
      input({
        path: "/graphql",
        responseBody: JSON.stringify({
          data: { __schema: { queryType: { name: "Query" } } },
        }),
      }),
    );
    expect(
      introspection.candidates.some(
        (candidate) => candidate.ruleId === "api.graphql_introspection",
      ),
    ).toBe(true);

    const requestBody = JSON.stringify([
      { query: "{ viewer { id } }" },
      { query: "{ viewer { name } }" },
    ]);
    const batch = analyze(
      input({
        method: "POST",
        path: "/graphql",
        requestBody,
        requestContentType: "application/json",
      }),
    );
    expect(
      batch.candidates.some(
        (candidate) => candidate.ruleId === "api.graphql_batch",
      ),
    ).toBe(true);
  });

  it("requires a browser-controlled source as well as a DOM sink", () => {
    const result = analyze(
      input({
        path: "/static.js",
        responseContentType: "application/javascript",
        responseBody: "element.innerHTML = trustedTemplate;",
      }),
    );
    expect(
      result.candidates.some((candidate) => candidate.ruleId === "js.dom_sink"),
    ).toBe(false);
  });

  it("detects concrete sensitive response values while redacting evidence", () => {
    const passwordHash =
      "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
    const card = "4111111111111111";
    const result = analyze(
      input({
        statusCode: 500,
        responseBody: JSON.stringify({
          password_hash: passwordHash,
          card_number: card,
          error: "SQLSTATE[42000] syntax error",
        }),
      }),
    );
    const rules = result.candidates.map((candidate) => candidate.ruleId);
    expect(rules).toContain("response.password_hash");
    expect(rules).toContain("response.payment_card");
    expect(rules).toContain("response.sql_error");
    expect(JSON.stringify(result)).not.toContain(card);
    expect(JSON.stringify(result)).not.toContain(passwordHash);
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
    responseBytes: 64,
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
