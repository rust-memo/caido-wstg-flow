import { describe, expect, it } from "vitest";

import { compareMessages, dice } from "./comparator";

describe("WSTG verification comparator", () => {
  it("flags a possible authorization bypass for distinct identities and same JSON", () => {
    const result = compareMessages(
      "GET /api/orders/7 HTTP/1.1\r\nAuthorization: Bearer alice\r\n\r\n",
      'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":7,"owner":"alice"}',
      "GET /api/orders/7 HTTP/1.1\r\nAuthorization: Bearer bob\r\n\r\n",
      'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":7,"owner":"alice"}',
    );
    expect(result.outcome).toBe("POSSIBLE_AUTHORIZATION_BYPASS");
    expect(result.identityDifferent).toBe(true);
  });

  it("recognizes explicit access denial", () => {
    const result = compareMessages(
      "GET /private HTTP/1.1\r\nCookie: sid=a\r\n\r\n",
      "HTTP/1.1 200 OK\r\n\r\nsecret",
      "GET /private HTTP/1.1\r\nCookie: sid=b\r\n\r\n",
      "HTTP/1.1 403 Forbidden\r\n\r\ndenied",
    );
    expect(result.outcome).toBe("ACCESS_DENIED");
  });

  it("calculates bounded similarity", () => {
    expect(dice("abcdef", "abcdef")).toBe(1);
    expect(dice("abcdef", "uvwxyz")).toBeGreaterThanOrEqual(0);
    expect(dice("abcdef", "uvwxyz")).toBeLessThanOrEqual(1);
  });

  it("does not call different request targets the same content", () => {
    const result = compareMessages(
      "GET /orders/1 HTTP/1.1\r\nAuthorization: Bearer alice\r\n\r\n",
      "HTTP/1.1 200 OK\r\n\r\nsame",
      "GET /orders/2 HTTP/1.1\r\nAuthorization: Bearer bob\r\n\r\n",
      "HTTP/1.1 200 OK\r\n\r\nsame",
    );
    expect(result.sameResource).toBe(false);
    expect(result.outcome).toBe("INCONCLUSIVE");
  });

  it("ignores volatile JSON keys and redacts sensitive changes", () => {
    const result = compareMessages(
      "GET /profile HTTP/1.1\r\nCookie: sid=a\r\n\r\n",
      'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"requestId":"a","password":"one","name":"Alice"}',
      "GET /profile HTTP/1.1\r\nCookie: sid=b\r\n\r\n",
      'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"requestId":"b","password":"two","name":"Bob"}',
    );
    expect(result.jsonCompared).toBe(true);
    expect(result.jsonChanges.join(" ")).not.toContain("one");
    expect(result.jsonChanges.join(" ")).not.toContain("two");
    expect(result.jsonChanges.join(" ")).not.toContain("requestId");
    expect(result.jsonChanges.join(" ")).toContain("[REDACTED]");
  });

  it("normalizes line endings and volatile body values", () => {
    const result = compareMessages(
      "GET /status HTTP/1.1\n\n",
      "HTTP/1.1 200 OK\nX-Test: a\n\nrun 550e8400-e29b-41d4-a716-446655440000 at 1712345678901",
      "GET /status HTTP/1.1\n\n",
      "HTTP/1.1 200 OK\nX-Test: b\n\nrun 123e4567-e89b-12d3-a456-426614174000 at 1712345678999",
    );
    expect(result.outcome).toBe("SAME_CONTENT");
    expect(result.headerChanges).toContain("x-test");
  });
});
