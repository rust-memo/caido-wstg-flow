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
});
