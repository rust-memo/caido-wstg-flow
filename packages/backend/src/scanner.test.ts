import { afterEach, describe, expect, it, vi } from "vitest";

import { WstgScanner, type WstgSDK } from "./scanner";

describe("scanner lifecycle", () => {
  afterEach(() => vi.useRealTimers());

  it("does not enter paused or scanning state while idle", () => {
    const events: Array<{ name: string; value: unknown }> = [];
    const scanner = new WstgScanner();
    const sdk = eventSDK(events);
    scanner.pause(sdk);
    scanner.resume(sdk);
    expect(events).toEqual([]);
  });

  it("cancels into a clean idle state and batches a data change", async () => {
    vi.useFakeTimers();
    const events: Array<{ name: string; value: unknown }> = [];
    const scanner = new WstgScanner();
    scanner.cancel(eventSDK(events), "Cancelled for test");
    expect(events[0]).toMatchObject({
      name: "scan-state",
      value: {
        phase: "IDLE",
        queued: 0,
        active: 0,
        scanned: 0,
        dropped: 0,
        message: "Cancelled for test",
      },
    });
    await vi.runAllTimersAsync();
    expect(events[1]).toMatchObject({
      name: "data-changed",
      value: { revision: 1, areas: ["overview"] },
    });
  });
});

function eventSDK(events: Array<{ name: string; value: unknown }>): WstgSDK {
  return {
    api: {
      send: (name: string, value: unknown) => events.push({ name, value }),
    },
  } as unknown as WstgSDK;
}
