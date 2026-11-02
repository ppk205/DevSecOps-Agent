import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getState, login, send, subscribe } from "./remote";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  onopen: (() => void) | null = null;
  listeners = new Map<string, (event: MessageEvent) => void>();
  close = vi.fn();
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  addEventListener(name: string, fn: (event: MessageEvent) => void) { this.listeners.set(name, fn); }
  emit(seq: number, text = "reply") {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify({ protocol: "devsec-chat/1", type: "text_delta", seq, text }) }));
  }
}

describe("remote transport", () => {
  beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal("EventSource", FakeEventSource);
    document.cookie = "csrf_token=; Max-Age=0; Path=/";
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("replays after reconnect and suppresses duplicate events", () => {
    vi.useFakeTimers();
    const onEvent = vi.fn();
    const onReconnect = vi.fn();
    const stop = subscribe(3, onEvent, { onReconnect });
    const first = FakeEventSource.instances[0];
    expect(first.url).toBe("/api/remote/events?after=3");
    first.onopen?.();
    first.emit(4);
    first.emit(4);
    first.onerror?.();
    vi.advanceTimersByTime(1000);
    const second = FakeEventSource.instances[1];
    expect(second.url).toBe("/api/remote/events?after=4");
    second.onopen?.();
    second.emit(4);
    second.emit(5);
    expect(onEvent.mock.calls.map(([e]) => e.seq)).toEqual([4, 5]);
    expect(onReconnect).toHaveBeenCalledTimes(1);
    stop();
    expect(second.close).toHaveBeenCalled();
    second.onerror?.();
    vi.runAllTimers();
    expect(FakeEventSource.instances).toHaveLength(2);
  });

  it("sends authenticated CSRF-protected login and protocol messages", async () => {
    const fetcher = vi.fn().mockImplementation(async (url: string) => ({
      ok: true,
      json: async () => url === "/api/remote/state" ? { csrf_token: "test-csrf" } : { ok: true },
    }));
    vi.stubGlobal("fetch", fetcher);
    await login("test-link");
    await send({ type: "user_message", text: "Review changes" });
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === "POST");
    expect(posts).toHaveLength(2);
    expect(posts[0][1]).toMatchObject({ credentials: "same-origin", headers: { "X-CSRF-Token": "test-csrf" }, body: JSON.stringify({ token: "test-link" }) });
    expect(JSON.parse(posts[1][1].body)).toEqual({ protocol: "devsec-chat/1", type: "user_message", text: "Review changes" });
  });

  it("bootstraps CSRF from the pre-login 401 and normalizes the host state", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ csrf_token: "test-csrf" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ ok: true }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ seq: 7, ready: null, started: false, pending: { request_id: "g0" }, pending_reviews: [], totals: { input_tokens: 8, output_tokens: 2, cost_usd: 0.1 }, busy: true }) });
    vi.stubGlobal("fetch", fetcher);
    await login("test-link");
    expect(fetcher.mock.calls[0][0]).toBe("/api/remote/state");
    const state = await getState();
    expect(state).toMatchObject({ pending_request: { request_id: "g0" }, started: false, totals: { total_tokens: 10, total_cost_usd: 0.1 } });
  });

  it("keeps the chat protocol separate from the model transport protocol", async () => {
    document.cookie = "csrf_token=test-csrf; Path=/";
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) });
    vi.stubGlobal("fetch", fetcher);
    await send({ type: "model_add", alias: "test", template: null, model_protocol: "openai_compatible", base_url: "http://localhost:8001/v1", models: ["test-model"], key: "" });
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toMatchObject({ protocol: "devsec-chat/1", model_protocol: "openai_compatible", template: null });
  });

  it("ignores malformed and wrong-protocol events without advancing the replay cursor", () => {
    vi.useFakeTimers();
    const receive = vi.fn();
    const stop = subscribe(0, receive);
    const source = FakeEventSource.instances[0];
    source.onmessage?.(new MessageEvent("message", { data: "not-json" }));
    source.onmessage?.(new MessageEvent("message", { data: JSON.stringify({ seq: 9, protocol: "v1", type: "text_delta" }) }));
    source.emit(1);
    expect(receive).toHaveBeenCalledTimes(1);
    stop();
  });
});
