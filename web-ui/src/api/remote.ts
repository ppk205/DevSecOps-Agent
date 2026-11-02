import { redactValue } from "../utils/redact";

export type Mode = "ask" | "auto";
export interface ModelEntry {
  alias: string;
  protocol: string;
  base_url: string;
  models: string[];
  default_model: string;
  local: boolean;
  key_set: boolean;
}
export interface ModelTemplate {
  id: string;
  label: string;
  protocol: string;
  base_url: string;
  models: string[];
  default_model: string | null;
}
export interface ReadyInfo {
  target: string;
  commit: string;
  dirty: boolean;
  provider: string;
  model: string;
  mode: Mode;
  local: boolean;
}
export interface PendingReview {
  id: string;
  source: string;
  ref: string | null;
  files: string[];
  at: string;
}
interface Envelope { protocol: "devsec-chat/1"; seq: number }
export interface PermissionRequest extends Envelope {
  type: "permission_request";
  request_id: string;
  gate: string;
  title: string;
  detail: string;
  payload: Record<string, unknown>;
  ai_recommendation: string;
  mode: Mode;
  dangerous: boolean;
  choices: string[];
}
export interface Usage {
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number | null;
  total_tokens?: number;
  total_cost_usd?: number | null;
}
export type RemoteEvent = Envelope & (
  | { type: "models"; items: ModelEntry[]; templates?: ModelTemplate[] }
  | ({ type: "ready" } & ReadyInfo)
  | { type: "text_delta"; text: string; role?: "user" | "assistant" }
  | { type: "tool_call"; id: string; name: string; arguments: unknown }
  | { type: "tool_result"; id: string; name: string; summary: string; result?: unknown }
  | PermissionRequest
  | { type: "gate_result"; request_id: string; gate: string; choice: string; person: string; mode?: Mode }
  | ({ type: "usage"; provider?: string; model?: string } & Usage)
  | { type: "error"; message: string }
  | { type: "done"; reason: string }
  | { type: "remote"; url?: string; off?: boolean }
  | { type: "pending"; items: PendingReview[] }
);
export interface PermissionReply {
  type: "permission_reply";
  request_id: string;
  choice: string;
  reason: string;
  edits?: Record<string, unknown>;
  confirm?: string;
}
export type RemoteMessage =
  | { type: "hello" }
  | { type: "start"; target: string; model: string; mode: Mode }
  | { type: "user_message"; text: string }
  | PermissionReply
  | { type: "interrupt" }
  | { type: "command"; name: string; args: string[] }
  | { type: "model_add"; alias: string; template: string | null; model_protocol: string; base_url: string; models: string[]; key: string }
  | { type: "model_key"; alias: string; key: string }
  | { type: "model_remove"; alias: string };
export interface ReplyResult { ok: boolean; error?: string }
export interface RemoteState {
  seq: number;
  ready: ReadyInfo | null;
  pending_request: PermissionRequest | null;
  pending_reviews: PendingReview[];
  totals: Usage;
  models?: ModelEntry[];
  busy: boolean;
  started?: boolean;
}

// Intentionally same-origin: the one-time login and model keys belong to this host.
async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error(`GET ${path} → ${response.status}`);
  return await response.json() as T;
}

async function post(path: string, body: unknown): Promise<ReplyResult> {
  let csrf = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("csrf_token="))?.slice("csrf_token=".length);
  if (!csrf) {
    // This GET returns a CSRF token even with 401 before the one-time login.
    const bootstrap = await fetch("/api/remote/state", { credentials: "same-origin", cache: "no-store" });
    const value = await bootstrap.json() as { csrf_token?: string };
    if (!bootstrap.ok && bootstrap.status !== 401) throw new Error("CSRF token unavailable");
    csrf = value.csrf_token;
  }
  if (!csrf) throw new Error("CSRF token unavailable");
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  });
  const result: ReplyResult = await response.json().catch(() => ({ ok: false }));
  if (!response.ok && !result.error) throw new Error(`POST ${path} → ${response.status}`);
  return redactValue({ ok: response.ok && result.ok !== false, error: result.error });
}

export async function login(token: string): Promise<void> {
  const result = await post("/api/remote/login", { token });
  if (!result.ok) throw new Error("Remote login failed");
}

export async function getState(): Promise<RemoteState> {
  const state = await get<RemoteState & { pending?: PermissionRequest | null }>("/api/remote/state");
  const totals = state.totals || {};
  const pending = state.pending_request ?? state.pending;
  return redactValue({
    ...state, pending_request: pending ? { ...pending, protocol: "devsec-chat/1", seq: pending.seq ?? state.seq } : null,
    pending_reviews: state.pending_reviews || [],
    totals: { ...totals,
      total_tokens: totals.total_tokens ?? (typeof totals.input_tokens === "number" && typeof totals.output_tokens === "number" ? totals.input_tokens + totals.output_tokens : undefined),
      total_cost_usd: totals.total_cost_usd ?? totals.cost_usd,
    },
  });
}

export function send(msg: RemoteMessage): Promise<ReplyResult> {
  return post("/api/remote/messages", { ...msg, protocol: "devsec-chat/1" });
}

export interface SubscriptionOptions {
  onStatus?: (status: "connected" | "reconnecting") => void;
  onReconnect?: () => void | Promise<void>;
}

const EVENT_TYPES = ["models", "ready", "text_delta", "tool_call", "tool_result", "permission_request", "gate_result", "usage", "error", "done", "remote", "pending"];

/** Recreate EventSource with the last accepted sequence, rather than its original URL. */
export function subscribe(after: number, onEvent: (e: RemoteEvent) => void, options: SubscriptionOptions = {}): () => void {
  let lastSeq = after;
  let source: EventSource;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  let opened = false;
  let delay = 1000;
  const connect = () => {
    if (stopped) return;
    source = new EventSource(`/api/remote/events?after=${lastSeq}`);
    const current = source;
    const receive = (message: MessageEvent) => {
      if (stopped || source !== current) return;
      let event: RemoteEvent;
      try { event = JSON.parse(message.data) as RemoteEvent; } catch { return; }
      if (!event || event.protocol !== "devsec-chat/1" || !Number.isSafeInteger(event.seq) || event.seq <= lastSeq || !EVENT_TYPES.includes(event.type)) return;
      lastSeq = event.seq;
      onEvent(redactValue(event));
    };
    source.onmessage = receive;
    // Accept both unnamed SSE frames and frames named after their protocol type.
    EVENT_TYPES.forEach((type) => current.addEventListener(type, receive as EventListener));
    source.onopen = () => {
      if (stopped || source !== current) return;
      options.onStatus?.("connected");
      if (opened) void options.onReconnect?.();
      opened = true;
      delay = 1000;
    };
    source.onerror = () => {
      if (stopped || source !== current || timer !== undefined) return;
      current.close();
      options.onStatus?.("reconnecting");
      timer = setTimeout(() => { timer = undefined; connect(); }, delay);
      delay = Math.min(delay * 2, 10000);
    };
  };
  connect();
  return () => { stopped = true; clearTimeout(timer); source?.close(); };
}
