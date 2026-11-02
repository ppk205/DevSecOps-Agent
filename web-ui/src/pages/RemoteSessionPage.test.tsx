import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RemoteEvent, RemoteState, SubscriptionOptions } from "../api/remote";
import { RemoteSessionPage } from "./RemoteSessionPage";
import { App } from "../App";

const api = vi.hoisted(() => ({ login: vi.fn(), getState: vi.fn(), send: vi.fn(), subscribe: vi.fn() }));
vi.mock("../api/remote", () => api);
let receive: (event: RemoteEvent) => void;
let connection: SubscriptionOptions;
const ready = { target: "sample", commit: "test-commit", dirty: false, provider: "local-test", model: "test-model", mode: "ask" as const, local: true };
const pending = { id: "p1", source: "post-commit", ref: "abc123", files: ["src/Example.java"], at: "2026-11-02T00:00:00Z" };
const initial: RemoteState = { seq: 0, ready, pending_request: null, pending_reviews: [], totals: { total_tokens: 0, total_cost_usd: 0 }, models: [], busy: false };

describe("RemoteSessionPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, "", "/app/remote");
    api.login.mockResolvedValue(undefined);
    api.getState.mockResolvedValue(initial);
    api.send.mockResolvedValue({ ok: true });
    api.subscribe.mockImplementation((_after, callback, options) => { receive = callback; connection = options; options.onStatus?.("connected"); return vi.fn(); });
  });

  it("removes token from URL after login, even under StrictMode", async () => {
    window.history.replaceState({}, "", "/app/remote#t=test-link");
    render(<StrictMode><RemoteSessionPage /></StrictMode>);
    await screen.findByRole("textbox", { name: "Message" });
    expect(api.login).toHaveBeenCalledTimes(1);
    expect(api.login).toHaveBeenCalledWith("test-link");
    expect(window.location.hash).toBe("");
    expect(api.subscribe).toHaveBeenCalledWith(0, expect.any(Function), expect.any(Object));
  });

  it("shows pending banner and relays review/dismiss without deciding locally", async () => {
    api.getState.mockResolvedValue({ ...initial, pending_reviews: [pending] });
    render(<RemoteSessionPage />);
    const review = await screen.findByRole("button", { name: /Review now/ });
    expect(screen.getByText(/abc123/)).toBeInTheDocument();
    fireEvent.click(review);
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "command", name: "pending", args: ["review", "p1"] }));
    fireEvent.click(screen.getByRole("button", { name: /Dismiss/ }));
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "command", name: "pending", args: ["dismiss", "p1"] }));
    expect(screen.getByText(/abc123/)).toBeInTheDocument();
    act(() => receive({ protocol: "devsec-chat/1", type: "pending", seq: 1, items: [] }));
    expect(screen.queryByRole("button", { name: /Review now/ })).not.toBeInTheDocument();
  });

  it("replays transcript once and restores current pending state on reconnect", async () => {
    render(<RemoteSessionPage />);
    await screen.findByRole("textbox", { name: "Message" });
    const event: RemoteEvent = { protocol: "devsec-chat/1", type: "text_delta", seq: 1, text: "AI proposal with citations" };
    act(() => { receive(event); receive(event); });
    expect(screen.getAllByText("AI proposal with citations")).toHaveLength(1);
    api.getState.mockResolvedValue({ ...initial, seq: 2, pending_reviews: [pending] });
    await act(async () => { await connection.onReconnect?.(); });
    expect(await screen.findByRole("button", { name: /Review now/ })).toBeInTheDocument();
  });

  it("closes a pending gate when another client answers", async () => {
    render(<RemoteSessionPage />);
    await screen.findByRole("textbox", { name: "Message" });
    act(() => receive({ protocol: "devsec-chat/1", type: "permission_request", seq: 1, request_id: "g3", gate: "G3", title: "Review candidates", detail: "Inspect these candidates", payload: {}, ai_recommendation: "Review", mode: "ask", dangerous: false, choices: ["approve", "reject"] }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    act(() => receive({ protocol: "devsec-chat/1", type: "gate_result", seq: 2, request_id: "g3", gate: "G3", choice: "approve", person: "tui" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("already answered by tui");
  });

  it("expired login explains how to obtain a new link", async () => {
    window.history.replaceState({}, "", "/app/remote#t=expired-test-link");
    api.login.mockRejectedValue(new Error("401"));
    render(<RemoteSessionPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("/remote on");
    expect(window.location.hash).toBe("");
    expect(api.subscribe).not.toHaveBeenCalled();
  });

  it("starts a headless host using the added alias and waits for host ready", async () => {
    api.getState.mockResolvedValue({ ...initial, ready: null, models: [{ alias: "local-test", protocol: "openai_compatible", base_url: "http://localhost:8001/v1", models: ["test-model"], default_model: "test-model", local: true, key_set: false }] });
    render(<RemoteSessionPage />);
    fireEvent.change(await screen.findByLabelText("Target folder"), { target: { value: "sample-target" } });
    fireEvent.change(screen.getByLabelText("Model"), { target: { value: "local-test:test-model" } });
    fireEvent.click(screen.getByRole("button", { name: "Start session" }));
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "start", target: "sample-target", model: "local-test:test-model", mode: "ask" }));
    expect(screen.queryByRole("textbox", { name: "Message" })).not.toBeInTheDocument();
    act(() => receive({ protocol: "devsec-chat/1", type: "ready", seq: 1, ...ready }));
    act(() => receive({ protocol: "devsec-chat/1", type: "done", seq: 2, reason: "completed" }));
    expect(screen.getByRole("textbox", { name: "Message" })).toBeInTheDocument();
  });

  it("requires explicit confirmation before relaying /mode auto", async () => {
    render(<RemoteSessionPage />);
    fireEvent.change(await screen.findByRole("textbox", { name: "Message" }), { target: { value: "/mode auto" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(api.send).not.toHaveBeenCalledWith(expect.objectContaining({ name: "mode" }));
    fireEvent.click(screen.getByRole("button", { name: "Use auto mode" }));
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "command", name: "mode", args: ["auto", "confirm"] }));
  });

  it("does not reopen a resolved historical gate while replaying transcript", async () => {
    api.getState.mockResolvedValue({ ...initial, seq: 10 });
    render(<RemoteSessionPage />);
    await screen.findByRole("textbox", { name: "Message" });
    act(() => receive({ protocol: "devsec-chat/1", type: "permission_request", seq: 2, request_id: "old", gate: "G3", title: "Old gate", detail: "", payload: {}, ai_recommendation: "", mode: "ask", dangerous: false, choices: ["approve", "reject"] }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("lets an attached client start a preconfigured headless host before G0", async () => {
    api.getState.mockResolvedValue({ ...initial, started: false });
    render(<RemoteSessionPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Start session" }));
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "start", target: "sample", model: "local-test:test-model", mode: "ask" }));
  });

  it("displays initial G0 and only enables chat after the host finishes starting", async () => {
    api.getState.mockResolvedValue({ ...initial, started: false, busy: true, pending_request: { protocol: "devsec-chat/1", type: "permission_request", seq: 1, request_id: "g0", gate: "G0", title: "Session consent", detail: "Send source excerpts", payload: { provider: "test", model: "test", code_leaves_machine: true }, ai_recommendation: "Review scope", mode: "ask", dangerous: true, choices: ["approve", "reject"] } });
    render(<RemoteSessionPage />);
    expect(await screen.findByRole("dialog")).toHaveTextContent("Session consent");
    expect(screen.queryByRole("textbox", { name: "Message" })).not.toBeInTheDocument();
    act(() => {
      receive({ protocol: "devsec-chat/1", type: "gate_result", seq: 2, request_id: "g0", gate: "G0", choice: "approve", person: "tui" });
      receive({ protocol: "devsec-chat/1", type: "done", seq: 3, reason: "completed" });
    });
    expect(screen.getByRole("textbox", { name: "Message" })).toBeInTheDocument();
  });

  it("tracks a headless start performed by another attached client", async () => {
    api.getState.mockResolvedValue({ ...initial, started: false });
    render(<RemoteSessionPage />);
    await screen.findByRole("button", { name: "Start session" });
    act(() => {
      receive({ protocol: "devsec-chat/1", type: "ready", seq: 1, ...ready });
      receive({ protocol: "devsec-chat/1", type: "done", seq: 2, reason: "completed" });
    });
    expect(screen.getByRole("textbox", { name: "Message" })).toBeInTheDocument();
  });

  it("routes remote without mounting the baseline shell", async () => {
    render(<MemoryRouter initialEntries={["/remote"]}><App /></MemoryRouter>);
    expect(await screen.findByRole("heading", { name: "Remote session" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("renders the user's message before an immediate host reply", async () => {
    render(<RemoteSessionPage />);
    const input = await screen.findByRole("textbox", { name: "Message" });
    api.send.mockImplementation(async (msg) => {
      if (msg.type === "user_message") {
        receive({ protocol: "devsec-chat/1", type: "text_delta", role: "user", seq: 1, text: msg.text });
        receive({ protocol: "devsec-chat/1", type: "text_delta", role: "assistant", seq: 2, text: "Immediate proposal" });
      }
      return { ok: true };
    });
    fireEvent.change(input, { target: { value: "Review this change" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(screen.getByRole("log").textContent).toMatch(/Review this change.*Immediate proposal/));
    expect(screen.getAllByText("Review this change")).toHaveLength(1);
    expect(screen.getByRole("log")).toHaveTextContent("YouReview this change");
  });

  it("banner letter shortcuts never fire while typing a message", async () => {
    api.getState.mockResolvedValue({ ...initial, pending_reviews: [pending] });
    render(<RemoteSessionPage />);
    const input = await screen.findByRole("textbox", { name: "Message" });
    fireEvent.keyDown(input, { key: "r" });
    expect(api.send).not.toHaveBeenCalledWith(expect.objectContaining({ name: "pending" }));
    fireEvent.keyDown(screen.getByRole("main"), { key: "r" });
    await waitFor(() => expect(api.send).toHaveBeenCalledWith({ type: "command", name: "pending", args: ["review", "p1"] }));
  });

  it("passes templates from the models event into the model form", async () => {
    api.getState.mockResolvedValue({ ...initial, ready: null, started: false });
    render(<RemoteSessionPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Add model" }));
    act(() => receive({ protocol: "devsec-chat/1", type: "models", seq: 1, items: [], templates: [
      { id: "public-template", label: "Public template", protocol: "openai_compatible", base_url: "http://localhost:8001/v1", models: ["test-model"], default_model: "test-model" },
    ] }));
    expect(screen.getByRole("option", { name: "Public template" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Template"), { target: { value: "public-template" } });
    expect(screen.getByLabelText("Base URL")).toHaveValue("http://localhost:8001/v1");
    expect(screen.getByLabelText("Model IDs (one per line)")).toHaveValue("test-model");
  });
});
