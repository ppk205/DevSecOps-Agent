import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { PermissionRequest } from "../../api/remote";
import { GateDialog } from "./GateDialog";

export const gate: PermissionRequest = {
  protocol: "devsec-chat/1", type: "permission_request", seq: 2,
  request_id: "request-1", gate: "G6", title: "Apply proposed fix", detail: "Write the reviewed fix to a worktree.",
  payload: { paths: ["src/Servlet.java"], diff: "--- a/src/Servlet.java\n+++ b/src/Servlet.java\n-old\n+new", provider: "local-test", model: "test-model" },
  ai_recommendation: "Review the proposed change", mode: "ask", dangerous: true, choices: ["apply", "reject", "defer"],
};

describe("remote gate dialog", () => {
  it('G6 apply disabled until diff end and "apply" typed', async () => {
    const reply = vi.fn().mockResolvedValue({ ok: true });
    render(<GateDialog request={gate} onReply={reply} onClose={vi.fn()} />);
    const apply = screen.getByRole("button", { name: /\[a\].*Apply/ });
    expect(apply).toBeDisabled();
    const diff = screen.getByRole("region", { name: "Full proposed diff" });
    Object.defineProperties(diff, { scrollHeight: { configurable: true, value: 900 }, clientHeight: { configurable: true, value: 200 }, scrollTop: { configurable: true, writable: true, value: 200 } });
    fireEvent.change(screen.getByLabelText('Type "apply" to confirm'), { target: { value: "apply" } });
    fireEvent.scroll(diff);
    expect(apply).toBeDisabled();
    diff.scrollTop = 700;
    fireEvent.scroll(diff);
    expect(apply).toBeEnabled();
    fireEvent.click(apply);
    await waitFor(() => expect(reply).toHaveBeenCalledWith(expect.objectContaining({ type: "permission_reply", request_id: "request-1", choice: "apply", confirm: "apply" })));
    expect(screen.getByText(/src\/Servlet.java/, { selector: "pre" })).toBeInTheDocument();
  });

  it("Enter with nothing highlighted does nothing; arrows select explicitly", async () => {
    const reply = vi.fn().mockResolvedValue({ ok: true });
    render(<GateDialog request={{ ...gate, gate: "G3", dangerous: false, choices: ["approve", "edit", "reject"] }} onReply={reply} onClose={vi.fn()} />);
    const dialog = screen.getByRole("dialog");
    fireEvent.keyDown(dialog, { key: "Enter" });
    expect(reply).not.toHaveBeenCalled();
    fireEvent.keyDown(dialog, { key: "ArrowRight" });
    fireEvent.keyDown(dialog, { key: "Enter" });
    await waitFor(() => expect(reply).toHaveBeenCalledWith(expect.objectContaining({ choice: "approve" })));
  });

  it("requires a rejection reason and ignores shortcuts inside text fields", async () => {
    const reply = vi.fn().mockResolvedValue({ ok: true });
    render(<GateDialog request={{ ...gate, gate: "G0", choices: ["approve", "reject"] }} onReply={reply} onClose={vi.fn()} />);
    expect(screen.getByRole("button", { name: /\[y\].*Approve/ })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /\[n\].*Reject/ }));
    expect(reply).not.toHaveBeenCalled();
    const reason = screen.getByLabelText("Reason");
    fireEvent.change(reason, { target: { value: "Keep this local" } });
    fireEvent.keyDown(reason, { key: "y" });
    expect(reply).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /\[n\].*Reject/ }));
    await waitFor(() => expect(reply).toHaveBeenCalledWith(expect.objectContaining({ choice: "reject", reason: "Keep this local" })));
  });

  it("malformed and non-object edits leave the gate undecided", async () => {
    const reply = vi.fn();
    render(<GateDialog request={{ ...gate, gate: "G1", choices: ["approve", "edit", "reject"] }} onReply={reply} onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Edited payload (JSON object)"), { target: { value: "[]" } });
    fireEvent.click(screen.getByRole("button", { name: /\[e\].*Edit/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("JSON object");
    expect(reply).not.toHaveBeenCalled();
  });

  it('shows "already answered by" and closes dialog', async () => {
    const close = vi.fn();
    const reply = vi.fn().mockResolvedValue({ ok: false, error: "already answered by tui" });
    render(<GateDialog request={{ ...gate, gate: "G2", choices: ["approve", "reject"] }} onReply={reply} onClose={close} />);
    fireEvent.click(screen.getByRole("button", { name: /Approve/ }));
    await waitFor(() => expect(close).toHaveBeenCalledWith("already answered by tui"));
  });

  it("Escape relays undecided, and blur never approves", async () => {
    const reply = vi.fn().mockResolvedValue({ ok: true });
    render(<GateDialog request={gate} onReply={reply} onClose={vi.fn()} />);
    fireEvent.blur(window);
    expect(reply).not.toHaveBeenCalled();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() => expect(reply).toHaveBeenCalledWith(expect.objectContaining({ choice: "undecided" })));
  });

  it("sends the exact G0 confirmation and resets selections on focus loss", async () => {
    const reply = vi.fn().mockResolvedValue({ ok: true });
    render(<GateDialog request={{ ...gate, gate: "G0", choices: ["approve", "reject"] }} onReply={reply} onClose={vi.fn()} />);
    const input = screen.getByLabelText('Type "send" to confirm');
    fireEvent.change(input, { target: { value: "send" } });
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "ArrowRight" });
    fireEvent.blur(window);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Enter" });
    expect(reply).not.toHaveBeenCalled();
    expect(input).toHaveValue("");
    fireEvent.change(input, { target: { value: "send" } });
    fireEvent.click(screen.getByRole("button", { name: /Approve/ }));
    await waitFor(() => expect(reply).toHaveBeenCalledWith(expect.objectContaining({ choice: "approve", confirm: "send" })));
  });
});
