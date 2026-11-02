import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ModelManager } from "./ModelManager";

const template = {
  id: "sample-template", label: "Sample template", protocol: "openai_chat_completions",
  base_url: "http://localhost:8001/v1", models: ["secondary", "primary"], default_model: "primary",
};

describe("remote added models", () => {
  it("submits a model-owned masked key without retaining it in the form", async () => {
    const send = vi.fn().mockResolvedValue({ ok: true });
    render(<ModelManager models={[]} onSend={send} disabled={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    fireEvent.change(screen.getByLabelText("Model alias"), { target: { value: "my-model" } });
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "http://localhost:8001/v1" } });
    fireEvent.change(screen.getByLabelText("Model IDs (one per line)"), { target: { value: "sample-model" } });
    const key = screen.getByLabelText("API key");
    expect(key).toHaveAttribute("type", "password");
    fireEvent.change(key, { target: { value: "test-only-placeholder" } });
    fireEvent.click(screen.getByRole("button", { name: "Save model" }));
    await waitFor(() => expect(send).toHaveBeenCalledWith({ type: "model_add", alias: "my-model", template: null, model_protocol: "openai_compatible", base_url: "http://localhost:8001/v1", models: ["sample-model"], key: "test-only-placeholder" }));
    expect(key).toHaveValue("");
    expect(screen.queryByText("test-only-placeholder")).not.toBeInTheDocument();
  });

  it("prefills a host-supplied template and sends explicit user overrides", async () => {
    const send = vi.fn().mockResolvedValue({ ok: true });
    const { rerender } = render(<ModelManager models={[]} templates={[template]} onSend={send} disabled={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    const selector = screen.getByLabelText("Template");
    expect(screen.getByRole("option", { name: "Custom" })).toBeInTheDocument();
    fireEvent.change(selector, { target: { value: template.id } });
    expect(screen.getByLabelText("Protocol")).toHaveValue("openai_chat_completions");
    expect(screen.getByLabelText("Base URL")).toHaveValue(template.base_url);
    expect(screen.getByLabelText("Model IDs (one per line)")).toHaveValue("primary\nsecondary");

    fireEvent.change(screen.getByLabelText("Model alias"), { target: { value: "my-custom-model" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "anthropic_messages" } });
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "http://localhost:8002/messages" } });
    fireEvent.change(screen.getByLabelText("Model IDs (one per line)"), { target: { value: "override-one\noverride-two" } });
    rerender(<ModelManager models={[]} templates={[{ ...template, base_url: "http://localhost:8003/v1" }]} onSend={send} disabled={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Save model" }));
    await waitFor(() => expect(send).toHaveBeenCalledWith({
      type: "model_add", alias: "my-custom-model", template: template.id,
      model_protocol: "anthropic_messages", base_url: "http://localhost:8002/messages",
      models: ["override-one", "override-two"], key: "",
    }));
  });

  it("uses a template's default model when its list is empty and preserves fields when choosing Custom", async () => {
    const send = vi.fn().mockResolvedValue({ ok: true });
    render(<ModelManager models={[]} templates={[{ ...template, models: [], default_model: "fallback-model" }]} onSend={send} disabled={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    fireEvent.change(screen.getByLabelText("Template"), { target: { value: template.id } });
    expect(screen.getByLabelText("Model IDs (one per line)")).toHaveValue("fallback-model");
    fireEvent.change(screen.getByLabelText("Template"), { target: { value: "custom" } });
    expect(screen.getByLabelText("Base URL")).toHaveValue(template.base_url);
    fireEvent.change(screen.getByLabelText("Model alias"), { target: { value: "custom-model" } });
    fireEvent.click(screen.getByRole("button", { name: "Save model" }));
    await waitFor(() => expect(send).toHaveBeenCalledWith(expect.objectContaining({ template: null, model_protocol: template.protocol, models: ["fallback-model"] })));
  });
});
