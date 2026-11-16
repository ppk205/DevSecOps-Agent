import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { OutboundNotifications } from "../OutboundNotifications";
import * as client from "../../api/client";

vi.mock("../../api/client", () => ({ fetchOutboundSettings: vi.fn(), saveOutboundSettings: vi.fn(), fetchOutbound: vi.fn(), sendOutbound: vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(client.fetchOutboundSettings).mockResolvedValue({ settings: { schema_version: 2, mode: "manual", telegram: { enabled: false, events: [], token_env: "DEVSEC_TELEGRAM_BOT_TOKEN", chat_env: "DEVSEC_TELEGRAM_CHAT_ID" }, discord: { enabled: false, events: [], webhook_env: "DEVSEC_DISCORD_WEBHOOK_SECRET" }, webhook: { enabled: false, events: [], url_env: "DEVSEC_WEBHOOK_URL", signing_key_env: "DEVSEC_WEBHOOK_SIGNING_SECRET", allowed_hosts: [] } }, events: { scan_completed: "Scan completed", gate_failed: "Security gate failed" } });
});

it("requires explicit consent before retrying an unknown webhook delivery", async () => {
  vi.mocked(client.fetchOutbound).mockResolvedValue({ run_id: "run-1", deliveries: [{ channel: "webhook", status: "unknown", detail: "No acknowledgement", delivery_id: "id", events: [{ kind: "scan_completed", label: "Scan completed", message: "Complete" }], selected_events: ["scan_completed"] }] });
  vi.mocked(client.sendOutbound).mockResolvedValue({ run_id: "run-1", deliveries: [] });
  const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  render(<OutboundNotifications />);
  fireEvent.click(screen.getByRole("button", { name: "Notification settings" }));
  await screen.findByLabelText("Webhook enabled");
  fireEvent.change(screen.getByLabelText("Run ID"), { target: { value: "run-1" } });
  fireEvent.click(screen.getByRole("button", { name: "Load deliveries" }));
  const retry = await screen.findByRole("button", { name: "Retry webhook delivery" });
  fireEvent.click(retry);
  expect(client.sendOutbound).not.toHaveBeenCalled();
  fireEvent.click(retry);
  await waitFor(() => expect(client.sendOutbound).toHaveBeenCalledWith("run-1", ["scan_completed"], ["webhook"], true));
  confirm.mockRestore();
});

it("saves generic webhook references, host and events without sending", async () => {
  render(<OutboundNotifications />);
  fireEvent.click(screen.getByRole("button", { name: "Notification settings" }));
  await screen.findByLabelText("Webhook enabled");
  fireEvent.click(screen.getByLabelText("Webhook enabled"));
  fireEvent.click(screen.getByLabelText("Webhook: Scan completed"));
  fireEvent.change(screen.getByLabelText("Webhook allowed hosts"), { target: { value: "hooks.example.com" } });
  fireEvent.change(screen.getByLabelText("Webhook URL environment variable"), { target: { value: "CUSTOM_URL" } });
  vi.mocked(client.saveOutboundSettings).mockResolvedValue(await client.fetchOutboundSettings());
  fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
  await waitFor(() => expect(client.saveOutboundSettings).toHaveBeenCalledWith(expect.objectContaining({ webhook: expect.objectContaining({ enabled: true, events: ["scan_completed"], allowed_hosts: ["hooks.example.com"], url_env: "CUSTOM_URL" }) })));
  expect(client.sendOutbound).not.toHaveBeenCalled();
});

it("requires an explicit event choice and save without sending", async () => {
  render(<OutboundNotifications />);
  fireEvent.click(screen.getByRole("button", { name: "Notification settings" }));
  await screen.findByLabelText("Telegram enabled");
  fireEvent.click(screen.getByLabelText("Telegram enabled"));
  fireEvent.click(screen.getByLabelText("Telegram: Scan completed"));
  fireEvent.change(screen.getByLabelText("Delivery mode"), { target: { value: "automatic" } });
  vi.mocked(client.saveOutboundSettings).mockResolvedValue(await client.fetchOutboundSettings());
  fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
  await waitFor(() => expect(client.saveOutboundSettings).toHaveBeenCalledWith(expect.objectContaining({ mode: "automatic", telegram: expect.objectContaining({ enabled: true, events: ["scan_completed"] }) })));
  expect(client.sendOutbound).not.toHaveBeenCalled();
});
