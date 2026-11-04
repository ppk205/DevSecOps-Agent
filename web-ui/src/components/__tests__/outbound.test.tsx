import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { OutboundNotifications } from "../OutboundNotifications";
import * as client from "../../api/client";

vi.mock("../../api/client", () => ({ fetchOutboundSettings: vi.fn(), saveOutboundSettings: vi.fn(), fetchOutbound: vi.fn(), sendOutbound: vi.fn() }));

beforeEach(() => {
  vi.mocked(client.fetchOutboundSettings).mockResolvedValue({ settings: { schema_version: 1, mode: "manual", telegram: { enabled: false, events: [], token_env: "DEVSEC_TELEGRAM_BOT_TOKEN", chat_env: "DEVSEC_TELEGRAM_CHAT_ID" }, discord: { enabled: false, events: [], webhook_env: "DEVSEC_DISCORD_WEBHOOK_SECRET" } }, events: { scan_completed: "Scan completed", gate_failed: "Security gate failed" } });
});

it("requires an explicit event choice and save without sending", async () => {
  render(<OutboundNotifications />);
  fireEvent.click(screen.getByRole("button", { name: "Telegram / Discord" }));
  await screen.findByLabelText("Telegram enabled");
  fireEvent.click(screen.getByLabelText("Telegram enabled"));
  fireEvent.click(screen.getByLabelText("Telegram: Scan completed"));
  fireEvent.change(screen.getByLabelText("Delivery mode"), { target: { value: "automatic" } });
  vi.mocked(client.saveOutboundSettings).mockResolvedValue(await client.fetchOutboundSettings());
  fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
  await waitFor(() => expect(client.saveOutboundSettings).toHaveBeenCalledWith(expect.objectContaining({ mode: "automatic", telegram: expect.objectContaining({ enabled: true, events: ["scan_completed"] }) })));
  expect(client.sendOutbound).not.toHaveBeenCalled();
});
