import { Route, Routes } from "react-router-dom";
import { Shell } from "./layout/Shell";
import { LivePage, PlaceholderPage } from "./pages/pages";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { HomePage } from "./pages/HomePage";
import { KeysPage } from "./pages/KeysPage";
import { LogsPage } from "./pages/LogsPage";
import { NewScanPage } from "./pages/NewScanPage";
import { ReportsPage } from "./pages/ReportsPage";
import { RemoteSessionPage } from "./pages/RemoteSessionPage";
import { StyleguidePage } from "./pages/StyleguidePage";

export function App() {
  return (
    <Routes>
      <Route path="remote" element={<RemoteSessionPage />} />
      <Route element={<Shell />}>
        <Route index element={<HomePage />} />
        <Route path="scans/new" element={<NewScanPage />} />
        <Route path="live" element={<LivePage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="keys" element={<KeysPage />} />
        {/* Hidden styleguide — reachable directly, absent from nav. */}
        <Route path="styleguide" element={<StyleguidePage />} />
        <Route path="*" element={<PlaceholderPage title="Not found" subtitle="No route matches this path." />} />
      </Route>
    </Routes>
  );
}
