import { Route, Routes } from "react-router-dom";
import { Shell } from "./layout/Shell";
import { HomePage, LivePage, PlaceholderPage } from "./pages/pages";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { LogsPage } from "./pages/LogsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { StyleguidePage } from "./pages/StyleguidePage";
import { en } from "./i18n/en";

export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<HomePage />} />
        <Route
          path="scans/new"
          element={<PlaceholderPage title={en.newScan.title} subtitle={en.newScan.subtitle} />}
        />
        <Route path="live" element={<LivePage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route
          path="keys"
          element={<PlaceholderPage title={en.apiKeys.title} subtitle={en.apiKeys.subtitle} />}
        />
        {/* Hidden styleguide — reachable directly, absent from nav. */}
        <Route path="styleguide" element={<StyleguidePage />} />
        <Route path="*" element={<PlaceholderPage title="Not found" subtitle="No route matches this path." />} />
      </Route>
    </Routes>
  );
}
