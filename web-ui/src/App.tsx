import { Route, Routes } from "react-router-dom";
import { Shell } from "./layout/Shell";
import { FindingsPage, HomePage, LivePage, PlaceholderPage } from "./pages/pages";
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
        <Route
          path="reports"
          element={<PlaceholderPage title={en.reports.title} subtitle={en.reports.subtitle} />}
        />
        <Route
          path="logs"
          element={<PlaceholderPage title={en.logs.title} subtitle={en.logs.subtitle} />}
        />
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
