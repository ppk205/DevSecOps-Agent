import "@testing-library/jest-dom/vitest";

// Vitest has no backend: default every test to the mock layer.
// A test that needs live-API behavior can override per-file with vi.stubEnv.
process.env.VITE_MOCK ??= "1";
