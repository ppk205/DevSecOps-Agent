import "@testing-library/jest-dom/vitest";

// Vitest không có backend: mặc định mọi test đều dùng tầng mock.
// Test nào cần hành vi API trực tiếp có thể ghi đè theo từng file bằng vi.stubEnv.
process.env.VITE_MOCK ??= "1";
