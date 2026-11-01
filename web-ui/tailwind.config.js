/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#000000",
        soft: "#0d0d0d",
        card: "#1a1a1a",
        elevated: "#262626",
        carbon: "#2b2b2b",
        hairline: "#3c3c3c",
        ink: "#ffffff",
        body: "#bbbbbb",
        muted: "#7e7e7e",
        mblue: "#0066b1",
        mbluedark: "#1c69d4",
        mred: "#e22718",
        electric: "#0653b6",
        warning: "#f4b400",
        success: "#0fa336",
      },
      fontFamily: {
        sans: ["Inter Variable", "Inter", "system-ui", "sans-serif"],
      },
      letterSpacing: {
        display: "-0.5px",
        label: "1.5px",
      },
      maxWidth: {
        pitwall: "1440px",
      },
    },
  },
  plugins: [],
};
