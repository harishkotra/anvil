/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "monospace"],
      },
      colors: {
        ink: {
          950: "#08090c",
          900: "#0d0f14",
          850: "#11141b",
          800: "#161a22",
          700: "#1f2430",
          600: "#2a3140",
          500: "#3b4457",
        },
        anvil: {
          purple: "#8b5cf6",
          cyan: "#22d3ee",
          amber: "#fbbf24",
          red: "#f87171",
          green: "#4ade80",
        },
      },
    },
  },
  plugins: [],
};
