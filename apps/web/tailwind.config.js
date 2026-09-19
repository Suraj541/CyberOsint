/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        paper: {
          bg: "var(--body-bg)",
          surface: "var(--card-bg)",
          card: "var(--card-bg)",
          panel: "var(--paper-panel)",
          muted: "var(--paper-muted)",
          border: "var(--card-border)",
          borderDark: "var(--border-dark)",
          ink: "var(--text-primary)",
          graphite: "var(--text-muted)",
          amber: "var(--accent-amber)",
          accent: "var(--accent-amber)",
          ochre: "#D97706",
          sage: "#2D7A4F",
          crimson: "#B91C1C",
        },
        cyber: {
          dark: "#171714",
          card: "#FFFDF5",
          border: "#E4DBC8",
          cyan: "#C2821A",
          emerald: "#2D7A4F",
          amber: "#D97706",
          crimson: "#B91C1C",
          violet: "#7C3AED",
        },
      },
      boxShadow: {
        dossier: "0 1px 3px rgba(23, 23, 20, 0.05), 0 4px 12px rgba(23, 23, 20, 0.03)",
        elevated: "0 4px 6px -1px rgba(23, 23, 20, 0.06), 0 10px 15px -3px rgba(23, 23, 20, 0.04)",
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
