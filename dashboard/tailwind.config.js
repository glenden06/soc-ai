/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0B0E14",
        panel: "#121722",
        line: "#1F2733",
        muted: "#7A8799",
        text: "#D9E2EC",
        sev: {
          critical: "#FF0000",
          high: "#FF6600",
          medium: "#FFB300",
          low: "#0066CC",
          info: "#666666",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "IBM Plex Mono", "Menlo", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
