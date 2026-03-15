/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: 'class',          // enables dark: prefix
  theme: {
    extend: {
      colors: {
        'cti-primary': '#3b82f6',    // blue for links/buttons
        'cti-critical': '#ef4444',   // red for high-risk
        'cti-warning': '#f59e0b',
        'cti-info': '#10b981',
        'cti-bg': '#0f172a',         // dark slate bg
        'cti-card': '#1e293b',
      },
    },
  },
  plugins: [],
}