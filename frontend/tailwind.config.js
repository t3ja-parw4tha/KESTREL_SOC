/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0f1117',
          surface: '#1a1d27',
          border: '#2a2d3a',
          text: '#e2e8f0',
          muted: '#64748b',
        },
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#3b82f6',
        safe: '#22c55e',
      },
    },
  },
  plugins: [],
}
