/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        panel: '#0b1220',
        sidebar: '#0f172a',
        accent: '#60a5fa',
        danger: '#ef4444',
        warn: '#f59e0b',
        success: '#10b981',
      },
    },
  },
  plugins: [],
};
