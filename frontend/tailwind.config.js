/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#F5F3EE',
        'bg-surface': '#FDFCFA',
        'bg-elevated': '#EDEAE4',
        'accent-blue': '#4A6741',
        'accent-cyan': '#7A6548',
        'text-primary': '#1A1714',
        'text-secondary': '#5C5650',
        'severity-critical': '#B44B4B',
        'severity-high': '#C67A3C',
        'severity-medium': '#B8963E',
        'severity-low': '#8E8E8E',
        'status-normal': '#5B8A52',
        'status-suspicious': '#B8963E',
        'status-attack': '#B44B4B',
      },
      fontFamily: {
        serif: ['"Source Serif 4"', 'Georgia', 'serif'],
        heading: ['"DM Serif Display"', 'Georgia', 'serif'],
        mono: ['"IBM Plex Mono"', 'Consolas', 'monospace'],
      },
      borderRadius: {
        'DEFAULT': '0.375rem',
      },
      boxShadow: {
        'card': '0 1px 2px rgba(0,0,0,0.06)',
        'card-hover': '0 2px 8px rgba(0,0,0,0.08)',
      },
    },
  },
  plugins: [],
};
