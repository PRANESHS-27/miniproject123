/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Brand — single accent for the whole product. Royal blue reads as
        // "trustworthy security" without being so dark it disappears on
        // a busy dashboard. We lift contrast in dark mode.
        brand: {
          50:  'rgb(var(--brand-50, 239 246 255) / <alpha-value>)',
          100: 'rgb(var(--brand-100, 219 234 254) / <alpha-value>)',
          200: 'rgb(var(--brand-200, 191 219 254) / <alpha-value>)',
          300: 'rgb(var(--brand-300, 147 197 253) / <alpha-value>)',
          400: 'rgb(var(--brand-400, 96 165 250) / <alpha-value>)',
          500: 'rgb(var(--brand-500, 59 130 246) / <alpha-value>)',
          600: 'rgb(var(--brand-600, 37 99 235) / <alpha-value>)',
          700: 'rgb(var(--brand-700, 29 78 216) / <alpha-value>)',
          800: 'rgb(var(--brand-800, 30 64 175) / <alpha-value>)',
          900: 'rgb(var(--brand-900, 30 58 138) / <alpha-value>)',
          950: 'rgb(var(--brand-950, 23 37 84) / <alpha-value>)',
        },
        // Workhorse neutral — used for page surfaces, table headers, and
        // borders so the UI doesn't feel like five different greys.
        slate: {
          50:  '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617',
        },
        // Semantic palette for severity & status pills.
        success: {
          50: '#ecfdf5', 100: '#d1fae5', 200: '#a7f3d0', 300: '#6ee7b7',
          400: '#34d399', 500: '#10b981', 600: '#059669', 700: '#047857',
          800: '#065f46', 900: '#064e3b',
        },
        warning: {
          50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d',
          400: '#fbbf24', 500: '#f59e0b', 600: '#d97706', 700: '#b45309',
          800: '#92400e', 900: '#78350f',
        },
        danger: {
          50: '#fef2f2', 100: '#fee2e2', 200: '#fecaca', 300: '#fca5a5',
          400: '#f87171', 500: '#ef4444', 600: '#dc2626', 700: '#b91c1c',
          800: '#991b1b', 900: '#7f1d1d',
        },
        info: {
          50: '#f0f9ff', 100: '#e0f2fe', 200: '#bae6fd', 300: '#7dd3fc',
          400: '#38bdf8', 500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1',
          800: '#075985', 900: '#0c4a6e',
        },
        // Legacy aliases — kept so existing utility classes that referenced
        // ink-* continue to work. The new build prefers `slate-*`.
        ink: {
          DEFAULT: '#0f172a',
          50: '#f8fafc', 100: '#f1f5f9', 200: '#e2e8f0', 300: '#cbd5e1',
          400: '#94a3b8', 500: '#64748b', 600: '#475569', 700: '#334155',
          800: '#1e293b', 900: '#0f172a',
        },
        accent: {
          DEFAULT: '#06b6d4',
          50: '#ecfeff', 100: '#cffafe', 200: '#a5f3fc', 300: '#67e8f9',
          400: '#22d3ee', 500: '#06b6d4', 600: '#0891b2', 700: '#0e7490',
        },
      },
      fontFamily: {
        sans: [
          'Inter var', 'Inter', 'ui-sans-serif', 'system-ui',
          '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'sans-serif',
        ],
        mono: [
          'JetBrains Mono', 'ui-monospace', 'SFMono-Regular',
          'Menlo', 'Consolas', 'monospace',
        ],
      },
      boxShadow: {
        'card': '0 1px 2px 0 rgba(15, 23, 42, 0.04), 0 1px 3px 0 rgba(15, 23, 42, 0.06)',
        'card-hover': '0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 10px 15px -3px rgba(15, 23, 42, 0.08)',
        'pop': '0 12px 32px -8px rgba(15, 23, 42, 0.18), 0 0 0 1px rgba(15, 23, 42, 0.04)',
        'inner-glow': 'inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      },
      borderRadius: {
        'xl': '0.875rem',
        '2xl': '1.125rem',
      },
      // Custom half-step sizes (Tailwind only ships 0.5 increments by default).
      // Used for the small 18px icons throughout the app.
      width:  { '4.5': '1.125rem' },
      height: { '4.5': '1.125rem' },
      animation: {
        'fade-in': 'fadeIn 200ms ease-out',
        'slide-up': 'slideUp 220ms cubic-bezier(0.16, 1, 0.3, 1)',
        'shimmer': 'shimmer 1.6s linear infinite',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
        slideUp: {
          '0%': { opacity: 0, transform: 'translateY(8px)' },
          '100%': { opacity: 1, transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-1000px 0' },
          '100%': { backgroundPosition: '1000px 0' },
        },
      },
    },
  },
  plugins: [],
}
