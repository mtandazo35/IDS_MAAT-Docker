// Tailwind del panel: se COMPILA (CLI standalone) a un unico CSS estatico que sirve el propio
// panel en /vendor/tailwind.css. No hay CDN ni JS en el navegador (CSP 'self').
//  - prefijo `tw-`: no choca con las clases propias (.card, .tab, .badge, .hidden...).
//  - preflight desactivado: el reset no debe tocar las paginas que ya tienen su CSS.
//  - colores = tokens de la capa de diseno (:root en dashboard.py, _NAV_CSS).
module.exports = {
  prefix: 'tw-',
  corePlugins: { preflight: false },
  content: ['./rootfs/usr/local/lib/ids-panel/**/*.py'],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: 'var(--ink)', 2: 'var(--ink-2)', 3: 'var(--ink-3)' },
        line: { DEFAULT: 'var(--line)', 2: 'var(--line-2)' },
        brand: { DEFAULT: 'var(--brand)', ink: 'var(--brand-ink)', soft: 'var(--brand-soft)' },
        ok: 'var(--ok)', warn: 'var(--warn)', bad: 'var(--bad)',
        surface: 'var(--surface)', canvas: 'var(--bg)',
      },
      borderRadius: { sm: 'var(--r-sm)', md: 'var(--r-md)', lg: 'var(--r-lg)' },
      boxShadow: { 1: 'var(--sh-1)', 2: 'var(--sh-2)' },
      fontFamily: { sans: 'var(--font)', mono: 'var(--mono)' },
    },
  },
};
