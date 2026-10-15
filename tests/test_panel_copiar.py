"""«Copiar» de los comandos del MikroTik (pcopiar de puntos_web.py) funciona en el panel por HTTP.

Corrección de defecto (el user, 2026-10-15): el panel va por HTTP y ahí el navegador no da
navigator.clipboard; «Copiar» decía siempre «No se pudo copiar». Ahora, fuera de un contexto seguro,
copia con textarea + execCommand('copy') en el mismo clic; si eso también falla, deja el texto
seleccionado y lo dice. Se ejecuta el JS de verdad con node y un DOM mínimo simulado (sin node se
omite).
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "images", "panel", "rootfs", "usr",
                   "local", "lib", "ids-panel")

ARNES = r"""
const JS = %s;
function correr(caso) {
  const ev = [];
  const boton = {textContent: 'Copiar'};
  const pre = {textContent: '/interface ovpn-client set [find name=ids-vpn] password=ABC disabled=no\n'};
  global.window = {isSecureContext: caso.seguro, getSelection: () => ({removeAllRanges() {},
                   addRange() { ev.push('seleccionado'); }})};
  // node >= 21 trae un `navigator` global de solo lectura: se redefine
  Object.defineProperty(globalThis, 'navigator', {configurable: true, writable: true,
    value: caso.clipboard ? {clipboard: {writeText: (t) => { ev.push('clipboard:' + t.length);
           return caso.clipboardFalla ? Promise.reject(new Error('no')) : Promise.resolve(); }}} : {}});
  global.setTimeout = () => 0;
  global.aviso = (t, m) => ev.push('aviso:' + t);
  global.document = {
    getElementById: () => pre,
    createRange: () => ({selectNodeContents() {}}),
    createElement: () => ({value: '', style: {}, setAttribute() {}, focus() {}, select() {},
                           setSelectionRange() {}}),
    body: {appendChild() { ev.push('textarea'); }, removeChild() {}},
    execCommand: (c) => { ev.push('exec:' + c); if (caso.execFalla) throw new Error('no'); return true; },
  };
  eval(JS.replace(/^<script>|<\/script>$/g, '') + ';pcopiar("x", boton);');
  return new Promise((ok) => setImmediate(() => ok({ev, boton: boton.textContent})));
}
(async () => {
  const salida = {};
  for (const [nombre, caso] of Object.entries(%s)) salida[nombre] = await correr(caso);
  process.stdout.write(JSON.stringify(salida));
})();
"""

CASOS = {
    "http": {"seguro": False, "clipboard": False},
    "http_con_clipboard": {"seguro": False, "clipboard": True},
    "https": {"seguro": True, "clipboard": True},
    "https_falla": {"seguro": True, "clipboard": True, "clipboardFalla": True},
    "nada_vale": {"seguro": False, "clipboard": False, "execFalla": True},
}


@unittest.skipUnless(shutil.which("node"), "sin node")
class Copiar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, LIB)
        try:
            import puntos_web
        finally:
            sys.path.remove(LIB)
        script = ARNES % (json.dumps(puntos_web._JS), json.dumps(CASOS))
        r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.res = json.loads(r.stdout)

    def test_por_http_copia_con_execcommand(self):
        r = self.res["http"]
        self.assertEqual(r["ev"], ["textarea", "exec:copy"])
        self.assertEqual(r["boton"], "Copiado")

    def test_por_http_no_usa_clipboard_aunque_exista(self):
        self.assertNotIn("clipboard", " ".join(self.res["http_con_clipboard"]["ev"]))
        self.assertEqual(self.res["http_con_clipboard"]["boton"], "Copiado")

    def test_por_https_usa_clipboard(self):
        r = self.res["https"]
        self.assertTrue(r["ev"][0].startswith("clipboard:"), r)
        self.assertEqual(r["boton"], "Copiado")

    def test_si_clipboard_falla_prueba_el_otro(self):
        r = self.res["https_falla"]
        self.assertIn("exec:copy", r["ev"])
        self.assertEqual(r["boton"], "Copiado")

    def test_si_nada_vale_deja_el_texto_seleccionado_y_lo_dice(self):
        r = self.res["nada_vale"]
        self.assertIn("seleccionado", r["ev"])
        self.assertIn("aviso:No se pudo copiar", r["ev"])
        self.assertEqual(r["boton"], "Copiar")


if __name__ == "__main__":
    unittest.main()
