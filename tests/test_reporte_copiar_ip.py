"""Reporte: clic en una IP la copia (el user, 2026-11-22).

En «Abonados con más actividad sospechosa» y en las tablas de cada categoría la IP lleva
data-copiar; un clic la copia y muestra «Copiado» un momento. El panel va por HTTP: ahí no hay
navigator.clipboard y se copia con textarea + execCommand; si eso falla, la IP queda seleccionada y
el modal (aviso) pide Ctrl+C. Se ejecuta el JS de verdad con node y un DOM mínimo (sin node se omite).
"""
import ast
import json
import os
import shutil
import subprocess
import unittest

DASH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "images", "panel", "rootfs", "usr",
                    "local", "lib", "ids-panel", "dashboard.py")


def _arbol():
    with open(DASH, encoding="utf-8") as f:
        return ast.parse(f.read())


def _cd_js(arbol):
    for n in arbol.body:
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "_CD_JS" for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError("no está _CD_JS")


def _funcion(arbol, nombre):
    for n in arbol.body:
        if isinstance(n, ast.FunctionDef) and n.name == nombre:
            return n
    raise AssertionError("no está " + nombre)


ARNES = r"""
const JS = %s;
const handlers = [];
function correr(caso) {
  const ev = [];
  const timers = [];
  const clases = new Set();
  const ip = {textContent: '192.0.2.44', dataset: {}, classList: {add: (c) => clases.add(c),
              remove: (c) => clases.delete(c)},
              getAttribute: (a) => (a === 'data-copiar' ? caso.valor : null)};
  // closest solo encuentra la IP con el selector de verdad: si el JS cambiara de selector, no copia
  const objetivo = {closest: (s) => (!caso.fuera && s === '[data-copiar]' ? ip : null)};
  global.window = {isSecureContext: caso.seguro, getSelection: () => ({removeAllRanges() {},
                   addRange() { ev.push('seleccionado'); }})};
  Object.defineProperty(globalThis, 'navigator', {configurable: true, writable: true,
    value: caso.clipboard ? {clipboard: {writeText: (t) => { ev.push('clipboard:' + t);
           return caso.clipboardFalla ? Promise.reject(new Error('no')) : Promise.resolve(); }}} : {}});
  // temporizadores de verdad cancelables: el doble clic depende de clearTimeout
  global.setTimeout = (f) => { timers.push(f); return timers.length; };
  global.clearTimeout = (id) => { if (id) timers[id - 1] = null; };
  global.aviso = (t, m) => ev.push('aviso:' + t);
  global.document.createRange = () => ({selectNodeContents() {}});
  global.document.createElement = () => ({value: '', style: {}, setAttribute() {}, focus() {}, select() {},
                                          setSelectionRange() {}});
  global.document.body = {appendChild(a) { ev.push('textarea:' + a.value); }, removeChild() {}};
  global.document.execCommand = (c) => { ev.push('exec:' + c); if (caso.execFalla) throw new Error('no');
                                         return !caso.execFalse; };
  // doble clic: el segundo llega con «Copiado» en pantalla y tiene que copiar la IP, no esa palabra
  for (let i = 0; i < (caso.clics || 1); i++) handlers.forEach((h) => h({target: objetivo}));
  return new Promise((ok) => setImmediate(() => {
    const durante = ip.textContent, verde = clases.has('copiado');
    timers.forEach((f) => f && f());
    ok({ev, durante, verde, despues: ip.textContent, verde_despues: clases.has('copiado')});
  }));
}
global.window = {addEventListener() {}};
global.document = {addEventListener: (t, h) => { if (t === 'click') handlers.push(h); },
                   querySelectorAll: () => []};
eval(JS.replace(/^<script>|<\/script>$/g, ''));
(async () => {
  const salida = {};
  for (const [nombre, caso] of Object.entries(%s)) salida[nombre] = await correr(caso);
  process.stdout.write(JSON.stringify(salida));
})();
"""

CASOS = {
    "http": {"seguro": False, "clipboard": False, "valor": "192.0.2.44"},
    "http_con_clipboard": {"seguro": False, "clipboard": True, "valor": "192.0.2.44"},
    "https": {"seguro": True, "clipboard": True, "valor": "192.0.2.44"},
    "https_falla": {"seguro": True, "clipboard": True, "clipboardFalla": True, "valor": "192.0.2.44"},
    "nada_vale": {"seguro": False, "clipboard": False, "execFalla": True, "valor": "192.0.2.44"},
    "fuera": {"seguro": False, "clipboard": False, "fuera": True, "valor": "192.0.2.44"},
    "exec_false": {"seguro": False, "clipboard": False, "execFalse": True, "valor": "192.0.2.44"},
    "doble_clic": {"seguro": False, "clipboard": False, "clics": 2, "valor": "192.0.2.44"},
}


class Marcado(unittest.TestCase):
    """Las dos listas del reporte marcan la IP para copiar, escapada."""

    @classmethod
    def setUpClass(cls):
        cls.arbol = _arbol()

    def _ejecutar(self, nombre, entorno):
        mod = ast.Module(body=[_funcion(self.arbol, nombre)], type_ignores=[])
        exec(compile(mod, DASH, "exec"), entorno)
        return entorno[nombre]

    def test_barras_llevan_data_copiar(self):
        import html
        barras = self._ejecutar("conducta_barras", {
            "html": html, "nombre_categoria": lambda c: c,
            "nodos": type("N", (), {"nombre": staticmethod(lambda x: x)})})
        out = barras([{"ip": "192.0.2.44", "alertas": 91, "nodo": "p001", "_cat": "botnet"},
                      {"ip": "<x>'\"", "alertas": 3}], "Abonados")
        # el globo conserva lo de la fila (IP, alertas, tipo) y dice que se copia
        self.assertIn("<span class=lip data-copiar='192.0.2.44' title='192.0.2.44: 91 alertas, botnet. "
                      "Clic para copiar la IP'>192.0.2.44</span>", out)
        # las comillas no cierran el atributo
        self.assertIn("data-copiar='&lt;x&gt;&#x27;&quot;'", out)
        self.assertNotIn("<x>", out)

    def test_copiado_no_mueve_la_tabla_ni_se_selecciona(self):
        with open(DASH, encoding="utf-8") as f:
            src = f.read()
        self.assertIn(".cdt td.ip[data-copiar]{min-width:16ch}", src)
        self.assertIn("[data-copiar].copiado{color:#1a7f37 !important;text-decoration:none;user-select:none", src)

    def test_tabla_de_categoria_lleva_data_copiar(self):
        with open(DASH, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("<td class=ip data-copiar='%s' title='Clic para copiar la IP'>%s</td>", src)
        self.assertIn('% (esc(f["ip"]), esc(f["ip"]),', src)

    def test_documentado_en_el_panel(self):
        with open(DASH, encoding="utf-8") as f:
            self.assertIn("Para <b>copiar una IP</b> basta con hacer clic sobre ella", f.read())


@unittest.skipUnless(shutil.which("node"), "sin node")
class Copiar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        js = _cd_js(_arbol())
        script = ARNES % (json.dumps(js), json.dumps(CASOS))
        r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.res = json.loads(r.stdout)

    def test_por_http_copia_la_ip_con_execcommand(self):
        r = self.res["http"]
        self.assertEqual(r["ev"], ["textarea:192.0.2.44", "exec:copy"])
        self.assertEqual((r["durante"], r["verde"]), ("Copiado", True))

    def test_vuelve_a_mostrar_la_ip(self):
        r = self.res["http"]
        self.assertEqual((r["despues"], r["verde_despues"]), ("192.0.2.44", False))

    def test_por_http_no_usa_clipboard_aunque_exista(self):
        self.assertNotIn("clipboard", " ".join(self.res["http_con_clipboard"]["ev"]))

    def test_por_https_usa_clipboard(self):
        r = self.res["https"]
        self.assertEqual(r["ev"], ["clipboard:192.0.2.44"])
        self.assertEqual(r["durante"], "Copiado")

    def test_si_clipboard_falla_prueba_el_otro(self):
        r = self.res["https_falla"]
        self.assertIn("exec:copy", r["ev"])
        self.assertEqual(r["durante"], "Copiado")

    def test_si_nada_vale_selecciona_y_avisa_con_modal(self):
        r = self.res["nada_vale"]
        self.assertIn("seleccionado", r["ev"])
        self.assertIn("aviso:No se pudo copiar", r["ev"])
        self.assertEqual(r["durante"], "192.0.2.44")

    def test_si_execcommand_devuelve_false_selecciona_y_avisa(self):
        r = self.res["exec_false"]
        self.assertIn("seleccionado", r["ev"])
        self.assertIn("aviso:No se pudo copiar", r["ev"])

    def test_doble_clic_copia_la_ip_las_dos_veces_y_la_restaura(self):
        r = self.res["doble_clic"]
        self.assertEqual(r["ev"], ["textarea:192.0.2.44", "exec:copy"] * 2)
        self.assertEqual((r["durante"], r["despues"]), ("Copiado", "192.0.2.44"))

    def test_clic_fuera_de_una_ip_no_copia(self):
        self.assertEqual(self.res["fuera"]["ev"], [])


if __name__ == "__main__":
    unittest.main()
