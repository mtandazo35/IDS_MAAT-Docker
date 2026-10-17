"""«En vivo» ya no se recarga entera cada 20 s.

Correccion de defecto (el user, 2026-10-16: «cuando actualiza como que todo palpita», «veo que hace un
refresh de toda la web»): la pagina llevaba <meta refresh> de 20 s y en cada recarga las barras de la
linea de tiempo volvian a crecer desde cero, casi siempre para pintar lo mismo (el resumen se rehace
cada 5 min). Ahora la pagina pregunta a /ventana-estado por la version del resumen y, solo si cambio,
cambia por detras los bloques de <main> que cambiaron, sin volver a animar las barras.

El JS se ejecuta de verdad con node y un DOM minimo simulado (sin node se omite esa parte).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


def escribir_reporte(p, nodo, nombre, mt, cuerpo="<section class=\"card\">hola</section>"):
    d = os.path.join(p.tmp.name, "panel", "nodos", nodo)
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, nombre)
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><html><head><style>.x{color:red}</style></head><body>"
                 "<main>%s</main></body></html>" % cuerpo)
    os.utime(f, (mt, mt))
    return f


class Pagina(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.p.cuarentena("_todos", [])          # generado con ventana_min=1440
        self.p.d.CFG["VENTANA_MIN"] = "1440"     # la elegida ya esta generada: nada pendiente
        self.ana = self.p.entrar("ana")

    def pagina(self, nodo="_todos"):
        r = self.p.pedir("GET", "/?nodo=" + nodo, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def version(self, nodo="_todos"):
        r = self.p.pedir("GET", "/ventana-estado?nodo=" + nodo, cookie=self.ana)
        self.assertEqual(r.status, 200)
        return json.loads(r.texto)["v"]

    def test_no_se_recarga_entera_y_trae_el_js_que_mira(self):
        mt = int(time.time()) - 600
        escribir_reporte(self.p, "_todos", "report-20261016-2040.html", mt)
        h = self.pagina()
        self.assertNotIn("http-equiv=refresh", h)
        self.assertNotIn("id='cd'", h)               # fuera la cuenta atras «refresca en N s»
        self.assertIn(self.p.d._JS_ENVIVO, h)
        self.assertIn(".quieto .tl-bar{animation:none}", h)

    def test_actualizado_es_la_hora_del_resumen_no_la_de_la_peticion(self):
        mt = int(time.time()) - 600                  # 10 min: no puede coincidir con «ahora»
        escribir_reporte(self.p, "_todos", "report-20261016-2040.html", mt)
        h = self.pagina()
        hora = datetime.fromtimestamp(mt, self.p.d.TZ_EC).strftime("%d/%m/%Y %H:%M")
        ahora = datetime.now(self.p.d.TZ_EC).strftime("%d/%m/%Y %H:%M")
        self.assertNotEqual(hora, ahora)
        m = re.search(r"<span id='hact' data-v='([^']*)'>([^<]*)</span>", h)
        self.assertIsNotNone(m, h[:2000])
        self.assertEqual(m.group(2), hora)
        self.assertEqual(m.group(1), "report-20261016-2040.html@%d" % mt)

    def test_la_version_cambia_solo_con_un_resumen_nuevo_y_es_por_nodo(self):
        mt = int(time.time()) - 600
        escribir_reporte(self.p, "_todos", "report-20261016-2040.html", mt)
        v1 = self.version()
        self.assertEqual(v1, "report-20261016-2040.html@%d" % mt)
        self.assertEqual(self.version(), v1)          # sin resumen nuevo, la misma
        escribir_reporte(self.p, "_todos", "report-20261016-2045.html", mt + 300)
        v2 = self.version()
        self.assertEqual(v2, "report-20261016-2045.html@%d" % (mt + 300))
        # la pagina dice la misma version que /ventana-estado: si no, pediria la pagina cada 20 s
        self.assertIn("data-v='%s'" % v2, self.pagina())
        # cada punto tiene la suya
        self.assertEqual(self.version("p001"), "")
        escribir_reporte(self.p, "p001", "report-20261016-2041.html", mt + 60)
        self.assertEqual(self.version("p001"), "report-20261016-2041.html@%d" % (mt + 60))
        self.assertEqual(self.version(), v2)

    def test_sin_resumen_todavia_version_vacia(self):
        self.assertEqual(self.version(), "")
        h = self.pagina()
        self.assertIn("<span id='hact' data-v=''>", h)
        self.assertIn(self.p.d._JS_ENVIVO, h)         # en cuanto salga, la pagina se recarga


# ---- el JS de verdad, con node ---------------------------------------------------------------
ARNES = r"""
const JS = %s;
const TOPO = 'http://panel/vendor/mapa/topojson-client.min.js';
let nid = 0;
function nodo(tag, html, extra) {
  const n = Object.assign({id: ++nid, tagName: tag, outerHTML: html, children: [], parentNode: null,
    attrs: {}, src: '', text: '', textContent: '', fresco: false}, extra || {});
  n.getAttribute = (k) => (k in n.attrs ? n.attrs[k] : null);
  n.setAttribute = (k, v) => { n.attrs[k] = String(v); };
  n.querySelectorAll = () => { const out = [];
    (function w(x) { for (const c of x.children) { if (c.tagName === 'SCRIPT') out.push(c); w(c); } })(n);
    return out; };
  return n;
}
// un bloque de <main>: {h: outerHTML, s: [{t: texto} | {src: url}]}, o un <script> suelto con su t
function bloque(b) {
  const n = b.h.startsWith('<script') ? nodo('SCRIPT', b.h, {text: b.t || '', textContent: b.t || ''})
                                      : nodo('SECTION', b.h);
  for (const s of b.s || []) {
    const sc = nodo('SCRIPT', '<script>', {src: s.src || '', text: s.t || '', textContent: s.t || ''});
    sc.parentNode = n; n.children.push(sc);
  }
  return n;
}
function clonar(n) {
  const c = nodo(n.tagName, n.outerHTML, {src: n.src, text: n.text, textContent: n.textContent});
  for (const h of n.children) { const k = clonar(h); k.parentNode = c; c.children.push(k); }
  return c;
}
async function correr(caso) {
  const ev = [], timers = [], TOK = {};
  let recargada = false;
  function ejecuta(x) { if (x.fresco) ev.push('corre:' + (x.src || x.text)); }
  function conHijos(n) {
    n.replaceChild = (nu, viejo) => { const i = n.children.indexOf(viejo); n.children[i] = nu;
      nu.parentNode = n; viejo.parentNode = null; if (nu.tagName === 'SCRIPT') ejecuta(nu);
      else nu.querySelectorAll().forEach(ejecuta); };
    for (const c of n.children) { c.parentNode = n; if (!c.replaceChild) conHijos(c); }
    return n;
  }
  const main = conHijos(nodo('MAIN', '<main>'));
  main.children = caso.inicio.map(bloque);
  conHijos(main);
  Object.defineProperty(main, 'innerHTML', {set(t) { main.children = TOK[t].map(clonar); conHijos(main); }});
  const ids0 = main.children.map((c) => c.id);
  const hact = nodo('SPAN', '<span>', {textContent: '16/10/2026 20:40'});
  hact.attrs['data-v'] = caso.v;
  const estados = caso.estados.slice(), paginas = (caso.paginas || []).slice();
  global.window = {};
  global.location = {pathname: '/', search: '?nodo=_todos',
                     reload() { ev.push('reload'); recargada = true; }};
  global.setTimeout = (f, ms) => { timers.push({f, ms}); return timers.length; };
  global.clearTimeout = () => {};
  global.document = {
    hidden: !!caso.oculta,
    scripts: [{src: TOPO}, {src: ''}],
    documentElement: {classList: {add(c) { ev.push('clase:' + c); }}},
    getElementById: (id) => (id === 'hact' ? hact : null),
    querySelector: (s) => (s === 'main' ? main : (s === '.wsel' ? (caso.admin ? {} : null) : null)),
    createElement: (t) => nodo('SCRIPT', '<script>', {fresco: true}),
    importNode: (n) => conHijos(clonar(n)),
  };
  function resp(cuerpo, extra) {
    return Object.assign({ok: true, redirected: false, json: () => Promise.resolve(cuerpo),
                          text: () => Promise.resolve(cuerpo)}, extra || {});
  }
  global.fetch = (u, o) => {
    const ruta = u.split('?')[0];
    ev.push('fetch:' + ruta);
    if (ruta === '/ventana-estado') {
      const e = estados.shift();
      if (e === 'falla' || e === undefined) return Promise.reject(new Error('red'));
      if (e === 'redir') return Promise.resolve(resp('<html>login</html>', {redirected: true}));
      return Promise.resolve(resp(e));
    }
    const pg = paginas.shift();
    if (!pg) return Promise.reject(new Error('sin pagina'));
    const k = 'pg' + Object.keys(TOK).length;
    TOK['tok-' + k] = pg.hijos ? pg.hijos.map(bloque) : [];
    return Promise.resolve(resp(k));
  };
  global.DOMParser = function () {
    this.parseFromString = (k) => {
      const pg = TOK['tok-' + k], meta = caso.paginasMeta[k] || {};
      const nm = {children: pg, innerHTML: 'tok-' + k};
      const h = nodo('SPAN', '<span>', {textContent: meta.hora || ''});
      h.attrs['data-v'] = meta.v || '';
      return {querySelector: (s) => (s === 'main' && !meta.sinMain ? nm : null),
              getElementById: (id) => (id === 'hact' && !meta.sinHact ? h : null)};
    };
  };
  eval(JS.replace(/^<script>|<\/script>$/g, ''));
  for (let i = 0; i < caso.vueltas && !recargada; i++) {
    const t = timers.findIndex((x) => x.ms === 20000);
    if (t < 0) break;
    const [{f}] = timers.splice(t, 1);
    f();
    await new Promise((ok) => setImmediate(ok));
  }
  return {ev, hijos: main.children.map((c) => c.outerHTML),
          iguales: main.children.map((c, i) => c.id === ids0[i]),
          hora: hact.textContent, v: hact.attrs['data-v'],
          pendientes: timers.filter((x) => x.ms === 20000).length};
}
(async () => {
  const salida = {};
  for (const [nombre, caso] of Object.entries(%s)) salida[nombre] = await correr(caso);
  process.stdout.write(JSON.stringify(salida));
})();
"""

INICIO = [{"h": "<div class=tiles>10</div>"},
          {"h": "<section>tl A</section>", "s": [{"t": "tlA"}]},
          {"h": "<section>mapa A</section>", "s": [{"t": "datosA"},
                                                   {"src": "http://panel/vendor/mapa/topojson-client.min.js"},
                                                   {"t": "mapaA"}]},
          {"h": "<script>ask</script>", "t": "ask"}]
TL_B = {"h": "<section>tl B</section>", "s": [{"t": "tlB"}]}
MAPA_B = {"h": "<section>mapa B</section>", "s": [{"t": "datosB"},
                                                 {"src": "http://panel/vendor/mapa/topojson-client.min.js"},
                                                 {"t": "mapaB"}]}


def caso(estados, v="A", paginas=(), meta=None, vueltas=None, **kw):
    c = {"inicio": INICIO, "v": v, "estados": list(estados), "paginas": list(paginas),
         "paginasMeta": meta or {}, "vueltas": vueltas or len(estados)}
    c.update(kw)
    return c


CASOS = {
    "igual": caso([{"v": "A"}, {"v": "A"}]),
    "cambia_un_bloque": caso([{"v": "B"}, {"v": "B"}],
                             paginas=[{"hijos": [INICIO[0], TL_B, INICIO[2], INICIO[3]]}],
                             meta={"pg0": {"v": "B", "hora": "16/10/2026 20:45"}}),
    "cambia_el_mapa": caso([{"v": "B"}], paginas=[{"hijos": [INICIO[0], INICIO[1], MAPA_B, INICIO[3]]}],
                           meta={"pg0": {"v": "B", "hora": "16/10/2026 20:45"}}),
    "cambia_la_forma": caso([{"v": "B"}],
                            paginas=[{"hijos": [INICIO[0], TL_B, {"h": "<section>nuevo</section>"},
                                                MAPA_B, INICIO[3]]}],
                            meta={"pg0": {"v": "B", "hora": "16/10/2026 20:45"}}),
    "pendiente_admin": caso([{"v": "A", "pendiente": True}], admin=True),
    "pendiente_lector": caso([{"v": "A", "pendiente": True}, {"v": "A", "pendiente": True}]),
    "sin_resumen_y_sale": caso([{"v": "B"}], v=""),
    "resumen_desaparece": caso([{"v": ""}]),
    "tres_fallos": caso(["falla", "falla", "falla"]),
    "dos_fallos_y_bien": caso(["falla", "falla", {"v": "A"}, "falla", "falla"]),
    "sesion_caducada": caso(["redir", "redir", "redir"]),
    "pestana_oculta": caso([{"v": "B"}], oculta=True),
    "pagina_sin_main": caso([{"v": "B"}], paginas=[{"hijos": []}], meta={"pg0": {"v": "B", "sinMain": True}}),
}


@unittest.skipUnless(shutil.which("node"), "sin node")
class JS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = PanelP()
        try:
            js = p.d._JS_ENVIVO
        finally:
            p.cerrar()
        r = subprocess.run(["node", "-e", ARNES % (json.dumps(js), json.dumps(CASOS))],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.res = json.loads(r.stdout)

    def pedidas(self, r):
        return [e for e in r["ev"] if e.startswith("fetch:")]

    def test_sin_resumen_nuevo_no_pide_la_pagina_ni_recarga(self):
        r = self.res["igual"]
        self.assertEqual(self.pedidas(r), ["fetch:/ventana-estado"] * 2)
        self.assertNotIn("reload", r["ev"])
        self.assertNotIn("clase:quieto", r["ev"])
        self.assertEqual(r["iguales"], [True] * 4)
        self.assertEqual(r["pendientes"], 1)         # sigue mirando

    def test_resumen_nuevo_cambia_solo_el_bloque_que_cambio_sin_animar(self):
        r = self.res["cambia_un_bloque"]
        self.assertEqual(self.pedidas(r), ["fetch:/ventana-estado", "fetch:/", "fetch:/ventana-estado"])
        self.assertNotIn("reload", r["ev"])
        self.assertIn("clase:quieto", r["ev"])        # las barras no vuelven a crecer desde cero
        self.assertEqual(r["hijos"][1], "<section>tl B</section>")
        self.assertEqual(r["iguales"], [True, False, True, True])   # el resto, intacto
        self.assertEqual([e for e in r["ev"] if e.startswith("corre:")], ["corre:tlB"])
        self.assertEqual((r["hora"], r["v"]), ("16/10/2026 20:45", "B"))
        self.assertEqual(r["pendientes"], 1)

    def test_el_mapa_se_redibuja_sin_volver_a_pedir_topojson(self):
        r = self.res["cambia_el_mapa"]
        self.assertEqual([e for e in r["ev"] if e.startswith("corre:")], ["corre:datosB", "corre:mapaB"])
        self.assertEqual(r["iguales"], [True, True, False, True])

    def test_si_cambia_la_forma_cambia_todo_main_y_corre_sus_scripts(self):
        r = self.res["cambia_la_forma"]
        self.assertNotIn("reload", r["ev"])
        self.assertEqual(len(r["hijos"]), 5)
        self.assertEqual(r["iguales"], [False] * 4 + [False])
        self.assertEqual([e for e in r["ev"] if e.startswith("corre:")],
                         ["corre:tlB", "corre:datosB", "corre:mapaB", "corre:ask"])

    def test_admin_con_otra_ventana_generandose_recarga_una_vez(self):
        self.assertIn("reload", self.res["pendiente_admin"]["ev"])

    def test_lector_no_entra_en_bucle_de_recargas(self):
        # el lector no ve el «generando…» (es del selector de admin): recargar no cambiaria nada
        self.assertNotIn("reload", self.res["pendiente_lector"]["ev"])

    def test_sin_resumen_al_cargar_recarga_cuando_sale(self):
        r = self.res["sin_resumen_y_sale"]
        self.assertIn("reload", r["ev"])
        self.assertNotIn("fetch:/", r["ev"])

    def test_si_el_resumen_desaparece_recarga(self):
        self.assertIn("reload", self.res["resumen_desaparece"]["ev"])

    def test_tres_fallos_seguidos_recarga_y_dos_no(self):
        self.assertIn("reload", self.res["tres_fallos"]["ev"])
        r = self.res["dos_fallos_y_bien"]
        self.assertNotIn("reload", r["ev"])
        self.assertEqual(r["pendientes"], 1)

    def test_sesion_caducada_acaba_en_recarga(self):
        self.assertIn("reload", self.res["sesion_caducada"]["ev"])

    def test_pestana_oculta_no_pregunta(self):
        r = self.res["pestana_oculta"]
        self.assertEqual(self.pedidas(r), [])
        self.assertEqual(r["pendientes"], 1)

    def test_respuesta_sin_main_recarga_en_vez_de_dejar_la_pagina_a_medias(self):
        r = self.res["pagina_sin_main"]
        self.assertIn("reload", r["ev"])
        self.assertEqual(r["iguales"], [True] * 4)


if __name__ == "__main__":
    unittest.main()
