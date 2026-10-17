"""El modal de las operaciones del punto distingue la sesión caducada de un fallo de red.

Corrección de defecto (revisión 2026-10-15, B8): con la sesión caducada, el servidor redirige a /login,
fetch() sigue la redirección y recibe la página de entrada; r.json() fallaba y el modal se quedaba para
siempre en «sin respuesta del panel; se reintenta en 5 s» (o «No se pudo hablar con el panel»). Ahora
pjSeguir termina con «La sesión caducó: vuelve a entrar» y pjPost lo dice; un fallo de red o un 500
siguen reintentando como antes. Se ejecuta el JS de verdad (_JS_TRABAJOS de puntos_web.py) con node y un
fetch simulado (sin node se omite; se corre a mano).
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
global.document = {getElementById: () => null, addEventListener() {}};
global.FormData = function () { return []; };
global.setTimeout = () => 0;                 // sin reintentos de verdad: se mira el primer paso
eval(JS.replace(/^<script>|<\/script>$/g, ''));
function resp(tipo, cuerpo) {
  if (tipo === 'red') return Promise.reject(new TypeError('Failed to fetch'));
  const login = tipo === 'login';             // /login tras la redirección: HTML, no JSON
  return Promise.resolve({
    ok: tipo !== 'error500', status: tipo === 'error500' ? 500 : 200, redirected: login,
    headers: {get: () => (login || tipo === 'error500') ? 'text/html; charset=utf-8'
                                                        : 'application/json; charset=utf-8'},
    json: () => login ? Promise.reject(new SyntaxError('Unexpected token <'))
                      : Promise.resolve(cuerpo || {}),
  });
}
const tic = () => new Promise((ok) => setImmediate(ok));
async function seguir(tipo, cuerpo) {
  const ev = {pinta: [], fin: []};
  global.fetch = () => resp(tipo, cuerpo);
  pjSeguir('op1', (j) => ev.pinta.push(j), (j) => ev.fin.push(j));
  await tic();
  return ev;
}
async function post(tipo, cuerpo) {
  const ev = {ok: [], mal: []};
  global.fetch = () => resp(tipo, cuerpo);
  pjPost({getAttribute: () => '/puntos/p001/api', elements: {}}, {}, (j) => ev.ok.push(j),
         (m) => ev.mal.push(m));
  await tic();
  return ev;
}
(async () => {
  const s = {};
  s.seguir_login = await seguir('login');
  s.seguir_red = await seguir('red');
  s.seguir_500 = await seguir('error500');
  s.seguir_fin = await seguir('json', {terminada: true, ok: true, mensaje: 'hecho'});
  s.post_login = await post('login');
  s.post_red = await post('red');
  s.post_json = await post('json', {ok: true, mensaje: 'guardado'});
  process.stdout.write(JSON.stringify(s));
})();
"""


@unittest.skipUnless(shutil.which("node"), "sin node")
class SesionCaducada(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, LIB)
        try:
            import puntos_web
        finally:
            sys.path.remove(LIB)
        r = subprocess.run(["node", "-e", ARNES % json.dumps(puntos_web._JS_TRABAJOS)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.res = json.loads(r.stdout)

    def test_seguir_con_la_sesion_caducada_termina_y_lo_dice(self):
        r = self.res["seguir_login"]
        self.assertEqual(r["pinta"], [])
        self.assertEqual(len(r["fin"]), 1)
        self.assertFalse(r["fin"][0]["ok"])
        self.assertIn("La sesión caducó: vuelve a entrar", r["fin"][0]["mensaje"])
        self.assertIn("sigue en el servidor", r["fin"][0]["mensaje"])

    def test_seguir_sin_red_o_con_un_500_sigue_reintentando(self):
        for caso in ("seguir_red", "seguir_500"):
            r = self.res[caso]
            self.assertEqual(r["fin"], [], caso)
            self.assertTrue(r["pinta"][0]["etapa"].startswith("sin respuesta del panel"), caso)

    def test_seguir_con_la_operacion_terminada_la_entrega(self):
        self.assertEqual(self.res["seguir_fin"]["fin"][0]["mensaje"], "hecho")

    def test_post_con_la_sesion_caducada_lo_dice(self):
        self.assertEqual(self.res["post_login"]["mal"], ["La sesión caducó: vuelve a entrar."])
        self.assertEqual(self.res["post_login"]["ok"], [])

    def test_post_sin_red_dice_lo_de_siempre_y_con_json_sigue(self):
        self.assertTrue(self.res["post_red"]["mal"][0].startswith("No se pudo hablar con el panel"))
        self.assertEqual(self.res["post_json"]["ok"][0]["mensaje"], "guardado")


if __name__ == "__main__":
    unittest.main()
