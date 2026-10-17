"""La lista de Puntos se recarga sola cada 30 s, pero nunca con un modal abierto.

Corrección de defecto (revisión 2026-10-15, B1): la recarga respetaba la baja, el alta y el modal de
confirmar, pero no el del trabajo (pjov): la baja pedida desde la lista sigue su avance en ese modal y
la recarga se llevaba el avance y el resultado. Se ejecuta el JS de verdad (_RECARGA_LISTA de
puntos_web.py) con node y un DOM mínimo simulado (sin node se omite; se corre a mano).
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
function correr(abiertos) {
  let tic = null, recargas = 0;
  global.setInterval = (f, ms) => { tic = {f, ms}; return 1; };
  global.location = {reload: () => { recargas += 1; }};
  global.document = {getElementById: (id) => ({style: {display: abiertos.includes(id) ? 'flex' : 'none'}})};
  eval(JS.replace(/^<script>|<\/script>$/g, ''));
  tic.f();
  return {ms: tic.ms, recargas};
}
const salida = {};
for (const [nombre, abiertos] of Object.entries(%s)) salida[nombre] = correr(abiertos);
process.stdout.write(JSON.stringify(salida));
"""

CASOS = {"nada": [], "trabajo": ["pjov"], "baja": ["pbajaov"], "alta": ["paltaov"], "confirmar": ["askov"]}


@unittest.skipUnless(shutil.which("node"), "sin node")
class RecargaLista(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, LIB)
        try:
            import puntos_web
        finally:
            sys.path.remove(LIB)
        r = subprocess.run(["node", "-e", ARNES % (json.dumps(puntos_web._RECARGA_LISTA), json.dumps(CASOS))],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.res = json.loads(r.stdout)

    def test_sin_modal_abierto_recarga_cada_30_s(self):
        self.assertEqual(self.res["nada"], {"ms": 30000, "recargas": 1})

    def test_con_el_modal_del_trabajo_abierto_no_recarga(self):
        self.assertEqual(self.res["trabajo"]["recargas"], 0)

    def test_con_los_otros_modales_tampoco(self):
        for caso in ("baja", "alta", "confirmar"):
            self.assertEqual(self.res[caso]["recargas"], 0, caso)


if __name__ == "__main__":
    unittest.main()
