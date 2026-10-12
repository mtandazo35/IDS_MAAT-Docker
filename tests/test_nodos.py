"""nodos.py: un nodo invalido nunca se convierte en «Todos» (CONTRATO-F2 §3.1).

Tipo: correccion de defecto (la primera version convertia cualquier id malo en TODOS) y
capacidad nueva (contexto por hilo que se restablece tambien con excepcion).
"""
import importlib
import json
import os
import sys
import tempfile
import threading
import unittest

LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")


def cargar(raiz):
    os.environ.update({"IDS_PANEL_DIR": os.path.join(raiz, "panel"),
                       "IDS_DATOS": os.path.join(raiz, "datos"),
                       "IDS_RUN": os.path.join(raiz, "run")})
    if LIB not in sys.path:
        sys.path.insert(0, LIB)
    import nodos
    return importlib.reload(nodos)


class Nodos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        for d in ("run", "datos/p001", "datos/p002", "panel"):
            os.makedirs(os.path.join(r, d))
        with open(os.path.join(r, "run", "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"puntos": {"p001": {"nombre": "norte", "redes": ["10.0.0.0/24"]},
                                  "p002": {"nombre": "sur", "redes": ["10.0.0.0/24"]}}}, f)
        for pid in ("p001", "p002"):
            open(os.path.join(r, "datos", pid, "eve.json"), "w").close()
        self.n = cargar(r)
        self.n.quitar_nodo()

    def tearDown(self):
        self.n.quitar_nodo()
        self.tmp.cleanup()

    def test_mal_formado_se_rechaza_y_no_amplia(self):
        for malo in ("", "todos", "p1", "p0001", "../p001", "p001 ", "p001\n", "p\u0661\u0662\u0663", None, 5):
            with self.assertRaises(self.n.NodoInvalido, msg=repr(malo)):
                self.n.poner_nodo(malo)
            self.assertFalse(self.n.hay_nodo())

    def test_inexistente_es_error_propio(self):
        with self.assertRaises(self.n.NodoInexistente):
            self.n.poner_nodo("p003")
        with self.assertRaises(self.n.NodoInexistente):
            self.n.nodos_de("p003")
        with self.assertRaises(self.n.NodoInexistente):
            self.n.exigir_pid("p003")

    def test_todos_solo_explicito(self):
        self.assertEqual(self.n.poner_nodo(self.n.TODOS), self.n.TODOS)
        self.assertEqual(self.n.nodos_de(), ["p001", "p002"])
        self.assertEqual(self.n.poner_nodo("p002"), "p002")
        self.assertEqual(self.n.nodos_de(), ["p002"])

    def test_sin_contexto_no_supone_nada(self):
        with self.assertRaises(self.n.SinContexto):
            self.n.nodo_actual()
        with self.assertRaises(self.n.SinContexto):
            self.n.nodos_de()

    def test_accion_nunca_va_a_todos(self):
        with self.assertRaises(self.n.NodoInvalido):
            self.n.exigir_pid(self.n.TODOS)
        with self.assertRaises(self.n.NodoInvalido):
            self.n.api_sock(self.n.TODOS)
        with self.assertRaises(self.n.NodoInvalido):
            self.n.clave("../x", "10.0.0.5")
        self.assertEqual(self.n.clave("p001", "10.0.0.5"), "p001|10.0.0.5")

    def test_contexto_se_restablece_con_excepcion(self):
        self.n.poner_nodo("p001")
        with self.assertRaises(KeyError):
            with self.n.contexto("p002"):
                self.assertEqual(self.n.nodo_actual(), "p002")
                raise KeyError("x")
        self.assertEqual(self.n.nodo_actual(), "p001")
        with self.assertRaises(self.n.NodoInexistente):
            with self.n.contexto("p009"):
                pass
        self.assertEqual(self.n.nodo_actual(), "p001")

    def test_contexto_es_por_hilo(self):
        vistos = {}
        listo = threading.Barrier(2)

        def mirar(pid):
            with self.n.contexto(pid):
                listo.wait(5)
                vistos[pid] = self.n.nodos_de()
        hs = [threading.Thread(target=mirar, args=(p,)) for p in ("p001", "p002")]
        for h in hs:
            h.start()
        for h in hs:
            h.join(5)
        self.assertEqual(vistos, {"p001": ["p001"], "p002": ["p002"]})

    def test_rutas_no_aceptan_ids_sin_validar(self):
        for f in (self.n.dir_eventos, self.n.eve_vivo, self.n.tzsp_json):
            with self.assertRaises(self.n.NodoInvalido):
                f("../../etc")
        with self.assertRaises(self.n.NodoInvalido):
            self.n.dir_salida("../x")
        self.assertTrue(self.n.dir_salida(self.n.TODOS).endswith(os.path.join("nodos", "_todos")))

    def test_no_resucita_el_directorio_de_un_punto_dado_de_baja(self):
        """Correccion de defecto (auditoria A-09): dir_salida no crea nodos/<pid> de un punto que no existe."""
        d = self.n.dir_salida("p007")
        self.assertFalse(os.path.exists(d))
        self.assertTrue(os.path.isdir(self.n.dir_salida("p001")))
        self.assertTrue(os.path.isdir(self.n.dir_salida(self.n.TODOS)))

    def test_ficheros_eventos_del_nodo(self):
        self.assertEqual([p for p, _ in self.n.ficheros_eventos("p002")], ["p002"])
        self.assertEqual(sorted(p for p, _ in self.n.ficheros_eventos(self.n.TODOS)), ["p001", "p002"])


if __name__ == "__main__":
    unittest.main()
