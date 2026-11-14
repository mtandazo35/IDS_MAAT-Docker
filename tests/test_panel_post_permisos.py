"""Toda ruta POST del panel exige permiso (QA T-08, 2026-11-14).

Las rutas POST de H._post llevan su comprobación de permiso escrita a mano, una por una, y las
pruebas las listaban también a mano: una ruta nueva sin `_puede` pasaba sin que nada lo dijera. Esta
prueba saca las rutas del propio código (AST de H._post) y exige que un usuario con un único permiso
inofensivo («En vivo», resumen.ver) reciba 403 o 404 en todas, salvo las de EXCEPCIONES, cada una con
su motivo. Las de /puntos/... las cubren las pruebas de Puntos (puntos_web.post, con su tabla
PERMISO_ACCION).
"""
import ast
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
A = importlib.import_module("test_panel_alcance")

DASH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "images", "panel", "rootfs",
                    "usr", "local", "lib", "ids-panel", "dashboard.py")

# ruta -> por qué un usuario sin permisos puede llegar a ella sin un 403
EXCEPCIONES = {
    "/login": "es la entrada: no hay sesión todavía",
}


def rutas_post():
    """Las rutas literales que compara H._post (`ruta == "..."` o `ruta in (...)`)."""
    with open(DASH, encoding="utf-8") as f:
        arbol = ast.parse(f.read())
    h = next(n for n in arbol.body if isinstance(n, ast.ClassDef) and n.name == "H")
    post = next(n for n in h.body if isinstance(n, ast.FunctionDef) and n.name == "_post")
    out = []
    for n in ast.walk(post):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id == "ruta":
            for c in n.comparators:
                vals = [c] if isinstance(c, ast.Constant) else getattr(c, "elts", [])
                for v in vals:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value not in out:
                        out.append(v.value)
    return out


class TodaRutaPostConPermiso(A.Base):
    def test_se_encuentran_las_rutas(self):
        """Conservación: el AST encuentra las rutas (si cambia la forma del manejador, que falle aquí)."""
        r = rutas_post()
        self.assertGreaterEqual(len(r), 40, r)
        for ruta in ("/exclusiones", "/cuarentena/enviar", "/perfil", "/mikrotik/reglas/aplicar"):
            self.assertIn(ruta, r)

    def test_sin_permiso_403_en_todas(self):
        """Corrección de defecto evitado: con solo «En vivo», ninguna ruta POST responde como si
        pudiera (200/303); las excepciones van con su motivo en EXCEPCIONES."""
        us = self.d.cargar_usuarios()
        for r in us:
            if r["user"] == "luis":
                r["permisos"] = ["resumen.ver"]
        self.d.guardar_usuarios(us)
        malas = []
        for ruta in rutas_post():
            if ruta in EXCEPCIONES:
                continue
            st = self.post(ruta, {"accion": "x", "ip": "p001|10.0.0.5", "nodo": "p001"}, "luis").status
            if st not in (403, 404):
                malas.append((ruta, st))
        self.assertEqual(malas, [], "rutas POST que no exigen permiso a quien no lo tiene")

    def test_el_administrador_si_llega(self):
        """Conservación (que la prueba de arriba no sea vacía): con todos los permisos, las mismas
        peticiones NO se rechazan por permiso en casi ninguna ruta; si todo diera 403 por otra causa
        (origen, sesión), la de arriba pasaría sin probar nada."""
        prohibidas = [ruta for ruta in rutas_post() if ruta not in EXCEPCIONES
                      and self.post(ruta, {"accion": "x", "ip": "p001|10.0.0.5", "nodo": "p001"},
                                    "ana").status == 403]
        self.assertLessEqual(len(prohibidas), 3, prohibidas)


if __name__ == "__main__":
    unittest.main()
