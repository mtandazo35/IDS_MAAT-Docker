"""La e2e no corre en un servidor con el IDS instalado (el user, 2026-10-15).

tests/integracion/test_e2e.sh monta un IDS en un IDS_RAIZ temporal, pero sus proyectos de compose,
contenedores y redes se llaman igual que los de verdad (ids-core, ids-p001...): `punto crear` pisaba el
p001 real y, al salir, limpiar() borraba todo lo que llevara la etiqueta ids-maat.punto, ids-core-panel
y esas redes. Se prueba con un docker, un systemctl, un uname y un id de mentira en el PATH (la e2e de
verdad no llega a arrancar): en un servidor instalado sale con 77 sin una sola orden que cree o borre, y
en una maquina vacia pasa la guarda. Tipo de cada prueba en su docstring.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E2E = os.path.join(REPO, "tests", "integracion", "test_e2e.sh")

FALSOS = {
    "uname": "#!/bin/sh\necho Linux\n",
    "id": "#!/bin/sh\necho 0\n",
    "systemctl": '#!/bin/sh\n[ "${FALSO_ORQ_ACTIVO:-0}" = 1 ] && exit 0\nexit 3\n',
    # apunta cada orden; responde lo que diga el entorno de la prueba
    "docker": """#!/bin/bash
echo "$*" >> "$DOCKER_LOG"
case "$1" in
  info) exit 0 ;;
  ps)
    case " $* " in
      *" label=ids-maat.punto "*) [ -n "${FALSO_ETIQUETA:-}" ] && echo 0123456789ab ;;
      *) for n in ${FALSO_NOMBRES:-}; do echo "$n"; done ;;
    esac
    exit 0 ;;
  network)
    [ "${2:-}" = ls ] && for n in ${FALSO_REDES:-}; do echo "$n"; done
    exit 0 ;;
  image) exit 1 ;;   # sin imagenes: pasada la guarda, la e2e se omite por eso
esac
exit 0
""",
}
SOLO_CONSULTAS = ("info", "ps ", "network ls")


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"), "necesita bash en Linux")
class Guarda(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="e2e-guarda-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        for nombre, texto in FALSOS.items():
            p = os.path.join(self.bin, nombre)
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(texto)
            os.chmod(p, 0o755)
        self.host = os.path.join(self.tmp, "host")      # hace de / para /srv/ids
        os.makedirs(self.host)
        self.log = os.path.join(self.tmp, "docker.log")

    def correr(self, **extra):
        env = {"PATH": self.bin + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": self.tmp, "LANG": "C.UTF-8", "DOCKER_LOG": self.log,
               "IDS_E2E_RAIZ_HOST": self.host,
               "IDS_IMG_VPN": "ids-maat-vpn:prueba", "IDS_IMG_SURICATA": "ids-maat-suricata:prueba"}
        env.update(extra)
        r = subprocess.run(["bash", E2E], env=env, capture_output=True, encoding="utf-8", timeout=60)
        try:
            with open(self.log, encoding="utf-8") as f:
                ordenes = f.read().splitlines()
        except FileNotFoundError:
            ordenes = []
        return r, ordenes

    def omitida_sin_tocar(self, motivo, **extra):
        r, ordenes = self.correr(**extra)
        self.assertEqual(r.returncode, 77, r.stdout + r.stderr)
        self.assertIn("servidor con el IDS instalado (", r.stdout)
        self.assertIn(motivo, r.stdout)
        # solo consultas: ni rm, ni network rm, ni compose, ni run, ni image
        for o in ordenes:
            self.assertTrue(o.startswith(SOLO_CONSULTAS), (o, ordenes))

    def test_con_contenedores_del_ids(self):
        """Correccion de defecto: con ids-core-panel o ids-pNNN-vpn/suricata se omite sin tocarlos."""
        self.omitida_sin_tocar("contenedores ids-core-panel,ids-p001-vpn",
                               FALSO_NOMBRES="otro ids-core-panel ids-p001-vpn")

    def test_con_contenedores_de_punto_por_su_etiqueta(self):
        """Correccion de defecto: un contenedor con la etiqueta ids-maat.punto (lo que borraba
        limpiar) basta para omitirla, se llame como se llame."""
        self.omitida_sin_tocar("etiqueta ids-maat.punto", FALSO_ETIQUETA="1")

    def test_con_las_redes_del_ids(self):
        """Correccion de defecto: las redes ids-pNNN / ids-core (las que borraba limpiar)."""
        self.omitida_sin_tocar("redes ids-p002", FALSO_REDES="bridge host ids-p002")

    def test_con_srv_ids(self):
        """Correccion de defecto: /srv/ids existe aunque no haya contenedores."""
        os.makedirs(os.path.join(self.host, "srv", "ids"))
        self.omitida_sin_tocar("existe /srv/ids")

    def test_con_ids_orq_activo(self):
        """Correccion de defecto: el servicio ids-orq activo."""
        self.omitida_sin_tocar("ids-orq activo", FALSO_ORQ_ACTIVO="1")

    def test_en_una_maquina_vacia_pasa_la_guarda(self):
        """Conservacion: sin nada del IDS (y con nombres parecidos que no lo son) la guarda deja
        seguir; aqui se para en la siguiente comprobacion, la de las imagenes."""
        r, ordenes = self.correr(FALSO_NOMBRES="otro ids-corepanel ids-p01-vpn ids-p001-web",
                                 FALSO_REDES="bridge ids-core-x ids-p1")
        self.assertEqual(r.returncode, 77, r.stdout + r.stderr)
        self.assertNotIn("servidor con el IDS instalado", r.stdout)
        self.assertIn("imágenes no construidas", r.stdout)
        self.assertTrue(any(o.startswith("image inspect") for o in ordenes), ordenes)


if __name__ == "__main__":
    unittest.main()
