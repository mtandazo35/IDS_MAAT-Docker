"""orquestador/ids-actualizar.sh (botón «Actualizar» del panel, ACTUALIZACIONES.md §4).

Se ejecuta el script REAL con IDS_RAIZ en un directorio temporal, un repositorio git local que
hace de GitHub (con ids_orq.py, plantillas, unidades y build.sh de verdad) y docker, systemctl e
ids-orq falsos que apuntan lo que se les pide. Comprueba:
- el camino bueno: imagen main-<sha7>, orquestador del commit instalado, imagenes.json con el commit,
  ids-orq reiniciado, panel recreado, respaldo sin la clave maestra y avance «ok»;
- la vuelta atrás si el panel nuevo no queda sano;
- que un commit que no es de main no se instala;
- el modo --pedido (el de la unidad): lee el pedido de ids-orq, lo borra y firma el avance con su op_id.

Tipo «capacidad nueva». Necesita Linux con bash, git, flock, tar y python3 (se corre en la VPS).
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "orquestador" / "ids-actualizar.sh"
LINUX = sys.platform.startswith("linux")
HERRAMIENTAS = all(shutil.which(h) for h in ("bash", "git", "flock", "tar", "python3"))
OP = "11111111-2222-4333-8444-555555555555"
IMG_PANEL_REL = "ghcr.io/mtandazo35/ids-maat-panel@sha256:" + "e" * 64

FALSO_DOCKER = """#!/bin/bash
echo "docker $*" >> "$LLAMADAS"
if [ "$1 $2" = "image ls" ]; then printf 'ids-maat-panel:main-aaaaaaa\\nids-maat-panel:%s\\n' "$ETIQUETA_ACTUAL"; fi
exit 0
"""
FALSO_SYSTEMCTL = """#!/bin/bash
echo "systemctl $*" >> "$LLAMADAS"
exit 0
"""
# «panel aplicar» falla las veces que diga el fichero $FALLOS_PANEL (y luego va bien)
FALSO_ORQ = """#!/bin/bash
echo "ids-orq $*" >> "$LLAMADAS"
if [ "$1 $2" = "panel aplicar" ] && [ -s "$FALLOS_PANEL" ]; then
  n=$(cat "$FALLOS_PANEL"); [ "$n" -gt 0 ] && { echo $((n - 1)) > "$FALLOS_PANEL"; exit 1; }
fi
exit 0
"""


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=Prueba", "-c", "user.email=prueba@example.invalid",
                           "-c", "init.defaultBranch=main", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(LINUX and HERRAMIENTAS, "Linux con bash, git, flock, tar y python3")
class Actualizador(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ids-act-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.R = self.d / "raiz"
        self.repo = self.d / "repo"
        self.falsos = self.d / "bin"
        self.llamadas = self.d / "llamadas.txt"
        self.fallos_panel = self.d / "fallos_panel"
        self.llamadas.write_text("", encoding="utf-8")
        self._repo()
        self._raiz()
        self.falsos.mkdir()
        for nombre, txt in (("docker", FALSO_DOCKER), ("systemctl", FALSO_SYSTEMCTL), ("ids-orq", FALSO_ORQ)):
            p = self.falsos / nombre
            p.write_text(txt, encoding="utf-8", newline="\n")
            p.chmod(0o755)

    def _repo(self):
        r = self.repo
        for rel in ("orquestador/ids_orq.py", "orquestador/ids-actualizar.sh", "images/build.sh",
                    "images/base.env", "host/logrotate/ids-maat.conf"):
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, r / rel)
        for sub in ("orquestador/plantillas", "host/systemd"):
            shutil.copytree(REPO / sub, r / sub)
        (r / "images" / "panel").mkdir(parents=True)
        (r / "images" / "panel" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        git(self.d, "init", "-q", str(r))
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "Lo instalado")
        self.c1 = git(r, "rev-parse", "HEAD")
        with open(r / "orquestador" / "ids_orq.py", "a", encoding="utf-8", newline="\n") as f:
            f.write("# version nueva del orquestador\n")
        git(r, "commit", "-q", "-am", "Orquestador nuevo")
        self.c2 = git(r, "rev-parse", "HEAD")
        git(r, "checkout", "-q", "-b", "otra")
        (r / "README.md").write_text("rama\n", encoding="utf-8")
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "Fuera de main")
        self.c_rama = git(r, "rev-parse", "HEAD")
        git(r, "checkout", "-q", "main")

    def _raiz(self):
        R = self.R
        etc = R / "etc" / "ids-maat"
        etc.mkdir(parents=True)
        self.imagenes = {"v": 1, "version": "0.1.3", "dev": False,
                         "imagenes": {"vpn": "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + "a" * 64,
                                      "suricata": "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "b" * 64,
                                      "panel": IMG_PANEL_REL}}
        (etc / "imagenes.json").write_text(json.dumps(self.imagenes), encoding="utf-8")
        (etc / "master.key").write_text("0" * 64 + "\n", encoding="utf-8")
        (etc / "logrotate.conf").write_text("# viejo\n", encoding="utf-8")
        lib = R / "usr" / "local" / "lib" / "ids-orq"
        (lib / "plantillas").mkdir(parents=True)
        (lib / "ids_orq.py").write_text("# orquestador viejo\n", encoding="utf-8")
        (lib / "ids-actualizar.sh").write_text("#!/bin/bash\n# viejo\n", encoding="utf-8")
        (lib / "plantillas" / "core.yml.tmpl").write_text("# vieja\n", encoding="utf-8")
        sd = R / "etc" / "systemd" / "system"
        sd.mkdir(parents=True)
        (sd / "ids-orq.service").write_text("# unidad vieja\n", encoding="utf-8")
        for d in ("srv/ids/run", "srv/ids/estado", "srv/ids/panel/conf", "srv/ids/pki", "srv/ids/puntos",
                  "srv/ids/fw", "root/backups"):
            (R / d).mkdir(parents=True, exist_ok=True)
        (R / "srv/ids/panel/conf/usuarios.json").write_text("[]", encoding="utf-8")

    def correr(self, *args, etiqueta=""):
        entorno = dict(os.environ, IDS_RAIZ=str(self.R), IDS_REPO_URL=str(self.repo),
                       IDS_ORQ_BIN=str(self.falsos / "ids-orq"), IDS_ESPERA_ORQ_S="2",
                       PATH="%s:%s" % (self.falsos, os.environ.get("PATH", "")),
                       LLAMADAS=str(self.llamadas), FALLOS_PANEL=str(self.fallos_panel),
                       ETIQUETA_ACTUAL=etiqueta)
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True,
                              timeout=180, env=entorno)

    def leer(self, rel):
        return (self.R / rel).read_text(encoding="utf-8")

    def avance(self):
        return json.loads(self.leer("srv/ids/run/actualizacion.json"))

    def test_camino_bueno(self):
        sha7 = self.c2[:7]
        r = self.correr(self.c2[:7], "ana", etiqueta="main-" + sha7)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        av = self.avance()
        self.assertEqual((av["estado"], av["a"], av["desde"], av["quien"]), ("ok", self.c2, "0.1.3", "ana"))
        self.assertEqual({p["estado"] for p in av["pasos"]}, {"ok"})
        img = json.loads(self.leer("etc/ids-maat/imagenes.json"))
        self.assertEqual((img["dev"], img["version"], img["commit"]), (True, "main-" + sha7, self.c2))
        self.assertEqual(img["imagenes"]["panel"], "ids-maat-panel:main-" + sha7)
        self.assertEqual(img["imagenes"]["vpn"], self.imagenes["imagenes"]["vpn"])     # los puntos, igual
        self.assertIn("# version nueva del orquestador", self.leer("usr/local/lib/ids-orq/ids_orq.py"))
        nuevo = self.R / "usr/local/lib/ids-orq/ids-actualizar.sh"
        self.assertEqual(nuevo.read_bytes(), SCRIPT.read_bytes())
        self.assertTrue(os.access(nuevo, os.X_OK))
        self.assertTrue((self.R / "etc/systemd/system/ids-actualizar.service").is_file())
        ll = self.llamadas.read_text(encoding="utf-8")
        self.assertIn("-t ids-maat-panel:main-%s panel" % sha7, ll)
        self.assertIn("systemctl daemon-reload", ll)
        self.assertIn("systemctl restart ids-orq", ll)
        self.assertIn("ids-orq estado", ll)
        self.assertIn("ids-orq panel aplicar", ll)
        self.assertIn("docker image rm ids-maat-panel:main-aaaaaaa", ll)       # la vieja, fuera
        self.assertNotIn("docker image rm ids-maat-panel:main-%s" % sha7, ll)
        tars = list((self.R / "root/backups").glob("ids-maat-actualizar-*.tar.gz"))
        self.assertEqual(len(tars), 1)
        with tarfile.open(tars[0]) as t:
            nombres = t.getnames()
        self.assertFalse([n for n in nombres if n.endswith("master.key")], nombres)
        self.assertTrue([n for n in nombres if n.endswith("etc/ids-maat/imagenes.json")], nombres)
        self.assertTrue([n for n in nombres if n.endswith("srv/ids/panel/conf/usuarios.json")], nombres)
        linea = json.loads(self.leer("srv/ids/estado/orq.jsonl").splitlines()[-1])
        self.assertEqual((linea["orden"], linea["codigo"], linea["a"]), ("sistema.actualizar", "OK", self.c2))

    def _commit_con_journald(self):
        r = self.repo
        (r / "host" / "journald").mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / "host/journald/90-ids.conf", r / "host/journald/90-ids.conf")
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "Con journald")
        return git(r, "rev-parse", "HEAD")

    def test_host_al_dia_no_avisa(self):
        """Corrección de defecto (revisión 2026-10-15, R1): con el host igual que en el commit, el
        mensaje de siempre."""
        c3 = self._commit_con_journald()
        dst = self.R / "etc/systemd/journald.conf.d/90-ids.conf"
        dst.parent.mkdir(parents=True)
        shutil.copy2(REPO / "host/journald/90-ids.conf", dst)
        r = self.correr(c3[:7], "ana", etiqueta="main-" + c3[:7])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.avance()["mensaje"], "Actualizado a %s." % c3[:7])

    def test_host_distinto_avisa_que_hay_que_volver_a_instalar(self):
        """Corrección de defecto (revisión 2026-10-15, R1): «Actualizar» no lleva fail2ban, journald,
        sysctl ni módulos (eso es install.sh) y no lo decía: un host con lo de antes quedaba así sin que
        nadie lo supiera. Ahora termina bien, sin tocar el host, y avisa."""
        c3 = self._commit_con_journald()
        dst = self.R / "etc/systemd/journald.conf.d/90-ids.conf"
        dst.parent.mkdir(parents=True)
        dst.write_text("# viejo\n", encoding="utf-8")
        r = self.correr(c3[:7], "ana", etiqueta="main-" + c3[:7])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        av = self.avance()
        self.assertEqual(av["estado"], "ok")
        self.assertIn("host sin actualizar (journald)", av["mensaje"])
        self.assertIn("install.sh", av["mensaje"])
        self.assertEqual(dst.read_text(encoding="utf-8"), "# viejo\n")            # el botón no lo toca
        linea = json.loads(self.leer("srv/ids/estado/orq.jsonl").splitlines()[-1])
        self.assertEqual(linea["codigo"], "OK")
        self.assertIn("host sin actualizar (journald)", linea["mensaje"])

    def test_panel_que_no_queda_sano_vuelve_atras(self):
        self.fallos_panel.write_text("1", encoding="utf-8")
        r = self.correr(self.c2, "ana")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        av = self.avance()
        self.assertEqual(av["estado"], "revertida", av)
        self.assertIn("recrear el panel", av["mensaje"])
        estados = {p["nombre"]: p["estado"] for p in av["pasos"]}
        self.assertEqual(estados["recrear el panel"], "fallo")
        self.assertEqual(estados["instalar el orquestador"], "revertido")
        self.assertEqual(json.loads(self.leer("etc/ids-maat/imagenes.json")), self.imagenes)
        self.assertEqual(self.leer("usr/local/lib/ids-orq/ids_orq.py"), "# orquestador viejo\n")
        self.assertEqual(self.leer("etc/systemd/system/ids-orq.service"), "# unidad vieja\n")
        ll = self.llamadas.read_text(encoding="utf-8")
        self.assertEqual(ll.count("ids-orq panel aplicar"), 2)                  # el nuevo y el de vuelta
        self.assertEqual(ll.count("systemctl restart ids-orq"), 2)
        self.assertEqual(json.loads(self.leer("srv/ids/estado/orq.jsonl").splitlines()[-1])["codigo"], "REVERTIDA")

    def test_un_commit_que_no_es_de_main_no_se_instala(self):
        r = self.correr(self.c_rama, "ana")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        av = self.avance()
        self.assertEqual(av["estado"], "fallo")
        self.assertIn("no es de la rama main", av["mensaje"])
        self.assertIn("No se cambió nada", av["mensaje"])
        self.assertEqual(json.loads(self.leer("etc/ids-maat/imagenes.json")), self.imagenes)
        self.assertNotIn("docker build", self.llamadas.read_text(encoding="utf-8"))
        self.assertEqual(list((self.R / "root/backups").glob("*.tar.gz")), [])

    def test_commit_que_no_existe_o_invalido(self):
        r = self.correr("abcdef0", "ana")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no está en GitHub", self.avance()["mensaje"])
        r = self.correr("main", "ana")
        self.assertEqual(r.returncode, 2)
        self.assertIn("commit inválido", r.stderr)

    def test_modo_pedido_de_la_unidad(self):
        ped = self.R / "srv/ids/estado/actualizar-pedido.json"
        ped.write_text(json.dumps({"commit": self.c2[:7], "quien": "panel:ana", "op_id": OP, "ts": 1}),
                       encoding="utf-8")
        r = self.correr("--pedido", etiqueta="main-" + self.c2[:7])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        av = self.avance()
        self.assertEqual((av["id"], av["quien"], av["estado"]), (OP, "panel:ana", "ok"))
        self.assertFalse(ped.exists())

    def test_ayuda_y_sintaxis(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)]).returncode, 0)
        r = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--pedido", r.stdout)


if __name__ == "__main__":
    unittest.main()
