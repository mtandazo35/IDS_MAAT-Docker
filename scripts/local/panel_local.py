"""Panel de IDS_MAAT-Docker en local (Windows o Linux), sin Docker y sin orquestador.

  python scripts/local/panel_local.py [--puerto 5637] [--escucha 127.0.0.1] [--horas 26]
                                      [--sin-datos] [--borrar]

Monta en .panel-local/ (ignorada por git) lo que en el VPS montan el compose y el orquestador:
  panel/   datos del panel (usuarios, cache, geo/ipv4.bin que el panel descarga solo)
  datos/   eve.json de cada punto        run/   estado.json y tzsp.json de cada punto
  master_key, orq_token                  clave_admin.txt  clave inicial del usuario admin
y arranca el panel con el codigo del repo (images/panel/rootfs) mas el generador de datos de
prueba (4 puntos: Centro, Norte, Sur sin espejo, Este pausado) en modo vivo.

Cada arranque regenera el historico (las horas son relativas a ahora); --sin-datos lo omite.
--borrar empieza de cero (usuarios, cache y datos). Ctrl+C para los dos procesos.
Requisitos: Python 3.11+ y `pip install cryptography`. Dar de alta Puntos no funciona (no
hay orquestador): los puntos los publica el generador en run/estado.json.
"""

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAIZ = os.path.join(REPO, "images", "panel", "rootfs", "usr", "local")
BASE = os.path.join(REPO, ".panel-local")
GENERADOR = os.path.join(REPO, "scripts", "local", "generar_datos.py")


def _fichero(ruta, contenido):
    if not os.path.exists(ruta):
        with open(ruta, "w", encoding="ascii", newline="\n") as f:
            f.write(contenido + "\n")


def entorno(a):
    env = dict(os.environ)
    env.update({
        "IDS_PANEL_DIR": os.path.join(BASE, "panel"),
        "IDS_DATOS": os.path.join(BASE, "datos"),
        "IDS_RUN": os.path.join(BASE, "run"),
        "IDS_MASTER_KEY": os.path.join(BASE, "master_key"),
        "IDS_ORQ_SOCK": os.path.join(BASE, "orq.sock"),
        "IDS_ORQ_TOKEN": os.path.join(BASE, "orq_token"),
        # mapa y tailwind: los del repo (en la imagen van en /usr/local/share/ids-panel)
        "IDS_SHARE": os.path.join(RAIZ, "share", "ids-panel"),
        "IDS_TZ": "America/Guayaquil",
        "IDS_PUERTO": str(a.puerto),
        "IDS_ESCUCHA": a.escucha,
        "IDS_MAAT_VERSION": "dev-local",
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def preparar(env):
    for d in ("panel", "datos", "run"):
        os.makedirs(os.path.join(BASE, d), exist_ok=True)
    _fichero(env["IDS_MASTER_KEY"], secrets.token_hex(32))
    _fichero(env["IDS_ORQ_TOKEN"], secrets.token_hex(32))
    ruta_clave = os.path.join(BASE, "clave_admin.txt")
    r = subprocess.run([sys.executable, os.path.join(RAIZ, "bin", "ids-panel"), "crear-admin",
                        "--usuario", "admin"], env=env, capture_output=True, text=True)
    if r.returncode == 0:
        clave = r.stdout.strip().split("CLAVE=", 1)[-1]
        with open(ruta_clave, "w", encoding="utf-8", newline="\n") as f:
            f.write("admin %s\n" % clave)
        print("usuario admin creado; clave inicial en %s (el panel pide cambiarla)" % ruta_clave)
    elif r.returncode == 3:
        if os.path.exists(ruta_clave):
            print("ya hay usuarios; clave inicial de admin en %s (si no la cambiaste)" % ruta_clave)
        else:
            print("ya hay usuarios")
    else:
        sys.exit("crear-admin fallo (%d): %s" % (r.returncode, (r.stderr or r.stdout).strip()))


def esperar_geo(panel, seg=90):
    """El panel descarga la base IP->pais al arrancar; sin ella el generador usa IPs sin pais
    (mapa vacio), asi que se espera un poco antes de generar."""
    geo = os.path.join(BASE, "panel", "geo", "ipv4.bin")
    if not os.path.exists(geo):
        print("esperando a que el panel descargue la base GeoIP (hasta %d s)..." % seg, flush=True)
    fin = time.time() + seg
    while time.time() < fin and panel.poll() is None:
        if os.path.exists(geo) and os.path.getsize(geo) > 0:
            return True
        time.sleep(1)
    print("sin base GeoIP: los datos salen sin pais (reinicia el lanzador cuando el panel la tenga)")
    return False


def main():
    ap = argparse.ArgumentParser(description="Panel de IDS_MAAT-Docker en local con datos de prueba")
    ap.add_argument("--puerto", type=int, default=5637)
    ap.add_argument("--escucha", default="127.0.0.1", help="0.0.0.0 para verlo desde otra maquina")
    ap.add_argument("--horas", type=float, default=26, help="horas de historico a generar")
    ap.add_argument("--sin-datos", action="store_true", help="no generar datos de prueba")
    ap.add_argument("--borrar", action="store_true", help="empezar de cero (borra .panel-local)")
    a = ap.parse_args()

    if a.borrar and os.path.isdir(BASE):
        shutil.rmtree(BASE)
    env = entorno(a)
    preparar(env)

    log_panel = open(os.path.join(BASE, "panel.log"), "a", encoding="utf-8")
    panel = subprocess.Popen([sys.executable, os.path.join(RAIZ, "bin", "ids-panel"), "servir"],
                             env=env, stdout=log_panel, stderr=subprocess.STDOUT)
    procs = [panel]
    host = "127.0.0.1" if a.escucha in ("0.0.0.0", "") else a.escucha
    print("panel: http://%s:%d   (log en %s)" % (host, a.puerto, os.path.join(BASE, "panel.log")), flush=True)
    try:
        if not a.sin_datos:
            esperar_geo(panel)
            log_gen = open(os.path.join(BASE, "generador.log"), "a", encoding="utf-8")
            procs.append(subprocess.Popen(
                [sys.executable, GENERADOR, BASE, "--horas", str(a.horas), "--vivo"],
                cwd=BASE, env=env, stdout=log_gen, stderr=subprocess.STDOUT))
            print("generador de datos en modo vivo (log en %s)" % os.path.join(BASE, "generador.log"), flush=True)
        print("Ctrl+C para parar", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        caido = next(p for p in procs if p.poll() is not None)
        print("%s termino con codigo %s; mira su log" % ("el panel" if caido is panel else "el generador",
                                                        caido.returncode))
        return 1
    except KeyboardInterrupt:
        print("parando...")
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
