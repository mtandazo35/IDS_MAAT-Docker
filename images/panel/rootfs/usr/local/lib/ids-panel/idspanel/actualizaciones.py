"""Botón «Actualizar» del panel (docs/ACTUALIZACIONES.md §4), como el del panel original.

- `buscar()` pregunta a la API pública de GitHub (sin token) qué commits de la rama main faltan
  desde lo instalado y deja el resultado en `estado/actualizacion-busqueda.json`.
- `avance()` lee `RUN/actualizacion.json`, que escribe en el servidor ids-actualizar.sh mientras
  actualiza (y deja al acabar con el resultado).

La actualización la lanza el orquestador (orden `sistema.actualizar`): el panel no tiene permisos
para tocar el servidor. Lleva el panel y el orquestador al commit pedido; los puntos no se tocan.

Lo instalado se sabe por, en este orden: el `commit` de estado.json (lo pone ids-actualizar o
lab-actualizar en imagenes.json), la versión de la imagen del panel (`main-<sha>` o `lab-<sha>`)
o la versión de la release (`v0.1.3`, que GitHub resuelve como etiqueta).
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

REPO = "mtandazo35/IDS_MAAT-Docker"
RAMA = "main"
API = "https://api.github.com/repos/" + REPO
RE_SHA = re.compile(r"\A[0-9a-f]{7,40}\Z")
RE_SHA_COMPLETO = re.compile(r"\A[0-9a-f]{40}\Z")
RE_VERSION_COMMIT = re.compile(r"\A(?:main|lab)-([0-9a-f]{7,40})\Z")
RE_VERSION_ETIQUETA = re.compile(r"\Av?([0-9]+\.[0-9]+\.[0-9]+)\Z")
HISTORIAL = 15              # commits de main que salen en «Historial de cambios»
MAX_MEJORAS = 40            # novedades que se listan (el resto se cuentan)
BUSCAR_CADA_S = 1800        # búsqueda automática como mucho cada 30 min (la API da 60/h por IP)
AVANCE_COLGADO_S = 3600     # «en curso» sin moverse tanto tiempo: la actualización murió
TIMEOUT_S = 15

FICHERO_BUSQUEDA = "actualizacion-busqueda.json"
FICHERO_AVANCE = "actualizacion.json"


def instalada(estado, version_imagen=""):
    """(ref, texto): `ref` es lo que se compara en GitHub (sha o etiqueta) y `texto` lo que se
    enseña. ("", texto) si no se sabe qué hay instalado."""
    estado = estado if isinstance(estado, dict) else {}
    c = estado.get("commit") or ""
    if isinstance(c, str) and RE_SHA.match(c):
        return c, c[:7]
    m = RE_VERSION_COMMIT.match(version_imagen or "")
    if m:
        return m.group(1), m.group(1)[:7]
    for v in (version_imagen, estado.get("version")):
        m = RE_VERSION_ETIQUETA.match(v if isinstance(v, str) else "")
        if m:
            return "v" + m.group(1), "v" + m.group(1)
    return "", version_imagen or ""


def pedir_github(url, timeout=TIMEOUT_S):
    """JSON de la API de GitHub. Lanza las excepciones de urllib (las traduce `motivo`)."""
    req = urllib.request.Request(url, headers={"User-Agent": "ids-maat-panel",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(4 * 1024 * 1024).decode("utf-8"))


def motivo(e):
    """Texto corto para el administrador de un fallo al hablar con GitHub."""
    if isinstance(e, urllib.error.HTTPError):
        if e.code in (403, 429):
            return "GitHub limita las consultas sin cuenta (60 por hora): prueba dentro de un rato"
        if e.code == 404:
            return "GitHub no encuentra el repositorio o la versión (404)"
        return "GitHub contestó HTTP %d" % e.code
    if isinstance(e, urllib.error.URLError):
        return "sin conexión con GitHub (%s)" % (getattr(e, "reason", "") or e)
    if isinstance(e, ValueError):
        return "GitHub contestó algo que no se entiende"
    return str(e)[:200] or e.__class__.__name__


def _asunto(c):
    return ((c.get("commit") or {}).get("message") or "").split("\n", 1)[0].strip()[:200]


def _fecha(c):
    """La marca ISO de GitHub tal cual (en UTC, «…Z»): el panel la pasa a la hora de la empresa al
    pintarla (fecha_ec). Cortada aquí, un commit de las 22:10 del 15 en Ecuador salía del 16."""
    d = ((c.get("commit") or {}).get("committer") or {}).get("date") \
        or ((c.get("commit") or {}).get("author") or {}).get("date") or ""
    return d if isinstance(d, str) else ""


def _es_merge(c):
    return len(c.get("parents") or []) > 1 or _asunto(c).lower().startswith("merge")


def buscar(estado, version_imagen="", pedir=None, ahora=None):
    """Lo que hay nuevo en main respecto a lo instalado. Nunca lanza: un fallo vuelve en «error».

    {"v", "checked", "instalada", "ref", "disponible", "objetivo" (sha de 40 del último commit de
     main), "ultimo" (su asunto), "fecha" (ISO en UTC), "n" (commits nuevos), "mejoras" [asuntos,
     del más nuevo al más viejo], "historial" [{"sha", "asunto", "fecha", "nuevo"}], "error"}"""
    pedir = pedir or pedir_github
    ahora = int(ahora if ahora is not None else time.time())
    ref, texto = instalada(estado, version_imagen)
    out = {"v": 1, "checked": ahora, "instalada": texto, "ref": ref, "disponible": False,
           "objetivo": "", "ultimo": "", "fecha": "", "n": 0, "mejoras": [], "historial": [],
           "error": ""}
    try:
        lista = pedir("%s/commits?sha=%s&per_page=%d" % (API, RAMA, HISTORIAL))
        if not isinstance(lista, list) or not lista or not RE_SHA_COMPLETO.match(str(lista[0].get("sha", ""))):
            raise ValueError("lista de commits vacía")
    except Exception as e:  # noqa: BLE001 - se enseña el motivo, no se cae la página
        out["error"] = motivo(e)
        return out
    cabeza = lista[0]["sha"]
    out.update(objetivo=cabeza, ultimo=_asunto(lista[0]), fecha=_fecha(lista[0]))
    nuevos = set()
    if not ref:
        out["error"] = "no se sabe qué versión hay instalada: se puede actualizar igual a la última de main"
        out["disponible"] = True
    elif cabeza.startswith(ref) or ref == cabeza:
        pass                                                   # al día
    else:
        try:
            cmp = pedir("%s/compare/%s...%s" % (API, ref, cabeza))
            if not isinstance(cmp, dict):
                raise ValueError("comparación ilegible")
        except Exception as e:  # noqa: BLE001
            out["error"] = "no se pudo comparar %s con main: %s" % (texto or ref, motivo(e))
            out["disponible"] = True
            cmp = None
        if cmp is not None:
            base = (cmp.get("base_commit") or {}).get("sha") or ""
            if RE_SHA_COMPLETO.match(base):
                out["instalada_sha"] = base
            commits = [c for c in (cmp.get("commits") or []) if isinstance(c, dict)]
            delante = cmp.get("ahead_by") if isinstance(cmp.get("ahead_by"), int) else len(commits)
            if cmp.get("status") in ("ahead", "diverged") and delante > 0:
                out["disponible"] = True
                out["n"] = delante
                nuevos = {c.get("sha") for c in commits}
                out["mejoras"] = [_asunto(c) for c in reversed(commits) if not _es_merge(c) and _asunto(c)][:MAX_MEJORAS]
    out["historial"] = [{"sha": str(c.get("sha", ""))[:7], "asunto": _asunto(c), "fecha": _fecha(c),
                         "nuevo": c.get("sha") in nuevos}
                        for c in lista if isinstance(c, dict) and not _es_merge(c) and _asunto(c)]
    return out


def leer_busqueda(dir_estado):
    try:
        with open(os.path.join(dir_estado, FICHERO_BUSQUEDA), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def guardar_busqueda(dir_estado, datos):
    from idspanel import util
    os.makedirs(dir_estado, mode=0o700, exist_ok=True)
    util.escribir_json(os.path.join(dir_estado, FICHERO_BUSQUEDA), datos)


def toca_buscar(busqueda, ahora=None):
    """¿Ha pasado BUSCAR_CADA_S desde la última búsqueda (o no hay ninguna)?"""
    ahora = ahora if ahora is not None else time.time()
    try:
        return ahora - int(busqueda.get("checked") or 0) >= BUSCAR_CADA_S
    except (TypeError, ValueError):
        return True


def avance(dir_run, ahora=None):
    """El de RUN/actualizacion.json (ver ids-actualizar.sh) o {}. Uno «en_curso» que no se mueve
    desde hace AVANCE_COLGADO_S sale como «colgada»: la unidad murió sin escribir el final."""
    try:
        with open(os.path.join(dir_run, FICHERO_AVANCE), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    ahora = ahora if ahora is not None else time.time()
    try:
        ts = int(d.get("ts") or 0)
    except (TypeError, ValueError):
        ts = 0
    if d.get("estado") == "en_curso" and ahora - ts > AVANCE_COLGADO_S:
        d = dict(d, estado="colgada")
    return d


def en_curso(av):
    return bool(av) and av.get("estado") == "en_curso"
