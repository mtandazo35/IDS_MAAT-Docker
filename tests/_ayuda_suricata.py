"""Ayudas de las pruebas del constructor B (imagen suricata e ids-reglas).

- cargar(nombre): importa un script de images/suricata/rootfs/usr/local/bin (sin .py).
- render(texto, marcadores, valores): render de la plantilla como lo describe el contrato
  (§4.6): str.replace de cada @@X@@ y error si sobra o falta algún marcador.
- yaml_subconjunto(texto): parser del subconjunto de YAML que usa la plantilla (mapas por
  sangría, listas "- ", escalares), para comprobar la estructura sin PyYAML.
- Como programa: `python3 tests/_ayuda_suricata.py render --salida F [--valor K=V ...]`
  renderiza la plantilla de la imagen (lo usan las pruebas de tests/imagen/).
"""
import argparse
import importlib.machinery
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ROOTFS = REPO / "images" / "suricata" / "rootfs"
BIN = ROOTFS / "usr" / "local" / "bin"
SHARE = ROOTFS / "usr" / "share" / "ids-maat"
FIXTURES = REPO / "tests" / "fixtures" / "suricata"
PLANTILLA = SHARE / "suricata.yaml.tmpl"
MANIFIESTO = SHARE / "plantilla.json"
RE_MARCADOR = re.compile(r"@@([A-Za-z0-9_]+)@@")

# Valores de prueba propios (B no duplica la tabla PERFILES del orquestador).
VALORES_PRUEBA = {
    "SENSOR_NAME": "p003",
    "HOME_NET": "[10.0.0.0/24,192.168.88.0/24]",
    "RULE_PATH": "/reglas/current/reducido",
    "CLUSTER_ID": "103",
    "HILOS": "1",
    "RING_SIZE": "1024",
    "BLOCK_SIZE": "131072",
    "SNAPLEN": "32768",
    "DETECT_PROFILE": "medium",
    "SGH_MPM_CONTEXT": "auto",
    "MPM_ALGO": "hs",
    "SPM_ALGO": "hs",
    "FLOW_MEMCAP": "64mb",
    "STREAM_MEMCAP": "64mb",
    "REASSEMBLY_MEMCAP": "256mb",
    "DEFRAG_MEMCAP": "32mb",
}


def cargar(nombre):
    """Importa un script sin extensión de la imagen como módulo."""
    ruta = BIN / nombre
    modulo = "ids_b_" + nombre.replace("-", "_")
    cargador = importlib.machinery.SourceFileLoader(modulo, str(ruta))
    spec = importlib.util.spec_from_loader(modulo, cargador)
    mod = importlib.util.module_from_spec(spec)
    antes = sys.dont_write_bytecode
    sys.dont_write_bytecode = True       # nada de __pycache__ dentro de rootfs/
    try:
        cargador.exec_module(mod)
    finally:
        sys.dont_write_bytecode = antes
    return mod


class ErrorRender(Exception):
    pass


def marcadores_de(texto):
    return set(RE_MARCADOR.findall(texto))


def render(texto, marcadores, valores):
    """Render del contrato: falla si sobra o falta algún marcador."""
    esperados = set(marcadores)
    en_texto = marcadores_de(texto)
    if en_texto != esperados:
        raise ErrorRender("la plantilla no coincide con plantilla.json: sobran %s, faltan %s"
                          % (sorted(en_texto - esperados), sorted(esperados - en_texto)))
    if set(valores) != esperados:
        raise ErrorRender("valores: sobran %s, faltan %s"
                          % (sorted(set(valores) - esperados), sorted(esperados - set(valores))))
    out = texto
    for k in marcadores:
        out = out.replace("@@%s@@" % k, str(valores[k]))
    if "@@" in out:
        raise ErrorRender("queda un marcador sin sustituir")
    return out


def render_imagen(valores=None):
    man = json.loads(MANIFIESTO.read_text(encoding="utf-8"))
    return render(PLANTILLA.read_text(encoding="utf-8"), man["marcadores"],
                  dict(VALORES_PRUEBA, **(valores or {})))


# --------------------------------------------------------------------------- YAML
class ErrorYaml(Exception):
    pass


def _escalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _quitar_comentario(linea):
    """Quita un comentario ' #...' fuera de comillas."""
    dentro = None
    for i, ch in enumerate(linea):
        if dentro:
            if ch == dentro:
                dentro = None
        elif ch in "\"'":
            dentro = ch
        elif ch == "#" and (i == 0 or linea[i - 1] in " \t"):
            return linea[:i].rstrip()
    return linea.rstrip()


def yaml_subconjunto(texto):
    """Parser del subconjunto de YAML de la plantilla. Escalares como texto. Falla con
    tabuladores, claves repetidas, sangría incoherente o estilo flujo ({...})."""
    lineas = []
    for n, bruta in enumerate(texto.splitlines(), 1):
        if "\t" in bruta:
            raise ErrorYaml("línea %d: tabulador" % n)
        if n <= 2 and bruta.strip() in ("%YAML 1.1", "---"):
            continue
        sin = _quitar_comentario(bruta)
        if not sin.strip():
            continue
        lineas.append((n, len(sin) - len(sin.lstrip(" ")), sin.strip()))
    pos = 0

    def bloque(sangria):
        if pos >= len(lineas):
            raise ErrorYaml("bloque vacío al final")
        n, s, t = lineas[pos]
        if s != sangria:
            raise ErrorYaml("línea %d: sangría %d, se esperaba %d" % (n, s, sangria))
        return lista(sangria) if t.startswith("- ") or t == "-" else mapa(sangria)

    def valor_de(n, resto, sangria_hijo_min):
        if resto == "":
            if pos < len(lineas) and lineas[pos][1] >= sangria_hijo_min:
                return bloque(lineas[pos][1])
            return None
        if resto.startswith("{") or resto.startswith("["):
            if not (resto.startswith("[") and resto.endswith("]")) or "{" in resto:
                raise ErrorYaml("línea %d: estilo flujo no admitido" % n)
        return _escalar(resto)

    def mapa(sangria):
        nonlocal pos
        out = {}
        while pos < len(lineas):
            n, s, t = lineas[pos]
            if s < sangria:
                break
            if s > sangria:
                raise ErrorYaml("línea %d: sangría inesperada" % n)
            if t.startswith("- "):
                break
            m = re.match(r"^([A-Za-z0-9_.$-]+):(?:\s+(.*))?$", t)
            if not m:
                raise ErrorYaml("línea %d: no es 'clave: valor': %r" % (n, t))
            clave, resto = m.group(1), (m.group(2) or "")
            if clave in out:
                raise ErrorYaml("línea %d: clave repetida %r" % (n, clave))
            pos += 1
            out[clave] = valor_de(n, resto, sangria + 1)
        return out

    def lista(sangria):
        nonlocal pos
        out = []
        while pos < len(lineas):
            n, s, t = lineas[pos]
            if s < sangria or not (t.startswith("- ") or t == "-"):
                if s > sangria:
                    raise ErrorYaml("línea %d: sangría inesperada en lista" % n)
                break
            if s > sangria:
                raise ErrorYaml("línea %d: sangría inesperada" % n)
            item = t[2:].strip() if t != "-" else ""
            m = re.match(r"^([A-Za-z0-9_.$-]+):(?:\s+(.*))?$", item)
            if m:
                # "- clave: valor" abre un mapa cuya sangría es la del texto tras "- "
                sang_item = s + 2
                lineas[pos] = (n, sang_item, item)
                out.append(mapa(sang_item))
            else:
                pos += 1
                out.append(_escalar(item))
        return out

    if not lineas:
        return {}
    res = bloque(lineas[0][1])
    if pos != len(lineas):
        raise ErrorYaml("línea %d: contenido fuera de bloque" % lineas[pos][0])
    return res


# --------------------------------------------------------------------------- suricata falso
class Resultado:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class FalsoSuricata:
    """Sustituye a subprocess.run en ids-reglas: responde a `suricata -V` y simula
    `suricata-update` sobre el conjunto de reglas de prueba de fixtures/suricata/et.

    Como el real: descarga a <data-dir>/update/cache/<md5(url)>-emerging.rules.tar.gz, con
    --offline usa solo esa caché, aplica el disable.conf (con la semántica que implementa
    ids-reglas) y escribe las reglas desactivadas comentadas en <-o>/suricata.rules."""

    def __init__(self, mod, version="7.0.10", fallar_en=None, clasificacion=True):
        self.mod = mod
        self.version = version
        self.fallar_en = fallar_en
        self.clasificacion = clasificacion
        self.llamadas = []
        self.url = "https://rules.example/open/suricata-%s/emerging.rules.tar.gz" % version

    def __call__(self, argv, **_kw):
        argv = list(argv)
        self.llamadas.append(argv)
        if argv[:2] == ["suricata", "-V"]:
            return Resultado(0, "This is Suricata version %s RELEASE\n" % self.version)
        if argv and argv[0] == "suricata-update":
            return self._update(argv[1:])
        raise FileNotFoundError(argv[0])

    def ruta_tar(self, data_dir):
        import hashlib
        return Path(data_dir) / "update" / "cache" / ("%s-emerging.rules.tar.gz"
                                                      % hashlib.md5(self.url.encode()).hexdigest())

    def _update(self, args):
        import fnmatch
        import io
        import tarfile
        op, i = {}, 0
        while i < len(args):
            if args[i] in ("--offline", "--etopen", "--no-test", "--fail"):
                op[args[i]] = True
                i += 1
            else:
                op[args[i]] = args[i + 1]
                i += 2
        salida = Path(op["-o"])
        if self.fallar_en == salida.name:
            return Resultado(1, "", "Error simulado en %s\n" % salida.name)
        tar = self.ruta_tar(op["--data-dir"])
        if op.get("--offline"):
            if not tar.is_file():
                return Resultado(1, "", "Error: no hay nada en caché (offline)\n")
            log = "-- Using cached file (offline)\n"
        else:
            tar.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(tar, "w:gz") as t:
                t.add(str(FIXTURES / "et" / "rules"), arcname="rules")
            log = "-- Checking %s.md5.\n-- Fetching %s.\n" % (self.url, self.url)
        ignorar = re.findall(r'-\s*"([^"]+)"', Path(op["-c"]).read_text(encoding="utf-8"))
        grupos, clasif = {}, None
        with tarfile.open(tar, "r:gz") as t:
            for m in t.getmembers():
                nombre = m.name.rsplit("/", 1)[-1]
                if not m.isfile():
                    continue
                datos = t.extractfile(m).read().decode("utf-8")
                if nombre == "classification.config":
                    clasif = datos
                elif nombre.endswith(".rules") and not any(fnmatch.fnmatch(nombre, p) for p in ignorar):
                    grupos[nombre] = datos.splitlines()
        entradas = self.mod.leer_conf_disable(Path(op["--disable-conf"]).read_text(encoding="utf-8"))
        out = io.StringIO()
        for grupo in sorted(grupos):
            for linea in grupos[grupo]:
                if not linea.strip() or linea.lstrip().startswith("#"):
                    continue
                if any(self.mod.casa_disable(e, linea, grupo) for e in entradas):
                    out.write("# " + linea + "\n")
                else:
                    out.write(linea + "\n")
        salida.mkdir(parents=True, exist_ok=True)
        (salida / "suricata.rules").write_text(out.getvalue(), encoding="utf-8", newline="\n")
        if self.clasificacion and clasif is not None:
            (salida / "classification.config").write_text(clasif, encoding="utf-8", newline="\n")
        return Resultado(0, log, "")


def main(argv=None):
    p = argparse.ArgumentParser(prog="_ayuda_suricata.py")
    sub = p.add_subparsers(dest="orden", required=True)
    r = sub.add_parser("render", help="renderiza la plantilla de la imagen")
    r.add_argument("--plantilla", default=str(PLANTILLA))
    r.add_argument("--manifiesto", default=str(MANIFIESTO))
    r.add_argument("--salida", required=True)
    r.add_argument("--valor", action="append", default=[], metavar="K=V")
    a = p.parse_args(argv)
    valores = dict(VALORES_PRUEBA)
    for kv in a.valor:
        k, _, v = kv.partition("=")
        valores[k] = v
    man = json.loads(Path(a.manifiesto).read_text(encoding="utf-8"))
    texto = render(Path(a.plantilla).read_text(encoding="utf-8"), man["marcadores"], valores)
    Path(a.salida).write_text(texto, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
