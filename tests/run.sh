#!/bin/bash
# ids-maat — runner de pruebas (CONTRATO-F1a §8.1). Sin lista que mantener: descubre todo.
#   tests/run.sh [--imagenes] [--integracion]
#   1. python tests/correr.py (unittest de tests/ y tests/legado/, un módulo por proceso en los
#      núcleos, hasta 4; IDS_PROCESOS=1 en serie; como root, en un cgroup con IDS_TOPE_MEMORIA, 3G por
#      defecto; python3, python o "py -3")
#   2. cada tests/test_*.sh con bash
#   3. --imagenes:    cada tests/imagen/test_*.sh       (Docker Linux, IDS_IMG_VPN, IDS_IMG_SURICATA)
#   4. --integracion: cada tests/integracion/test_*.sh  (root y Docker)
# Un .sh que sale con 77 cuenta como OMITIDA. Sale con 1 si falla alguna.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

IMAGENES=0
INTEGRACION=0
for a in "$@"; do
  case "$a" in
    --imagenes) IMAGENES=1 ;;
    --integracion) INTEGRACION=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "opción desconocida: $a" >&2; exit 2 ;;
  esac
done

buscar_python() {
  local c
  for c in python3 python "py -3"; do
    # shellcheck disable=SC2086 # "py -3" son dos palabras a propósito
    if $c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

PY=$(buscar_python) || { echo "no hay Python >= 3.11 (python3, python o py -3)" >&2; exit 1; }
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUTF8=1

# Dependencias de las pruebas que el host no trae (QA T-02, 2026-11-14): sin reportlab, test_informe_pdf
# no se importaba y la suite no terminaba nunca en verde, así que un fallo nuevo pasaba como «uno más».
# Si faltan, se instalan las de tests/requisitos-pruebas.txt (las versiones de la imagen del panel) en
# IDS_DEPS_DIR con un contenedor python:<versión>-slim y pip --target, y se añaden a PYTHONPATH. No toca
# los paquetes del host. IDS_DEPS=0 lo desactiva. Una carpeta ya preparada para el mismo fichero se reusa.
preparar_deps() {
  local req ver dir huella
  req=tests/requisitos-pruebas.txt
  [ "${IDS_DEPS:-1}" = 0 ] && return 0
  [ -f "$req" ] || return 0
  # shellcheck disable=SC2086
  $PY -c 'import reportlab, PIL, chardet' >/dev/null 2>&1 && return 0
  # shellcheck disable=SC2086
  ver=$($PY -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  huella=$(sha256sum "$req" | cut -c1-12)
  dir="${IDS_DEPS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ids-maat-pruebas}/py$ver-$huella"
  if [ ! -f "$dir/.listo" ]; then
    if ! command -v docker >/dev/null 2>&1; then
      echo "   AVISO: faltan dependencias de las pruebas ($req) y no hay docker para instalarlas aparte" >&2
      return 0
    fi
    echo "   instalando $req en $dir (python:$ver-slim, pip --target)"
    rm -rf "$dir" && mkdir -p "$dir" || return 0
    if docker run --rm -v "$dir:/deps" -v "$PWD/$req:/req.txt:ro" "python:$ver-slim" \
         pip install -q --disable-pip-version-check --root-user-action=ignore --no-compile \
         --target /deps -r /req.txt; then
      touch "$dir/.listo"
    else
      echo "   AVISO: no se pudieron instalar las dependencias de las pruebas en $dir" >&2
      return 0
    fi
  fi
  export PYTHONPATH="$dir${PYTHONPATH:+:$PYTHONPATH}"
  echo "   (dependencias de las pruebas desde $dir)"
}
preparar_deps

# node para las pruebas del JavaScript del panel (QA T-11, 2026-11-14): sin node se omitían sin que
# nadie lo notara (la VPS no lo trae). Si falta y hay docker, un shim lo corre en un contenedor
# (IDS_NODE_IMAGEN, node:22-alpine por defecto) con el temporal y el repo montados en la misma ruta.
# IDS_NODE=0 lo desactiva. Las pruebas de JS son obligatorias en linux (tests/obligatorias.txt).
preparar_node() {
  local img dir tmp
  [ "${IDS_NODE:-1}" = 0 ] && return 0
  command -v node >/dev/null 2>&1 && return 0
  command -v docker >/dev/null 2>&1 || { echo "   AVISO: sin node ni docker: las pruebas de JS se omitirán" >&2; return 0; }
  img="${IDS_NODE_IMAGEN:-node:22-alpine}"
  if ! docker image inspect "$img" >/dev/null 2>&1 && ! docker pull -q "$img" >/dev/null 2>&1; then
    echo "   AVISO: no se pudo traer $img: las pruebas de JS se omitirán" >&2
    return 0
  fi
  tmp="${TMPDIR:-/tmp}"
  dir=$(mktemp -d "$tmp/ids-node-XXXXXX") || return 0
  cat > "$dir/node" <<EOF
#!/bin/sh
exec docker run --rm -i -v "$tmp:$tmp" -v "$PWD:$PWD" -w "\$PWD" "$img" node "\$@"
EOF
  chmod +x "$dir/node"
  export PATH="$dir:$PATH"
  echo "   (node de las pruebas en un contenedor: $img)"
}
preparar_node

FALLOS=0
OMITIDAS=0
PASADAS=0

echo "== unittest ($PY): tests/test_*.py y tests/legado/test_*.py, con las omisiones y su motivo"
# IDS_OBLIGATORIAS=linux|root: las de tests/obligatorias.txt no pueden omitirse.
# IDS_RESUMEN=<fichero>: resumen en Markdown (en GitHub Actions, $GITHUB_STEP_SUMMARY).
# IDS_PROCESOS=<n>: módulos en paralelo; por defecto los núcleos hasta 4 (la memoria), 1 = en serie.
ARGS_PY=()
[ -n "${IDS_OBLIGATORIAS:-}" ] && ARGS_PY+=(--obligatorias "$IDS_OBLIGATORIAS")
[ -n "${IDS_RESUMEN:-}" ] && ARGS_PY+=(--resumen "$IDS_RESUMEN")
[ -n "${IDS_PROCESOS:-}" ] && ARGS_PY+=(--procesos "$IDS_PROCESOS")
# IDS_TOPE_MEMORIA=<n>: tope de memoria de las pruebas en un cgroup propio (systemd-run --scope,
# como root); por defecto 3G, 0 = sin tope. El 2026-10-16 la suite agotó la memoria del VPS de
# producción y el kernel mató a Suricata; con el tope, un exceso mata la suite y no los servicios.
# OOMPolicy=continue: si el tope mata a un proceso de pruebas, systemd no para el scope entero (por
# defecto lo para, OOMPolicy=stop: el 2026-10-17 la corrida acabó en «Terminated» sin resumen) y
# correr.py repite en serie lo que quedaba y lo dice. Un systemd que no lo acepte se queda con el tope.
TOPE=()
if [ "${IDS_TOPE_MEMORIA:-3G}" != 0 ] && [ "$(id -u)" = 0 ] && command -v systemd-run >/dev/null 2>&1; then
  for oom in continue ""; do
    extra=()
    [ -n "$oom" ] && extra=(-p "OOMPolicy=$oom")
    if systemd-run --quiet --scope -p MemoryMax=64M ${extra[@]+"${extra[@]}"} true >/dev/null 2>&1; then
      TOPE=(systemd-run --quiet --scope -p "MemoryMax=${IDS_TOPE_MEMORIA:-3G}" -p MemorySwapMax=0
            ${extra[@]+"${extra[@]}"} --)
      echo "   (en un cgroup con MemoryMax=${IDS_TOPE_MEMORIA:-3G}${oom:+, OOMPolicy=$oom})"
      break
    fi
  done
fi
# shellcheck disable=SC2086
if ${TOPE[@]+"${TOPE[@]}"} $PY tests/correr.py "${ARGS_PY[@]}"; then
  PASADAS=$((PASADAS + 1))
else
  FALLOS=$((FALLOS + 1))
fi

# Un .sh omitido (77) dice su motivo en la última línea de su salida. Con
# IDS_SH_OBLIGATORIAS=1 (CI), un .sh omitido no cuenta como verificado: es un fallo.
resumen_sh() {   # resumen_sh <línea markdown>
  [ -n "${IDS_RESUMEN:-}" ] && printf '%s\n' "$1" >> "$IDS_RESUMEN"
  return 0
}
correr_sh() {
  local f rc salida motivo
  for f in "$@"; do
    [ -f "$f" ] || continue
    echo "== $f"
    salida=$(mktemp)
    bash "$f" 2>&1 | tee "$salida"
    rc=${PIPESTATUS[0]}
    motivo=$(grep -v '^[[:space:]]*$' "$salida" | tail -n 1)
    rm -f "$salida"
    case "$rc" in
      0) PASADAS=$((PASADAS + 1)); resumen_sh "- \`$f\`: bien" ;;
      77)
        if [ "${IDS_SH_OBLIGATORIAS:-0}" = 1 ]; then
          FALLOS=$((FALLOS + 1)); echo "   OMITIDA y obligatoria (NO verificada): $f: $motivo"
          resumen_sh "- \`$f\`: **omitida y obligatoria (no verificada)**: $motivo"
        else
          OMITIDAS=$((OMITIDAS + 1)); echo "   OMITIDA: $f: $motivo"
          resumen_sh "- \`$f\`: omitida: $motivo"
        fi ;;
      *) FALLOS=$((FALLOS + 1)); echo "   FALLO ($rc): $f"; resumen_sh "- \`$f\`: **fallo ($rc)**" ;;
    esac
  done
}

resumen_sh "### Pruebas de shell"
correr_sh tests/test_*.sh
[ "$IMAGENES" = 1 ] && correr_sh tests/imagen/test_*.sh
[ "$INTEGRACION" = 1 ] && correr_sh tests/integracion/test_*.sh

echo
echo "== resumen: $PASADAS bien, $OMITIDAS omitidas, $FALLOS con fallos"
[ "$FALLOS" -eq 0 ] || exit 1
exit 0
