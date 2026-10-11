#!/bin/bash
# ids-maat — runner de pruebas (CONTRATO-F1a §8.1). Sin lista que mantener: descubre todo.
#   tests/run.sh [--imagenes] [--integracion]
#   1. python -m unittest discover -s tests -p "test_*.py"   (python3, python o "py -3")
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
FALLOS=0
OMITIDAS=0
PASADAS=0

echo "== unittest ($PY)"
# shellcheck disable=SC2086
if $PY -m unittest discover -s tests -p "test_*.py"; then
  PASADAS=$((PASADAS + 1))
else
  FALLOS=$((FALLOS + 1))
fi

correr_sh() {
  local f rc
  for f in "$@"; do
    [ -f "$f" ] || continue
    echo "== $f"
    bash "$f"
    rc=$?
    case "$rc" in
      0) PASADAS=$((PASADAS + 1)) ;;
      77) OMITIDAS=$((OMITIDAS + 1)); echo "   OMITIDA: $f" ;;
      *) FALLOS=$((FALLOS + 1)); echo "   FALLO ($rc): $f" ;;
    esac
  done
}

correr_sh tests/test_*.sh
[ "$IMAGENES" = 1 ] && correr_sh tests/imagen/test_*.sh
[ "$INTEGRACION" = 1 ] && correr_sh tests/integracion/test_*.sh

echo
echo "== resumen: $PASADAS bien, $OMITIDAS omitidas, $FALLOS con fallos"
[ "$FALLOS" -eq 0 ] || exit 1
exit 0
