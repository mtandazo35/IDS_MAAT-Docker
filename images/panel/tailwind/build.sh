#!/bin/sh
# Regenera rootfs/usr/local/share/ids-panel/tailwind.css (se COMMITEA: la imagen no necesita
# el CLI). Hace falta el CLI standalone de Tailwind v3.4.x:
#   https://github.com/tailwindlabs/tailwindcss/releases/tag/v3.4.17
# Uso: TAILWIND=/ruta/al/tailwindcss images/panel/tailwind/build.sh
set -eu
cd "$(dirname "$0")/.."
"${TAILWIND:-tailwindcss}" -c tailwind/tailwind.config.js -i tailwind/input.css \
  -o rootfs/usr/local/share/ids-panel/tailwind.css --minify
