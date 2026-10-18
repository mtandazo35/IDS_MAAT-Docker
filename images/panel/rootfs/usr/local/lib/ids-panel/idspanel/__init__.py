"""ids-panel: piezas del panel de IDS_MAAT-Docker que el dashboard heredado reutiliza (F2).

Módulos:
  config       entorno (IDS_*) -> Config
  util         escritura atómica, JSON, fechas, escape
  orq          cliente del orquestador (socket JSON por líneas) y traducción de errores
  estado       lectura de estado.json y tzsp.json
  operaciones  operaciones en curso del orquestador (op_id), para /operaciones/<op_id>
  cli          ids-panel servir | crear-admin | restablecer | salud

El servidor y las pantallas son dashboard.py (y puntos_web.py, eventos_web.py) en el directorio
padre. El panel mínimo de F1b (app, vistas, sesiones, usuarios, red, eve, bitacora, static) se
retiró en F2 (CONTRATO-F2-panel.md).

Importable en Windows: nada de AF_UNIX ni fcntl a nivel de módulo.
"""

VERSION = "0.1.9"
