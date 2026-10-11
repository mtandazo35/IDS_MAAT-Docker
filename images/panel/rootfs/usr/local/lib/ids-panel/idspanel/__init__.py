"""ids-panel: panel web de IDS_MAAT-Docker (F1b). Solo stdlib de Python 3.11+.

Módulos:
  config     entorno (IDS_*) -> Config
  util       escritura atómica, JSON, fechas, escape
  usuarios   usuarios.json: PBKDF2-SHA256, crear/restablecer/cambiar clave
  sesiones   sesiones (sha256 del token), freno de login
  red        IP real tras el proxy de confianza, comprobación de origen (CSRF)
  orq        cliente del orquestador (socket JSON por líneas) y traducción de errores
  estado     lectura de estado.json y tzsp.json
  eve        últimas alertas de un punto y conteo de 24 h, leyendo el final del eve.json
  bitacora   bitacora.jsonl (quién hizo qué)
  vistas     HTML (todo dato pasa por esc())
  app        servidor HTTP y rutas
  cli        ids-panel servir | crear-admin | restablecer | salud

Importable en Windows: nada de AF_UNIX ni fcntl a nivel de módulo.
"""

VERSION = "0.1.0"
