# Actualizaciones y CI

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- las imágenes y cómo se construyen;
- la firma y su verificación;
- el botón «Actualizar» y la reversión;
- el mantenimiento por CVE.

Las reglas ET y los feeds se actualizan aparte ([INSTANCIA.md](INSTANCIA.md) §11).

## 1. Imágenes

| Imagen | Contiene |
|---|---|
| `ghcr.io/<owner>/ids-maat-panel` | el panel; los servicios `web` y `worker` de compose usan la misma imagen sin s6. Incluye los assets (mapa, GeoIP: DB-IP lite fijada por commit y SHA256 en `geo_base.py`; el panel la renueva cada 30 días en `/srv/ids/panel/geo`) y `cryptography` instalado con `--require-hashes` |
| `ghcr.io/<owner>/ids-maat-vpn` | s6-overlay v3, OpenVPN, `tzsp-decap`, socat, nft, `ovpn-auth`, `salud-vpn` |
| `ghcr.io/<owner>/ids-maat-suricata` | Suricata del paquete de Debian (versión en `LABEL`), plantilla de `suricata.yaml`, `local.rules`, suricata-update |

- **Bases fijadas por digest** (`debian:trixie-slim@sha256:…`).
- **Etiquetas:** `1.4.0` y `sha-abc1234`. **La producción nunca usa `latest` ni etiquetas**: los
  compose llevan `image: …@sha256:<digest>`.
- **Paquetes públicos.** Los paquetes de GHCR nacen privados aunque el repositorio sea público.
  Hay que hacerlos públicos **una vez**, en los ajustes de cada paquete. Así el VPS descarga sin
  credenciales y no se guarda ningún PAT en los servidores.
  - La API REST de GitHub no permite cambiar la visibilidad de un paquete de una cuenta de
    usuario: es un paso manual en la web, tras la primera release que publica cada imagen.
    Para `ids-maat-panel`, `ids-maat-vpn` e `ids-maat-suricata`:
    `https://github.com/users/<owner>/packages/container/ids-maat-<img>/settings` →
    *Danger Zone* → *Change visibility* → *Public*.
  - El job `visibilidad` de `release.yml` pide cada manifiesto **sin credenciales** y falla (con
    el enlace en el aviso) mientras alguno siga privado. La release ya está publicada: basta con
    cambiar la visibilidad y relanzar el job.
  - Si se instala con un paquete todavía privado, `install.sh` se para con «el paquete … es
    privado» y el mismo enlace.

## 2. GitHub Actions

Hay dos workflows:

- **`ci.yml`**, en cada push y PR, **solo lint** (desde 2026-10-15, decisión del dueño):
  pyflakes, shellcheck, `bash -n`, la comprobación `eol=lf`, `tailwind.css` al día, la sintaxis
  YAML y `nft -c`. Las pruebas de comportamiento, las de imagen y la integración se corren en la VPS.
- **`release.yml`**, que **solo se dispara con etiquetas `v*`**:

```yaml
on: { push: { tags: ["v*"] } }
permissions: { contents: write, packages: write, id-token: write, attestations: write }
jobs:
  ci-verde:  # exige un ci.yml en verde para el commit etiquetado (no lo repite)
  imagen:
    needs: ci-verde
    strategy: { matrix: { img: [panel, vpn, suricata] } }
    steps:   # checkout, login GHCR, metadata (semver + sha-), build-push (provenance, sbom),
             # cosign sign --yes ghcr.io/<owner>/ids-maat-<img>@<digest>
  release:   # release.json = {version, imagenes:{panel,vpn,suricata: digest}, min_orq, migraciones}
             # cosign sign-blob --bundle release.json.bundle; adjuntos a la GitHub Release
```

- **Acciones fijadas por SHA de commit.**
- **Renovate o Dependabot** abren PR para las bases, las acciones y las dependencias Python.
- **Reconstrucción semanal por CVE.** Un workflow programado reconstruye con las bases al día. Si
  el escáner (Trivy o Grype) encuentra un CVE corregible alto o crítico, se publica una release de
  parche: se sube el último número (`v1.4.2` → `v1.4.3`). Nada de sufijos con `+`, que las
  etiquetas de imagen no admiten.

## 3. Verificación en el VPS

El orquestador verifica antes de descargar nada.

```sh
ID='^https://github\.com/<owner>/IDS_MAAT-Docker/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
ISS='https://token.actions.githubusercontent.com'
cosign verify-blob --bundle release.json.bundle \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" release.json
cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" \
  ghcr.io/<owner>/ids-maat-panel@sha256:<digest>      # y vpn, suricata
```

- **`cosign`** lo instala el instalador, con su sha256 verificado.
- **Lista blanca:** solo se aceptan las imágenes `ids-maat-{panel,vpn,suricata}`.
- **Salidas que necesita el orquestador:**
  - `ghcr.io`;
  - `github.com` y `objects.githubusercontent.com`, para la release;
  - la infraestructura de sigstore (`*.sigstore.dev`, TUF, Rekor), para la verificación keyless.

## 4. Botón «Actualizar»

`panel → orq: sistema.actualizar {version, canario}`. La orden retiene la cola del orquestador
mientras dura.

1. **Verificar las firmas** (§3).
2. **`docker pull` de todos los digests** antes de parar nada. El orquestador también extrae la
   plantilla de `suricata.yaml` de la versión nueva y renderiza los yaml de los puntos.
3. **Respaldo verificado** en `/root/backups/ids-maat-<ts>.tar.gz` (0600):
   - qué incluye: `estado.db`, `bitacora.db` y `orq.db` con `setpriv`, la PKI, `/srv/ids/puntos` y
     el firewall; `eventos.db` va aparte y es opcional;
   - cómo se verifica: `tar -tzf` y sha256;
   - **si falla, se aborta**;
   - si el proveedor lo permite, también un snapshot del VPS.
4. **Panel primero** (servicios `web` y `worker`):
   - el `web` nuevo migra el esquema al arrancar y tiene que responder `/salud` con
     `{ok, schema_version, version}` antes de 120 s;
   - si no lo hace, se vuelve al digest anterior y, si hubo migración, se restaura `estado.db` del
     respaldo;
   - mientras se recrea, el panel muestra «reconectando», porque la orden la ejecuta el
     orquestador.
5. **Canario:** se recrea el punto elegido y debe cumplir durante 10 min:
   - contenedores sanos y netns coherentes;
   - el eve crece;
   - `host == pid`;
   - el TZSP llega;
   - `drops_pct` no empeora más de 2 puntos.

   Si falla, se revierte y se para.
6. **El resto, de uno en uno.** El `vpn` solo se recrea si cambió su digest; el MikroTik reconecta
   en segundos. Cada punto tiene 3 min de comprobación y, si falla, se revierte solo ese.
7. **[B] ACTUALIZACION**, con origen, destino, quién la lanzó, resultado por componente y ruta del
   respaldo.

No hay actualización automática: la lanza siempre una persona.

## 5. Reversión y migraciones

- **Instancias (`vpn` y `suricata`).** No guardan esquema. «Volver a la versión anterior» recrea
  con los digests previos de `orq.db` y está disponible **30 días**. Las imágenes previas no se
  borran hasta la siguiente actualización buena.
- **Panel.** Las migraciones **solo avanzan**:
  - si la versión nueva no migró el esquema, volver al digest anterior es inmediato;
  - si migró, volver atrás **exige restaurar `estado.db` del respaldo de esa actualización**, y se
    pierde lo cambiado desde entonces. El panel lo dice antes de confirmar y no lo ofrece pasados
    los 30 días.
- **`sistema.revertir {objetivo, pid?}`** aplica lo anterior: al panel, a un punto o a todo.

## 6. El orquestador

El orquestador **no se actualiza desde el panel**. Lo actualiza `/root/ids-maat/actualizar-orquestador.sh`:

1. respaldo;
2. verificación de la firma del fichero de la release;
3. sustitución;
4. `systemctl restart ids-orq`;
5. prueba del socket;
6. si falla, reversión.

`release.json` declara `min_orq`. Si el orquestador instalado es más viejo, el panel avisa y no
ofrece esa versión.
