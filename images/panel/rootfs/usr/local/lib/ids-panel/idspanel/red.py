"""Proxy inverso de confianza, IP real y comprobación de origen (CSRF).

El panel habla HTTP detrás de un proxy inverso externo que termina el TLS. SOLO si el par TCP
es una IP de IDS_PROXY se cree lo que dicen X-Forwarded-For/-Proto/-Host o Forwarded; si la
conexión viene de otro sitio (p. ej. el túnel SSH de emergencia), se ignoran y se usan la IP y el
Host reales (PLAN-PANEL §12).
"""

import ipaddress
import urllib.parse


def _ip(txt):
    txt = (txt or "").strip().strip('"')
    if txt.startswith("[") and "]" in txt:           # [2001:db8::1]:443
        txt = txt[1:txt.index("]")]
    elif txt.count(":") == 1:                          # 192.0.2.1:5555
        txt = txt.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(txt)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def es_proxy(peer, proxies):
    ip = _ip(peer)
    return bool(ip is not None and proxies and any(ip in red for red in proxies
                                                   if ip.version == red.version))


def _forwarded(valor):
    """Elementos de una cabecera Forwarded (RFC 7239) como lista de dicts."""
    out = []
    for elem in (valor or "").split(","):
        d = {}
        for par in elem.split(";"):
            k, _s, v = par.strip().partition("=")
            if k:
                d[k.strip().lower()] = v.strip().strip('"')
        if d:
            out.append(d)
    return out


class Origen:
    """Lo que el panel cree de una petición: IP real, protocolo y hosts públicos."""

    def __init__(self, headers, peer, proxies):
        self.headers = headers
        self.peer = peer
        self.de_proxy = es_proxy(peer, proxies)

    def _h(self, nombre):
        return (self.headers.get(nombre) or "").strip()

    @property
    def ip(self):
        if self.de_proxy:
            xff = [x for x in self._h("X-Forwarded-For").split(",") if x.strip()]
            if xff:
                ip = _ip(xff[-1])              # la que añadió nuestro proxy
                if ip is not None:
                    return str(ip)
            fw = _forwarded(self._h("Forwarded"))
            if fw and fw[-1].get("for"):
                ip = _ip(fw[-1]["for"])
                if ip is not None:
                    return str(ip)
        ip = _ip(self.peer)
        return str(ip) if ip is not None else str(self.peer)

    @property
    def https(self):
        if not self.de_proxy:
            return False
        proto = self._h("X-Forwarded-Proto").split(",")[0].strip().lower()
        if not proto:
            fw = _forwarded(self._h("Forwarded"))
            proto = (fw[0].get("proto", "") if fw else "").lower()
        return proto == "https"

    def hosts(self):
        """Host:puerto con los que se compara el Origin. X-Forwarded-Host/Forwarded solo del proxy."""
        out = [self._h("Host")]
        if self.de_proxy:
            out.append(self._h("X-Forwarded-Host").split(",")[0].strip())
            fw = _forwarded(self._h("Forwarded"))
            if fw:
                out.append(fw[0].get("host", ""))
        return [h for h in out if h]


def _host_puerto(valor):
    valor = (valor or "").strip().lower()
    if not valor:
        return None
    try:
        u = urllib.parse.urlsplit("//" + valor)
        return (u.hostname or "", u.port)
    except ValueError:
        return None


def origen_ajeno(headers, hosts):
    """"" si un POST viene de este mismo panel; si no, el motivo para rechazarlo (CSRF).

    Como el panel anterior (suricata-ids-lab):
    - Sec-Fetch-Site cross-site/same-site -> se rechaza; same-origin -> pasa.
    - Si hay Origin (o Referer), su host:puerto tiene que ser uno de `hosts` (Host real, y los
      del proxy solo si la conexión viene del proxy).
    - Origin "null" solo pasa con Sec-Fetch-Site none.
    - Sin Origin ni Referer pasa (no es un navegador); el token CSRF de la sesión sigue haciendo
      falta en todo POST autenticado.
    """
    org = (headers.get("Origin") or "").strip()
    ref = (headers.get("Referer") or "").strip()
    sfs = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if sfs in ("cross-site", "same-site"):
        return "Sec-Fetch-Site: %s" % sfs
    if sfs == "same-origin":
        return ""
    fuente = org or ref
    if not fuente:
        return ""
    if org.lower() == "null":
        if sfs == "none":
            return ""
        return "Origin: null"
    try:
        u = urllib.parse.urlsplit(fuente)
        h, p = (u.hostname or "").lower(), u.port
    except ValueError:
        return "origen ilegible"
    if u.scheme not in ("http", "https") or not h:
        return "origen no web"
    p = p or (443 if u.scheme == "https" else 80)
    for cand in hosts:
        hp = _host_puerto(cand)
        # un proxy (nginx $host) manda el nombre sin puerto: ahí cuenta el nombre
        if hp and hp[0] and hp[0] == h and (hp[1] is None or hp[1] == p):
            return ""
    return "origen %s://%s:%s distinto del panel" % (u.scheme, h, p)
