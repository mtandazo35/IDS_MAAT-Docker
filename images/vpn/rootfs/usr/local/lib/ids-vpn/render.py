#!/usr/bin/env python3
"""render.py: valida el entorno del contenedor `vpn` y genera sus tablas nft.

Uso (lo llaman los oneshot de s6, CONTRATO-F1a §5.1):

    render.py validar      valida las variables de §4.1; sale con 1 y un mensaje si falla
    render.py nft-punto    imprime la tabla `inet ids_punto` (§4.7)
    render.py nft-mon      imprime la tabla `netdev ids_mon` (§4.7)

Solo stdlib. Importable en Windows: no hace nada al importarse.
"""
import ipaddress
import os
import re
import sys

RE_PUNTO = re.compile(r"p\d{3}")
RE_ENTERO = re.compile(r"0|[1-9][0-9]*")


class ErrorEntorno(ValueError):
    """Una variable de entorno no cumple §4.1."""


def _entero(env, nombre, minimo, maximo=None):
    valor = env.get(nombre, "")
    if not RE_ENTERO.fullmatch(valor):
        raise ErrorEntorno(f"{nombre}={valor!r} no es un entero")
    n = int(valor)
    if n < minimo or (maximo is not None and n > maximo):
        rango = f"{minimo}-{maximo}" if maximo is not None else f">= {minimo}"
        raise ErrorEntorno(f"{nombre}={valor!r} fuera de rango ({rango})")
    return n


def _ipv4(env, nombre):
    valor = env.get(nombre, "")
    try:
        ip = ipaddress.IPv4Address(valor)
    except ValueError:
        raise ErrorEntorno(f"{nombre}={valor!r} no es una IPv4") from None
    if str(ip) != valor:
        raise ErrorEntorno(f"{nombre}={valor!r} no está en forma canónica")
    return ip


def validar(env):
    """Valida el entorno (§4.1) y devuelve un dict con los valores ya tipados.

    Lanza ErrorEntorno con un mensaje claro en la primera variable que falla."""
    punto = env.get("PUNTO", "")
    if not RE_PUNTO.fullmatch(punto):
        raise ErrorEntorno(f"PUNTO={punto!r} no cumple ^p\\d{{3}}$")

    n = _entero(env, "N", 1, 250)

    tun_net_txt = env.get("TUN_NET", "")
    try:
        tun_net = ipaddress.IPv4Network(tun_net_txt, strict=True)
    except ValueError:
        raise ErrorEntorno(f"TUN_NET={tun_net_txt!r} no es una red IPv4 válida") from None
    if tun_net.prefixlen != 24 or "/" not in tun_net_txt or str(tun_net) != tun_net_txt:
        raise ErrorEntorno(f"TUN_NET={tun_net_txt!r} debe ser un CIDR /24 (p. ej. 100.64.3.0/24)")

    sensor = _ipv4(env, "TUN_SENSOR")
    if sensor != tun_net.network_address + 1:
        raise ErrorEntorno(f"TUN_SENSOR={sensor} no es la .1 de TUN_NET={tun_net}")

    mk = _ipv4(env, "TUN_MK")
    if mk != tun_net.network_address + 2:
        raise ErrorEntorno(f"TUN_MK={mk} no es la .2 de TUN_NET={tun_net}")

    api_txt = env.get("API_PUERTO", "")
    if api_txt not in ("8729", "8728"):
        raise ErrorEntorno(f"API_PUERTO={api_txt!r} debe ser 8729 o 8728")

    tzsp_puerto = _entero(env, "TZSP_PUERTO", 1, 65535)
    tzsp_bytes = _entero(env, "TZSP_BYTES", 0)

    return {
        "punto": punto,
        "n": n,
        "tun_net": tun_net,
        "tun_sensor": sensor,
        "tun_mk": mk,
        "api_puerto": int(api_txt),
        "tzsp_puerto": tzsp_puerto,
        "tzsp_bytes": tzsp_bytes,
    }


def nft_punto(cfg):
    """Texto exacto de la tabla `inet ids_punto` (§4.7). Nunca `flush ruleset`."""
    mk = cfg["tun_mk"]
    return (
        "table inet ids_punto\n"
        "delete table inet ids_punto\n"
        "table inet ids_punto {\n"
        "  chain input {\n"
        "    type filter hook input priority filter; policy drop;\n"
        "    iif lo accept\n"
        "    ct state established,related accept\n"
        '    iifname "eth0" tcp dport 1194 accept comment "OpenVPN (DNAT del host)"\n'
        f'    iifname "tun0" ip saddr {mk} udp dport {cfg["tzsp_puerto"]} counter accept comment "espejo TZSP"\n'
        # ping del MikroTik del punto al sensor (el user, 2026-10-15: para comprobar el tunel);
        # solo echo-request y desde su IP del tunel, con tope. La respuesta sale por established.
        f'    iifname "tun0" ip saddr {mk} icmp type echo-request limit rate 5/second accept comment "ping del MikroTik"\n'
        '    counter comment "resto"\n'
        "  }\n"
        "  chain output {\n"
        "    type filter hook output priority filter; policy drop;\n"
        "    oif lo accept\n"
        "    ct state established,related accept\n"
        f'    oifname "tun0" ip daddr {mk} tcp dport {cfg["api_puerto"]} accept comment "API via rele"\n'
        '    counter comment "resto"\n'
        "  }\n"
        "  chain forward { type filter hook forward priority filter; policy drop; }\n"
        "}\n"
    )


def nft_mon():
    """Texto exacto de la tabla `netdev ids_mon` (§4.7): descarta lo inyectado en ids-mon."""
    return (
        "table netdev ids_mon\n"
        "delete table netdev ids_mon\n"
        "table netdev ids_mon {\n"
        '  chain ingreso { type filter hook ingress device "ids-mon" priority -500; policy drop; }\n'
        "}\n"
    )


def main(argv=None, env=None, salida=None, errores=None):
    argv = sys.argv[1:] if argv is None else argv
    env = os.environ if env is None else env
    salida = sys.stdout if salida is None else salida
    errores = sys.stderr if errores is None else errores

    if len(argv) != 1 or argv[0] not in ("validar", "nft-punto", "nft-mon"):
        print("uso: render.py validar|nft-punto|nft-mon", file=errores)
        return 2
    orden = argv[0]
    try:
        cfg = validar(env)
    except ErrorEntorno as e:
        print(f"render.py: entorno inválido: {e}", file=errores)
        return 1
    if orden == "validar":
        print(f"render.py: entorno válido para {cfg['punto']} (N={cfg['n']}, túnel {cfg['tun_net']})",
              file=errores)
    elif orden == "nft-punto":
        salida.write(nft_punto(cfg))
    else:
        salida.write(nft_mon())
    salida.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
