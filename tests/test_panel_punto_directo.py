"""Punto «directo» en el panel (sin VPN, solo LAN; el user, 2026-10-18).

- El alta pregunta la conexión: por VPN (lo de siempre, mismos parámetros que antes) o directa con
  la IP del MikroTik en la red local; una IP pública o vacía se rechaza sin llamar al orquestador.
- «Conectado» en un punto directo = llega el espejo de su MikroTik (tzsp.visto_s < 2 min), no un
  cliente VPN: lista, salud por etapas, semáforo y selector de nodo.
- La ficha habla de la conexión directa (sin comandos de VPN, sin regenerar clave ni desbanear) y
  el final del alta no dice que «la clave no llegó».

Panel de verdad sobre un directorio temporal y orquestador falso (fixtures/panel2/_dash_p.py)."""
import json
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402

RE_TOKEN = r"name=op value='([0-9a-f-]{36})'"
COMANDOS_DIRECTO = ("# ids-maat p002 (sur) · N=2 · conexión directa (sin VPN, solo LAN) · MikroTik 192.168.88.1\n"
                    "#   sniff-target=192.168.88.10 sniff-target-port=37009\n")


class _Base(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        # el orquestador falso da los datos del espejo para el punto directo
        orq = self.p.orq

        def transporte(pet):
            if pet["orden"] == "punto.comandos" and (pet.get("params") or {}).get("pid") == "p002":
                orq.pedidas.append(pet)
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                        "datos": {"comandos": COMANDOS_DIRECTO, "clave_id": None}}
            return orq(pet)
        self.p.pw.TRANSPORTE = transporte

    def cambiar(self, pid, **campos):
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"][pid].update(campos)
        est["ts"] = int(time.time())
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + len(json.dumps(campos))
        os.utime(ruta, (t, t))

    def directo(self, visto_s=None, **extra):
        """p002 pasa a punto directo: contenedores sanos, sin cliente VPN; `visto_s` del espejo."""
        campos = {"modo": "directo", "mk_ip": "192.168.88.1", "sensor": "192.168.88.10", "mk": "192.168.88.1",
                  "tzsp_puerto": 37009, "puerto": 37009, "vpn_cliente": None,
                  "tzsp": {"edad_s": 5, "rx": 10 if visto_s is not None else 0,
                           "tx": 10 if visto_s is not None else 0, "rechazados": 0, "visto_s": visto_s}}
        campos.update(extra)
        self.cambiar("p002", **campos)

    def get(self, ruta):
        r = self.p.pedir("GET", ruta, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:400])
        return r.texto

    def fila(self, texto, pid):
        m = re.search(r"<tr><td><a href='/puntos/%s'>.*?</tr>" % pid, texto, re.S)
        self.assertIsNotNone(m, pid)
        return m.group(0)


class Alta(_Base):
    def token(self):
        return re.search(RE_TOKEN, self.get("/puntos/nuevo")).group(1)

    def test_el_alta_pregunta_la_conexion(self):
        h = self.get("/puntos/nuevo")
        self.assertIn("name=modo value=vpn checked", h)
        self.assertIn("name=modo value=directo", h)
        self.assertIn("name=mk_ip", h)
        lista = self.get("/puntos")                      # el modal: la IP oculta hasta elegir «Directa»
        self.assertIn("<div class=pmkip hidden>", lista)
        self.assertIn("f.modo.value='vpn';f.mk_ip.value='';paltaModo(f);", lista)
        self.assertIn("function paltaModo(f)", lista)

    def test_alta_directa_pide_punto_crear_con_modo_y_ip(self):
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": self.token(), "nombre": "lan", "modo": "directo",
                                                   "mk_ip": " 192.168.88.1 "}, cookie=self.ana)
        self.assertIn(r.status, (302, 303), r.texto[:300])
        self.assertEqual(self.p.orq.ordenes("punto.crear")[0]["params"],
                         {"nombre": "lan", "perfil": "reducido", "ros_version": 6, "modo": "directo",
                          "mk_ip": "192.168.88.1"})

    def test_alta_por_vpn_igual_que_antes(self):
        """Conservación: con «Por VPN» (o sin el campo) los parámetros no cambian; la IP se ignora."""
        self.p.pedir("POST", "/puntos/nuevo", {"op": self.token(), "nombre": "norte2", "modo": "vpn",
                                               "mk_ip": "192.168.88.1"}, cookie=self.ana)
        self.assertEqual(self.p.orq.ordenes("punto.crear")[0]["params"],
                         {"nombre": "norte2", "perfil": "reducido", "ros_version": 6})

    def test_ip_publica_vacia_o_mala_no_llega_al_orquestador(self):
        for ip, txt in (("8.8.8.8", "solo para la red local"), ("", "IP del MikroTik"),
                        ("192.168.88", "IP del MikroTik"), ("192.168.88.1/24", "IP del MikroTik")):
            with self.subTest(ip=ip):
                r = self.p.pedir("POST", "/puntos/nuevo", {"op": self.token(), "nombre": "lan", "modo": "directo",
                                                           "mk_ip": ip, "ajax": "1"}, cookie=self.ana)
                self.assertEqual(r.status, 400)
                self.assertIn(txt, json.loads(r.texto)["error"])
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": self.token(), "nombre": "lan", "modo": "lan",
                                                   "ajax": "1"}, cookie=self.ana)
        self.assertEqual(r.status, 400)
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])


class Conectado(_Base):
    def test_sin_espejo_esperando_y_con_espejo_conectado(self):
        self.directo(visto_s=None)
        fila = self.fila(self.get("/puntos"), "p002")
        self.assertIn("esperando MikroTik", fila)
        self.assertIn("esperando el espejo del MikroTik 192.168.88.1", fila)
        s = self.p.d.salud_punto("p002")
        self.assertEqual(s["estado"], "esperando")
        self.assertIn("esperando el espejo del MikroTik 192.168.88.1", s["motivo"])
        self.assertEqual(s["etapas"][0]["nombre"], "Espejo del MikroTik (directo)")
        self.assertNotIn("VPN", s["motivo"])
        # llega su espejo: conectado
        self.directo(visto_s=8)
        fila = self.fila(self.get("/puntos"), "p002")
        self.assertIn(">conectado<", fila)
        self.assertIn("llega el espejo del MikroTik 192.168.88.1", fila)
        self.assertTrue(self.p.d.salud_punto("p002")["etapas_por_id"]["vpn"]["ok"])
        # espejo viejo (más de 2 min): ya no cuenta como conectado
        self.directo(visto_s=600)
        self.assertIn("esperando MikroTik", self.fila(self.get("/puntos"), "p002"))

    def test_receptor_caido_no_dice_vpn(self):
        self.directo(visto_s=None, contenedores={"vpn": {"estado": "exited", "salud": "none"},
                                                 "suricata": {"estado": "running", "salud": "healthy"}})
        s = self.p.d.salud_punto("p002")
        self.assertEqual(s["estado"], "desconectada")
        self.assertEqual(self.p.pw.salud_texto(self.p.pw.salud(self.p.d.salud_punto, "p002")), "receptor caído")
        sel = re.search(r"class=nodosel>.*?</form>", self.get("/cuarentena?nodo=p002"), re.S).group(0)
        self.assertIn("sur (p002) &middot; receptor caído", sel)
        # un punto con VPN sigue diciendo «VPN caída»
        self.cambiar("p001", contenedores={"vpn": {"estado": "exited", "salud": "none"},
                                           "suricata": {"estado": "running", "salud": "healthy"}})
        self.assertEqual(self.p.pw.salud_texto(self.p.pw.salud(self.p.d.salud_punto, "p001")), "VPN caída")

    def test_semaforo(self):
        from idspanel import estado
        base = {"estado": "activo", "deseado": "activo", "modo": "directo",
                "contenedores": {"vpn": {"estado": "running", "salud": "healthy"},
                                 "suricata": {"estado": "running", "salud": "healthy"}}}
        self.assertEqual(estado.semaforo(dict(base, tzsp={"visto_s": 5})), "verde")
        self.assertEqual(estado.semaforo(dict(base, tzsp={"visto_s": None})), "ambar")
        self.assertEqual(estado.semaforo(dict(base, tzsp={"visto_s": 300})), "ambar")


class Ficha(_Base):
    def test_ficha_de_un_punto_directo(self):
        self.directo(visto_s=8)
        h = self.get("/puntos/p002")
        self.assertIn("<h2>Conexión directa: datos para el MikroTik</h2>", h)
        self.assertIn("sniff-target=192.168.88.10 sniff-target-port=37009", h)
        self.assertIn("a 192.168.88.10:37009/udp · solo desde 192.168.88.1", h)
        self.assertIn("la red local directa a 192.168.88.1", h)
        self.assertIn("<a href='#vpn'>Conexión</a>", h)
        for nada in ("Regenerar la clave VPN", "/puntos/p002/desbanear", "Puerto VPN / red del túnel",
                     "VPN: comandos para el MikroTik", "&lt;CLAVE-VPN&gt;"):
            self.assertNotIn(nada, h)
        # la ficha de un punto con VPN no cambia
        h1 = self.get("/puntos/p001")
        self.assertIn("VPN: comandos para el MikroTik", h1)
        self.assertIn("Regenerar la clave VPN", h1)
        self.assertIn("Puerto VPN / red del túnel", h1)

    def test_fin_del_alta_sin_clave_que_no_llego(self):
        pw = self.p.pw
        self.assertIsNone(pw._entrega_clave("punto.crear", "OK", {"pid": "p002", "modo": "directo"}))
        self.assertEqual(pw._entrega_clave("punto.crear", "OK", {"pid": "p001"}), "no_llego")
        self.directo(visto_s=None)
        txt = pw._cuerpo_fin(self.p.d, {"orden": "punto.crear", "ok": True, "pid": "p002",
                                        "resultado": {"pid": "p002", "modo": "directo",
                                                      "comandos": COMANDOS_DIRECTO}})
        self.assertIn("punto directo, sin VPN", txt)
        self.assertIn("sniff-target-port=37009", txt)
        self.assertNotIn("clave", txt.lower().replace("clave de la vpn", ""))
        # una visita posterior (sin el resultado) tampoco habla de la clave
        txt = pw._cuerpo_fin(self.p.d, {"orden": "punto.crear", "ok": True, "pid": "p002"})
        self.assertIn("punto directo, sin VPN", txt)
        self.assertNotIn("La clave no llegó", txt)


if __name__ == "__main__":
    unittest.main()
