"""La clave de la VPN de cada punto la guarda el panel CIFRADA y la ficha da los comandos con ella
puesta (el user, 2026-10-15: copió los comandos de la ficha, que traían <CLAVE-VPN>, y el MikroTik
se quedó con ese texto de clave y no conectaba).

- Regenerar (y el alta) guardan la clave entregada, cifrada con la clave maestra; nunca en claro.
- La página de regenerar da la orden `/interface ovpn-client set ... password=<clave>` lista.
- La ficha pone la clave en los comandos (v7 y v6) solo si el usuario de los comandos es el de la
  clave guardada, y se sirve con cabeceras privadas (no-store).
- Sin clave guardada, la ficha lo dice y ofrece regenerarla.
- La baja del punto la borra.

Tipo «corrección de defecto»: fallan sin el arreglo. Panel de verdad sobre un directorio temporal y
orquestador falso (fixtures/panel2/_dash_p.py), sin red.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_panel_puntos_estados as _tpe  # noqa: E402

CLAVE = "Kq3ZtV9xLm2Pw7Rb4Ns8Yc1D"
COMANDOS = ("# ids-maat p001 (norte)\n#\n"
            "# --- RouterOS v7 ---\n"
            "/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1194 protocol=tcp mode=ip \\\n"
            "    user=vpn7ad2d8 password=<CLAVE-VPN> cipher=aes256-gcm auth=sha1 verify-server-certificate=yes \\\n"
            "    add-default-route=no use-peer-dns=no disabled=no\n"
            "#\n# --- RouterOS v6 (6.49 o superior) ---\n"
            "/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1194 mode=ip \\\n"
            "    user=vpn7ad2d8 password=<CLAVE-VPN> cipher=aes256 auth=sha1 verify-server-certificate=yes \\\n"
            "    add-default-route=no disabled=no\n")


class ClaveVpn(_tpe._Base):
    encolar = _tpe.Operacion.encolar

    def setUp(self):
        super().setUp()
        real = self.p.orq
        self.cid = "huella-1"          # la huella de la clave vigente que da el orquestador
        self.entrega = True            # si el resultado de regenerar trae la clave
        self.orq_con_clave = False     # el orquestador la guarda cifrada y da los comandos completos (2026-10-16)

        def transporte(pet):
            if pet["orden"] == "punto.comandos":
                real.pedidas.append(pet)
                datos = {"comandos": COMANDOS, "clave_id": self.cid}
                if self.orq_con_clave:
                    datos.update(comandos=COMANDOS.replace("<CLAVE-VPN>", CLAVE), clave=CLAVE)
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "", "datos": datos}
            if pet["orden"] == "op.estado" and real.ops.get((pet.get("params") or {}).get("op_id")) == \
                    "punto.vpn.regenerar":
                real.pedidas.append(pet)
                res = {"pid": "p001", "usuario": "vpn7ad2d8", "clave_id": self.cid}
                if self.entrega:
                    res.update(clave=CLAVE, comandos=COMANDOS.replace("<CLAVE-VPN>", CLAVE))
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                        "datos": {"estado": "terminada", "codigo": "OK", "mensaje": "credencial regenerada",
                                  "avance": "3/3", "pasos": [{"nombre": "usuarios", "estado": "ok"}],
                                  "resultado": res}}
            return real(pet)
        self.p.pw.TRANSPORTE = transporte

    def ruta_claves(self):
        return self.p.nodos.ruta("conf", "vpn-claves.json")

    def regenerar(self):
        url = self.encolar("regenerar")
        return self.get(url)

    def test_sin_clave_guardada_la_ficha_lo_dice_y_ofrece_regenerar(self):
        h = self.get("/puntos/p001")
        self.assertIn("El panel no tiene la clave vigente de la VPN", h)
        self.assertIn("password=&lt;CLAVE-VPN&gt;", h)
        self.assertRegex(h, r"<form method=post action='/puntos/p001/regenerar' onsubmit=\"return ask\(this,"
                            r"'Regenerar la clave VPN'")

    def test_regenerar_guarda_cifrada_y_da_la_orden_lista(self):
        h = self.regenerar()
        self.assertIn("/interface ovpn-client set [find name=ids-vpn] password=%s verify-server-certificate=yes disabled=no" % CLAVE, h)
        with open(self.ruta_claves(), encoding="utf-8") as f:
            texto = f.read()
        self.assertNotIn(CLAVE, texto)                      # nunca en claro
        g = json.loads(texto)["puntos"]["p001"]
        self.assertEqual(g["usuario"], "vpn7ad2d8")
        self.assertTrue(g["clave"].startswith("enc1:"), g)
        self.assertEqual(self.p.pw.clave_vpn("p001"), ("vpn7ad2d8", CLAVE))
        if os.name == "posix":
            self.assertEqual(os.stat(self.ruta_claves()).st_mode & 0o777, 0o600)

    def test_la_ficha_da_los_comandos_con_la_clave_puesta(self):
        self.regenerar()
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertEqual(r.status, 200)
        h = r.texto
        self.assertNotIn("&lt;CLAVE-VPN&gt;", h)
        self.assertEqual(h.count("user=vpn7ad2d8 password=%s " % CLAVE), 2)     # v7 y v6
        self.assertIn("/interface ovpn-client set [find name=ids-vpn] password=%s verify-server-certificate=yes disabled=no" % CLAVE, h)
        self.assertNotIn("El panel no tiene la clave vigente", h)
        self.assertEqual(r.cab("Cache-Control"), "no-store")

    def test_con_los_comandos_completos_del_orquestador_no_pide_regenerar(self):
        """Corrección de defecto (el user, 2026-10-16: «no le pones la clave a la vpn y toca generar la
        clave para que funcione»): el orquestador guarda la clave cifrada y da los comandos ya con ella.
        Sin copia en el panel, la ficha los da tal cual, con la orden corta, y sin «Regenerar»."""
        self.orq_con_clave = True
        self.assertFalse(os.path.exists(self.ruta_claves()))
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        h = r.texto
        self.assertEqual(h.count("user=vpn7ad2d8 password=%s " % CLAVE), 2)
        self.assertIn("/interface ovpn-client set [find name=ids-vpn] password=%s verify-server-certificate=yes disabled=no" % CLAVE, h)
        self.assertNotIn("El panel no tiene la clave vigente", h)
        self.assertNotIn("&lt;CLAVE-VPN&gt;", h)
        self.assertEqual(r.cab("Cache-Control"), "no-store")

    def test_con_otro_usuario_no_pone_una_clave_que_no_es_suya(self):
        self.p.pw.guardar_clave_vpn("p001", "vpnOTRO", CLAVE, self.cid)
        h = self.get("/puntos/p001")
        self.assertNotIn(CLAVE, h)
        self.assertIn("El panel no tiene la clave vigente de la VPN", h)

    def test_regenerada_por_la_consola_no_da_la_vieja_como_buena(self):
        """Revisión 2026-10-15 (hallazgo 1): `ids-orq punto vpn-regenerar` conserva el usuario; la
        huella de la clave vigente cambia y la ficha deja de poner la guardada."""
        self.regenerar()
        self.cid = "huella-2"
        h = self.get("/puntos/p001")
        self.assertNotIn(CLAVE, h)
        self.assertIn("El panel no tiene la clave vigente de la VPN", h)
        self.assertIn("password=&lt;CLAVE-VPN&gt;", h)

    def test_regenerada_sin_entrega_olvida_la_guardada(self):
        """Revisión 2026-10-15 (hallazgo 1): regenerar terminó OK pero la clave no llegó al panel."""
        self.regenerar()
        self.entrega = False
        self.cid = "huella-1"                     # aunque la huella no se distinga, se olvida
        self.regenerar()
        self.assertIsNone(self.p.pw.clave_vpn("p001"))
        self.assertNotIn(CLAVE, self.get("/puntos/p001"))

    def test_el_alta_tambien_la_guarda(self):
        """punto.crear (orquestador falso del banco: p003, ids-p003, CLAVE-VPN-UNICA-7Q2)."""
        tok = __import__("re").search(_tpe.RE_TOKEN, self.get("/puntos/nuevo")).group(1)
        self.p.pw.TRANSPORTE = self.p.orq                     # el alta la contesta el falso del banco
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "este", "redes": "10.1.0.0/24",
                                                   "ros_version": "7", "perfil": "reducido"}, cookie=self.ana)
        h = self.get(r.cab("Location"))
        self.assertIn("La clave de la VPN ya va puesta en los comandos", h)
        self.assertEqual(self.p.pw.clave_vpn("p003"), ("ids-p003", "CLAVE-VPN-UNICA-7Q2"))

    def test_si_el_disco_falla_la_clave_se_sigue_mostrando(self):
        """Revisión 2026-10-15 (hallazgo 2): un OSError al guardar no tumba la página (antes, 500 y
        la clave de un solo uso perdida)."""
        def roto(_todo):
            raise OSError(28, "No space left on device")
        self.p.pw._escribir_vpn_claves = roto
        h = self.regenerar()
        self.assertIn(CLAVE, h)
        self.assertIn("el panel no la pudo guardar", h)
        self.assertIsNone(self.p.pw.clave_vpn("p001"))

    def test_un_fichero_corrupto_se_aparta_y_no_se_pisa_en_silencio(self):
        """Revisión 2026-10-15 (hallazgo 3)."""
        os.makedirs(os.path.dirname(self.ruta_claves()), exist_ok=True)
        with open(self.ruta_claves(), "w", encoding="utf-8") as f:
            f.write("{roto")
        self.assertTrue(self.p.pw.guardar_clave_vpn("p001", "vpn7ad2d8", CLAVE, self.cid))
        apartados = [x for x in os.listdir(os.path.dirname(self.ruta_claves()))
                     if x.startswith("vpn-claves.json.corrupto-")]
        self.assertEqual(len(apartados), 1)
        self.assertEqual(self.p.pw.clave_vpn("p001", self.cid), ("vpn7ad2d8", CLAVE))

    def test_la_baja_la_borra(self):
        self.regenerar()
        self.assertTrue(self.p.pw.limpiar_punto(self.p.d, "p001"))
        self.assertIsNone(self.p.pw.clave_vpn("p001"))
        with open(self.ruta_claves(), encoding="utf-8") as f:
            self.assertNotIn("p001", json.load(f)["puntos"])

    def test_sin_clave_maestra_no_guarda_nada(self):
        os.environ["IDS_MASTER_KEY"] = os.path.join(self.p.tmp.name, "no-existe")
        self.addCleanup(os.environ.__setitem__, "IDS_MASTER_KEY",
                        os.path.join(self.p.tmp.name, "secretos", "master_key"))
        self.assertFalse(self.p.pw.guardar_clave_vpn("p001", "vpn7ad2d8", CLAVE))
        self.assertFalse(os.path.exists(self.ruta_claves()))


if __name__ == "__main__":
    unittest.main()
