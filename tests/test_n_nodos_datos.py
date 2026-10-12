"""Núcleo del panel (N): datos por nodo y vista «Todos» (CONTRATO-F2 §3, §10.1, §10.5).

Árbol de _dash: p001 y p002 con la MISMA IP 10.0.0.5 y el MISMO flujo de alertas.
"""
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()


class Importacion(Base):
    def test_importar_no_escribe_nada(self):
        """Tipo: capacidad nueva. Importar el modulo no crea ni toca ningun fichero (ni
        dentro del arbol: todo lo que escribe lo hace al arrancar o al usarse)."""
        antes = self.a.foto()
        _dash.cargar(self.a)
        self.assertEqual(self.a.foto(), antes)

    def test_rutas_dentro_del_arbol(self):
        """Tipo: corrección de defecto. Las rutas del heredado (/etc, /var/log, /root...)
        pasan a PANEL; ninguna constante de fichero apunta fuera del arbol."""
        for nombre in ("SESSIONS_FILE", "LOGIN_LOG", "EXCL_FILE", "CONF", "MK_CONF", "MK_SENT",
                       "MK_SENT_DNS", "MK_LOG", "ROUTERS_CONF", "BITACORA_LOG", "ACCIONES_FILE",
                       "USERS_FILE", "FEEDS_CONF", "FEEDS_META", "AIDB_CACHE", "PUBLICAS_CONF",
                       "EMPRESA_FILE", "TRUST_FILE", "REPORT_CONF", "RESPALDOS_MK", "_GEOIP_BIN2"):
            ruta = getattr(self.d, nombre)
            self.assertTrue(os.path.abspath(ruta).startswith(os.path.abspath(self.tmp.name)),
                            "%s = %s" % (nombre, ruta))
        for viejo in ("LOGDIR", "EVE", "THRESHOLD_FILE", "router_defecto", "rid_por_iface",
                      "chequear_update", "ovpn_estado", "mkinit_correr", "sensor_modo",
                      "_systemctl_env", "_suricatasc", "_svc_activo", "save_conf", "ip_del_sensor"):
            self.assertFalse(hasattr(self.d, viejo), viejo)


class Aislamiento(Base):
    def test_en_vivo_por_nodo_y_todos(self):
        """Tipo: capacidad nueva (caso obligatorio «misma IP y mismo flujo en dos puntos»).
        Con un nodo elegido solo salen sus eventos; en «Todos» la IP repetida sale en DOS
        filas, una por punto, sin sumar."""
        with self.n.contexto("p001"):
            f1 = self.d.tail_grupos()
        with self.n.contexto("p002"):
            f2 = self.d.tail_grupos()
        with self.n.contexto(self.n.TODOS):
            ft = self.d.tail_grupos()
        self.assertEqual([(r[1], r[5], r[6]) for r in f1], [(_dash.IP, 3, "p001")])
        self.assertEqual([(r[1], r[5], r[6]) for r in f2], [(_dash.IP, 3, "p002")])
        self.assertEqual(sorted((r[1], r[5], r[6]) for r in ft),
                         [(_dash.IP, 3, "p001"), (_dash.IP, 3, "p002")])

    def test_top_origenes_identidad_pid_ip(self):
        """Tipo: capacidad nueva. El Top de «Todos» trata (pid, IP) como origen: dos
        entradas de 3 alertas, no una de 6."""
        with self.n.contexto(self.n.TODOS):
            filas, procesados = self.d.top_origenes()
        self.assertEqual(procesados, 6)
        self.assertEqual(sorted((f["pid"], f["src"], f["total"]) for f in filas),
                         [("p001", _dash.IP, 3), ("p002", _dash.IP, 3)])
        with self.n.contexto("p002"):
            filas, _ = self.d.top_origenes()
        self.assertEqual([(f["pid"], f["total"]) for f in filas], [("p002", 3)])

    def test_historial_y_conducta_por_nodo(self):
        """Tipo: capacidad nueva. Una base por punto en nodos/<pid>/; en «Todos» se unen
        las filas con su campo nodo, sin fusionar la IP repetida."""
        for pid in ("p001", "p002"):
            with self.n.contexto(pid):
                self.assertEqual(self.d.hist_ingerir(), 1)
            self.assertTrue(os.path.exists(os.path.join(self.a.panel, "nodos", pid, "historial.db")))
        with self.n.contexto("p001"):
            r1 = self.d.hist_conducta()
            self.d.guardar_conducta(r1)
        with self.n.contexto("p002"):
            self.d.guardar_conducta(self.d.hist_conducta())
        self.assertEqual([(f["nodo"], f["ip"], f["alertas"]) for f in r1["filas"]], [("p001", _dash.IP, 3)])
        with self.n.contexto(self.n.TODOS):
            rt = self.d.hist_conducta()
            ct = self.d.cargar_conducta()
            csv = self.d.conducta_csv(ct).decode("utf-8-sig")
        self.assertEqual(sorted((f["nodo"], f["ip"], f["alertas"]) for f in rt["filas"]),
                         [("p001", _dash.IP, 3), ("p002", _dash.IP, 3)])
        self.assertEqual(len(ct["filas"]), 2)
        self.assertTrue(csv.startswith("Nodo;IP;"))
        self.assertEqual(sum(1 for l in csv.splitlines() if _dash.IP in l), 2)

    def test_conducta_lee_rotados_y_no_sigue_enlaces(self):
        """Tipo: capacidad nueva. La conducta de un punto lee sus eve.json* (tambien .gz) y
        nunca un enlace simbolico metido en datos/."""
        import gzip
        with gzip.open(os.path.join(self.a.datos, "p001", "eve.json.1.gz"), "wt", encoding="utf-8") as f:
            f.write(_dash.alerta(src="10.0.0.6", hace=3600) + "\n")
        fuera = os.path.join(self.tmp.name, "ajeno.json")
        with open(fuera, "w", encoding="utf-8") as f:
            f.write(_dash.alerta(src="10.0.0.99") + "\n")
        try:
            os.symlink(fuera, os.path.join(self.a.datos, "p001", "eve.json.2"))
            hay_enlace = True
        except (OSError, NotImplementedError):
            hay_enlace = False
        with self.n.contexto("p001"):
            rep = self.d.conducta_recolectar()
        ips = sorted(f["ip"] for f in rep["filas"])
        self.assertIn("10.0.0.6", ips)
        if hay_enlace:
            self.assertNotIn("10.0.0.99", ips)

    def test_reporte_y_cuarentena_por_nodo(self):
        """Tipo: capacidad nueva. cuarentena.json y report-*.html salen del directorio del
        nodo que se mira (o del de «Todos»)."""
        self.a.salida("p001", "cuarentena.json", {"ventana_min": 60, "candidatos": [{"ip": _dash.IP}]})
        self.a.salida("p002", "cuarentena.json", {"ventana_min": 1440, "candidatos": []})
        with self.n.contexto("p001"):
            self.assertEqual(self.d.ventana_generada(), 60)
            self.assertEqual([c["router"] for c in self.d._cpes_de_reporte()], ["p001"])
        with self.n.contexto("p002"):
            self.assertEqual(self.d.ventana_generada(), 1440)
            self.assertEqual(self.d._cpes_de_reporte(), [])
        self.assertTrue(self.d.logdir("p001").endswith(os.path.join("nodos", "p001")))

    def test_clave_siempre_pid_ip(self):
        """Tipo: corrección de defecto. Con un solo punto el heredado devolvia la IP pelada;
        ahora la identidad es SIEMPRE pid|ip, y sin punto (en «Todos») es un error."""
        with self.n.contexto("p001"):
            self.assertEqual(self.d.clave_cpe(_dash.IP, ""), "p001|" + _dash.IP)
        self.assertEqual(self.d.clave_cpe(_dash.IP, "p002"), "p002|" + _dash.IP)
        with self.n.contexto(self.n.TODOS):
            with self.assertRaises(self.n.NodoInvalido):
                self.d.clave_cpe(_dash.IP, "")


class DosHilos(Base):
    def test_dos_hilos_con_nodos_distintos(self):
        """Tipo: capacidad nueva (caso obligatorio «dos operadores o tareas a la vez»). Cada
        hilo ve solo su nodo durante cientos de lecturas intercaladas."""
        barrera = threading.Barrier(2)
        errores = []

        def trabajo(pid):
            try:
                with self.n.contexto(pid):
                    barrera.wait()
                    for _ in range(60):
                        filas = self.d.tail_grupos()
                        if {r[6] for r in filas} != {pid} or self.n.nodo_actual() != pid:
                            errores.append((pid, filas))
                        top, _ = self.d.top_origenes()
                        if {f["pid"] for f in top} != {pid}:
                            errores.append((pid, top))
            except Exception as ex:          # noqa: BLE001
                errores.append((pid, repr(ex)))

        hs = [threading.Thread(target=trabajo, args=(p,)) for p in ("p001", "p002")]
        for h in hs:
            h.start()
        for h in hs:
            h.join(60)
        self.assertEqual(errores, [])
        self.assertFalse(self.n.hay_nodo())


class Exclusiones(Base):
    def test_exclusion_de_un_nodo_no_vale_en_otro(self):
        """Tipo: capacidad nueva. Una exclusion con nodo=p001 oculta la alerta solo en p001."""
        self.d.ORQ_TRANSPORTE = lambda pet: {"op_id": pet["op_id"], "ok": True, "codigo": "ACEPTADA"}
        self.d.guardar_exclusiones([{"tipo": "src", "ip": _dash.IP, "motivo": "prueba", "puertos": [],
                                     "sid": "2000001", "hasta": 0, "nodo": "p001"}])
        with self.n.contexto(self.n.TODOS):
            filas = self.d.tail_grupos()
        self.assertEqual([r[6] for r in filas], ["p002"])

    def test_threshold_por_punto_afectado(self):
        """Tipo: capacidad nueva. Al guardar se pide punto.threshold al orquestador con el
        contenido de cada punto; solo lo que cambio; un fallo se registra y se avisa."""
        pedidas = []

        def transporte(pet):
            pedidas.append(pet)
            return {"op_id": pet["op_id"], "ok": True, "codigo": "ACEPTADA", "datos": {}}

        self.d.ORQ_TRANSPORTE = transporte
        regla = {"tipo": "src", "ip": _dash.IP, "motivo": "prueba", "puertos": [], "sid": "2000001",
                 "hasta": 0, "nodo": "p001"}
        self.assertEqual(self.d.guardar_exclusiones([regla]), [])
        por_pid = {p["params"]["pid"]: p["params"]["contenido"] for p in pedidas}
        self.assertEqual(sorted(por_pid), ["p001", "p002"])
        self.assertTrue(all(p["orden"] == "punto.threshold" for p in pedidas))
        self.assertIn("suppress gen_id 1, sig_id 2000001, track by_src, ip 10.0.0.5", por_pid["p001"])
        self.assertNotIn("suppress", por_pid["p002"])
        guardado = json.load(open(self.d.EXCL_FILE, encoding="utf-8"))
        self.assertEqual(guardado[0]["nodo"], "p001")
        pedidas.clear()
        self.assertEqual(self.d.guardar_exclusiones([regla]), [])
        self.assertEqual(pedidas, [])                     # nada cambio: nada que pedir
        self.d.ORQ_TRANSPORTE = lambda pet: {"op_id": pet["op_id"], "ok": False, "codigo": "FALLO",
                                             "mensaje": "suricata no recargo"}
        regla2 = dict(regla, nodo="")             # ahora vale en todos: solo cambia lo de p002
        avisos = self.d.guardar_exclusiones([regla2])
        self.assertEqual(len(avisos), 1)
        self.assertIn("p002", avisos[0])
        with open(self.d.BITACORA_LOG, encoding="utf-8") as f:
            self.assertIn("THRESHOLD-FALLO\tpunto=p002", f.read())
        pedidas.clear()
        self.d.ORQ_TRANSPORTE = transporte            # lo que fallo se vuelve a pedir
        self.assertEqual(self.d.guardar_exclusiones([regla2]), [])
        self.assertEqual([p["params"]["pid"] for p in pedidas], ["p002"])

    def test_nodo_mal_escrito_no_vale_en_todos(self):
        """Tipo: corrección de defecto. Una exclusion con un nodo mal formado no se aplica
        en ninguno (nunca se amplia a «todos los nodos»), y no se puede guardar."""
        with open(self.d.EXCL_FILE, "w", encoding="utf-8") as f:
            json.dump([{"tipo": "src", "ip": _dash.IP, "nodo": "p1", "motivo": "x"}], f)
        self.assertEqual(self.d.cargar_exclusiones(), [])
        with self.assertRaises(ValueError):
            self.d.guardar_exclusiones([{"tipo": "src", "ip": _dash.IP, "nodo": "../p001", "motivo": "x"}])


if __name__ == "__main__":
    unittest.main()
