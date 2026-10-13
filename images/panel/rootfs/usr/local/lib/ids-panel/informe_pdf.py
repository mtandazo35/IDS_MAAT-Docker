"""Informe de seguridad en PDF (uso interno del ISP): que clientes hay en cada categoria, cuando
cayeron en ella y que hicieron.

Lo pidio el user (2026-10-13): «Generar reporte» solo mandaba a imprimir la pagina. Este modulo
SOLO dibuja: recibe los datos ya calculados por el panel (`dashboard.informe_datos`) y devuelve
los bytes del PDF. Asi se prueba aislado y no sabe nada de la base ni de los nodos.

Usa reportlab (python3-reportlab de Debian en la imagen, como python3-cryptography).
"""

import io
import time

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

TINTA = colors.HexColor("#141b24")
SUAVE = colors.HexColor("#5b6675")
LINEA = colors.HexColor("#dfe3e8")
FONDO = colors.HexColor("#f4f6f9")
AZUL = colors.HexColor("#2a78d6")

_E = {
    "titulo": ParagraphStyle("titulo", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=TINTA),
    "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=9.5, leading=13, textColor=SUAVE),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=TINTA,
                         spaceBefore=10, spaceAfter=4),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=TINTA,
                         spaceBefore=6, spaceAfter=2),
    "txt": ParagraphStyle("txt", fontName="Helvetica", fontSize=9, leading=12.5, textColor=TINTA),
    "nota": ParagraphStyle("nota", fontName="Helvetica", fontSize=8, leading=11, textColor=SUAVE),
    "celda": ParagraphStyle("celda", fontName="Helvetica", fontSize=8, leading=10, textColor=TINTA,
                            alignment=TA_LEFT),
    "celdab": ParagraphStyle("celdab", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=TINTA),
    "cab": ParagraphStyle("cab", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5,
                          textColor=SUAVE),
    "kpin": ParagraphStyle("kpin", fontName="Helvetica-Bold", fontSize=18, leading=21, textColor=TINTA),
    "kpil": ParagraphStyle("kpil", fontName="Helvetica", fontSize=8, leading=10, textColor=SUAVE),
}


def _x(t):
    """Texto seguro para Paragraph (que interpreta <, > y &)."""
    return (str(t if t is not None else "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def fecha(ts, con_hora=True, zona=None):
    if not ts:
        return "-"
    fmt = "%d/%m/%Y %H:%M" if con_hora else "%d/%m/%Y"
    if zona is not None:
        from datetime import datetime
        return datetime.fromtimestamp(ts, zona).strftime(fmt)
    return time.strftime(fmt, time.localtime(ts))


def _cuando(par, zona=None):
    """(ts, aproximado) -> «13/10/2026 09:42», o «12/10/2026 (aprox.)» si solo se sabe el dia."""
    ts, aprox = par
    return fecha(ts, con_hora=not aprox, zona=zona) + (" (aprox.)" if aprox and ts else "")


def _tabla(cabecera, filas, anchos, zebra=True, centrar_desde=1):
    datos = [[Paragraph(_x(c).upper(), _E["cab"]) for c in cabecera]]
    for f in filas:
        datos.append([c if hasattr(c, "wrap") else Paragraph(_x(c), _E["celda"]) for c in f])
    t = Table(datos, colWidths=anchos, repeatRows=1)
    est = [("BACKGROUND", (0, 0), (-1, 0), FONDO),
           ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINEA),
           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
           ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
    if zebra:
        for i in range(2, len(datos), 2):
            est.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafbfc")))
    t.setStyle(TableStyle(est))
    return t


def _kpis(pares, ancho):
    celdas = [[Paragraph(_x(n), _E["kpin"]), Paragraph(_x(lbl), _E["kpil"])] for n, lbl in pares]
    t = Table([[Table([[a], [b]], colWidths=[ancho / len(pares) - 8]) for a, b in celdas]],
              colWidths=[ancho / len(pares)] * len(pares))
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINEA),
                           ("INNERGRID", (0, 0), (-1, -1), 0.6, LINEA),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    return t


def _pie(datos):
    def dibujar(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(SUAVE)
        izq = "%s · Informe de seguridad · Uso interno, confidencial" % (datos.get("empresa") or "IDS")
        canvas.drawString(doc.leftMargin, 10 * mm, izq)
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, "Página %d" % doc.page)
        canvas.setStrokeColor(LINEA)
        canvas.line(doc.leftMargin, 13 * mm, A4[0] - doc.rightMargin, 13 * mm)
        canvas.restoreState()
    return dibujar


def generar(datos, comprimir=True):
    """Bytes del PDF. `datos` (lo arma dashboard.informe_datos):
      empresa, nodo, desde, hasta, dias, generado, usuario, zona (tzinfo o None),
      totales: {abonados, alertas, cortar},
      categorias: [{clave, nombre, gravedad, color, que_es, que_hacer,
                    abonados: [{ip, cliente, nodo, desde, hasta, aprox, alertas, dias,
                                repetido, firmas: [[categoria, firma, n, primera, ultima, aprox]],
                                destinos: [[dest, n]], puertos: [[p, n]], malos: [[dom, n]]}]}],
      metodologia: [str]."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=18 * mm,
                            title="Informe de seguridad", author=datos.get("empresa") or "",
                            subject="Conducta por abonado", pageCompression=1 if comprimir else 0)
    ancho = A4[0] - 30 * mm
    z = datos.get("zona")
    h = []

    # --- portada / cabecera --------------------------------------------------------------
    h.append(Paragraph("Informe de seguridad" + (" — " + _x(datos["empresa"]) if datos.get("empresa") else ""),
                       _E["titulo"]))
    h.append(Spacer(1, 3))
    h.append(Paragraph(
        "<b>Nodo:</b> %s &nbsp;·&nbsp; <b>Período:</b> %s a %s (%d día%s)<br/>"
        "<b>Generado:</b> %s%s" % (
            _x(datos.get("nodo", "")), fecha(datos.get("desde"), zona=z), fecha(datos.get("hasta"), zona=z),
            datos.get("dias", 0), "" if datos.get("dias") == 1 else "s",
            fecha(datos.get("generado"), zona=z),
            (" por " + _x(datos["usuario"])) if datos.get("usuario") else ""), _E["sub"]))
    h.append(Spacer(1, 10))

    # --- resumen ---------------------------------------------------------------------------
    tot = datos.get("totales", {})
    h.append(_kpis([("{:,}".format(tot.get("abonados", 0)).replace(",", "."), "abonados con alertas"),
                    ("{:,}".format(tot.get("alertas", 0)).replace(",", "."), "alertas reales en el período"),
                    ("{:,}".format(tot.get("cortar", 0)).replace(",", "."),
                     "para cortar (botnet, escaneo, fuerza bruta)")], ancho))
    h.append(Spacer(1, 10))
    cats = [c for c in datos.get("categorias", []) if c.get("abonados")]
    h.append(Paragraph("Resumen por categoría", _E["h1"]))
    if cats:
        h.append(_tabla(["Categoría", "Gravedad", "Abonados", "Alertas", "Primer caso", "Último caso"],
                        [[Paragraph("<b>%s</b>" % _x(c["nombre"]), _E["celda"]), c["gravedad"],
                          len(c["abonados"]), "{:,}".format(sum(a["alertas"] for a in c["abonados"])).replace(",", "."),
                          _cuando(min(((a["desde"], a.get("aprox")) for a in c["abonados"] if a.get("desde")),
                                      default=(None, False)), z),
                          fecha(max((a["hasta"] or a["desde"] for a in c["abonados"] if a.get("desde")), default=None), zona=z)]
                         for c in cats],
                        [ancho * w for w in (.27, .13, .12, .12, .18, .18)]))
    else:
        h.append(Paragraph("Ningún abonado con alertas reales en el período.", _E["txt"]))

    # --- por categoria: quien y desde cuando ------------------------------------------------
    for c in cats:
        bloque = [Paragraph("%s &nbsp;<font size=9 color='%s'>%s · %d abonado%s</font>" % (
            _x(c["nombre"]), c.get("color", "#5b6675"), _x(c["gravedad"]).upper(), len(c["abonados"]),
            "" if len(c["abonados"]) == 1 else "s"), _E["h1"]),
            Paragraph("%s <b>Qué hacer:</b> %s" % (_x(c.get("que_es", "")), _x(c.get("que_hacer", ""))),
                      _E["txt"]),
            Spacer(1, 5)]
        filas = []
        for a in sorted(c["abonados"], key=lambda a: (a.get("desde") or 9e18)):
            cayo = _cuando((a["desde"], a.get("aprox")), z)
            filas.append([Paragraph("<b>%s</b>" % _x(a["ip"]), _E["celda"]), a.get("cliente") or "-",
                          a.get("nodo", ""), cayo, fecha(a.get("hasta"), zona=z),
                          "{:,}".format(a["alertas"]).replace(",", "."), a.get("dias", 0),
                          a.get("repetido") or "-"])
        bloque.append(_tabla(["Abonado", "Cliente", "Nodo", "Cayó en la categoría", "Última vez",
                              "Alertas", "Días", "Lo más repetido"], filas,
                             [ancho * w for w in (.12, .16, .10, .15, .13, .10, .06, .18)]))
        h.append(KeepTogether(bloque[:3]))
        h.extend(bloque[3:])

    # --- ficha de cada abonado: que paso y cuando -------------------------------------------
    if cats:
        h.append(PageBreak())
        h.append(Paragraph("Ficha de cada abonado", _E["h1"]))
        h.append(Paragraph("Qué hizo cada cliente en el período, firma por firma, con la primera y la "
                           "última vez que se vio. Ordenado por gravedad y, dentro, por cuándo cayó.",
                           _E["nota"]))
    for c in cats:
        for a in sorted(c["abonados"], key=lambda a: (a.get("desde") or 9e18)):
            ficha = [Paragraph("%s &nbsp;<font size=9 color='#5b6675'>%s · %s · %s</font>" % (
                _x(a["ip"]), _x(a.get("cliente") or "cliente sin identificar"), _x(a.get("nodo", "")),
                _x(c["nombre"])), _E["h2"]),
                Paragraph("Cayó en <b>%s</b> el %s; última vez %s. %s alertas reales en %d día%s." % (
                    _x(c["nombre"]), _cuando((a.get("desde"), a.get("aprox")), z), fecha(a.get("hasta"), zona=z),
                    "{:,}".format(a["alertas"]).replace(",", "."), a.get("dias", 0),
                    "" if a.get("dias") == 1 else "s"), _E["txt"]),
                Spacer(1, 4)]
            if a.get("firmas"):
                ficha.append(_tabla(["Categoría", "Firma", "Veces", "Primera vez", "Última vez"],
                                    [[f[0], f[1], f[2], _cuando((f[3], f[5] if len(f) > 5 else False), z),
                                      fecha(f[4], zona=z)] for f in a["firmas"]],
                                    [ancho * w for w in (.16, .44, .08, .16, .16)]))
            otros = []
            for titulo, clave in (("Destinos", "destinos"), ("Puertos", "puertos"),
                                  ("Dominios sospechosos", "malos")):
                if a.get(clave):
                    otros.append("<b>%s:</b> %s" % (titulo, ", ".join(
                        "%s (%s)" % (_x(k), n) for k, n in a[clave][:6])))
            if otros:
                ficha.append(Spacer(1, 3))
                ficha.append(Paragraph("<br/>".join(otros), _E["nota"]))
            ficha.append(Spacer(1, 8))
            h.append(KeepTogether(ficha))

    # --- metodologia ------------------------------------------------------------------------
    h.append(Paragraph("Cómo se calcula", _E["h1"]))
    for p in datos.get("metodologia", []):
        h.append(Paragraph(_x(p), _E["txt"]))
        h.append(Spacer(1, 3))

    doc.build(h, onFirstPage=_pie(datos), onLaterPages=_pie(datos))
    return buf.getvalue()
