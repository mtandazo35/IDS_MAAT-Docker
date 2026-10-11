"""Ningún fichero de texto del repo con CRLF ni BOM (CONTRATO-F1a: todo el repo LF y sin BOM).
Revisa el árbol de trabajo (lo que git versionaría), no el índice: así falla antes del commit."""

import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def ficheros():
    try:
        r = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=REPO, capture_output=True,
                           text=True, check=True)
        nombres = [x for x in r.stdout.splitlines() if x]
    except (OSError, subprocess.CalledProcessError):
        nombres = [p.relative_to(REPO).as_posix() for p in REPO.rglob("*")
                   if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts]
    return [REPO / n for n in nombres if (REPO / n).is_file()]


class FinalesDeLinea(unittest.TestCase):
    def test_sin_crlf_ni_bom(self):
        malos = []
        for p in ficheros():
            datos = p.read_bytes()
            if b"\0" in datos[:8192]:          # binario (pcap, png…)
                continue
            rel = p.relative_to(REPO).as_posix()
            if datos.startswith(b"\xef\xbb\xbf"):
                malos.append("%s: BOM" % rel)
            if b"\r\n" in datos:
                malos.append("%s: CRLF" % rel)
        self.assertEqual(malos, [], "\n".join(malos))

    def test_gitattributes_lf(self):
        self.assertIn("* text=auto eol=lf", (REPO / ".gitattributes").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
