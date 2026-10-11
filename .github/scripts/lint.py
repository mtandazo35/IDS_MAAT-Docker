#!/usr/bin/env python3
"""Lista los ficheros que revisa el job lint (CONTRATO-F1a §6.4).

    lint.py python   -> *.py del repo y scripts con shebang python3 bajo images/*/rootfs/
    lint.py shell    -> *.sh del repo y scripts con shebang sh o bash
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RE_PY = re.compile(r"^#!\s*(/usr/bin/env\s+)?(/usr/bin/|/usr/local/bin/)?python3\b")
RE_SH = re.compile(r"^#!\s*(/usr/bin/env\s+)?(/bin/|/usr/bin/)?(ba)?sh(\s|$)")


def ficheros():
    r = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=REPO, capture_output=True, text=True,
                       check=True)
    return [REPO / x for x in r.stdout.splitlines() if x and (REPO / x).is_file()]


def primera_linea(p):
    try:
        with open(p, "rb") as f:
            return f.readline(200).decode("utf-8", errors="replace")
    except OSError:
        return ""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (["python"], ["shell"]):
        print(__doc__, file=sys.stderr)
        return 2
    out = []
    for p in ficheros():
        rel = p.relative_to(REPO).as_posix()
        if argv[0] == "python":
            if rel.endswith(".py") or (rel.startswith("images/") and "/rootfs/" in rel and RE_PY.match(primera_linea(p))):
                out.append(rel)
        else:
            if rel.endswith(".sh") or RE_SH.match(primera_linea(p)):
                out.append(rel)
    print("\n".join(sorted(set(out))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
