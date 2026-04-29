#!/usr/bin/env python3
"""Validation automatisée des règles Sigma.

Ce script est volontairement minimal pour une démo vitrine :
il délègue la validation au validateur principal `validate_sigma.py`
présent à la racine du projet.

Usage :
  python scripts/validate_sigma.py
  python scripts/validate_sigma.py --target detections/
"""

from __future__ import annotations

import argparse
import tempfile
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Valide les règles Sigma de detections/.")
    parser.add_argument(
        "--target",
        type=Path,
        default=Path("detections/"),
        help="Répertoire cible contenant des règles Sigma (*.yml).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Mode strict (warnings bloquants).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    target = (repo_root / args.target).resolve()
    validator = repo_root / "validate_sigma.py"

    sigma_files = sorted(target.rglob("sigma_rule.y*ml"))
    if not sigma_files:
        print(f"[!] Aucun fichier sigma_rule.yml trouvé dans {target}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        for i, src in enumerate(sigma_files, start=1):
            dst = stage / f"{i:03d}_{src.name}"
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

        cmd = [sys.executable, str(validator), str(stage)]
        if args.strict:
            cmd.append("--strict")

        proc = subprocess.run(cmd, cwd=str(repo_root))
        return proc.returncode


if __name__ == "__main__":
    sys.exit(main())

