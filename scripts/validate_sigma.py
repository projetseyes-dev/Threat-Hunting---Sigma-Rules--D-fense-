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

    cmd = [sys.executable, str(validator), str(target)]
    if args.strict:
        cmd.append("--strict")

    proc = subprocess.run(cmd, cwd=str(repo_root))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())

