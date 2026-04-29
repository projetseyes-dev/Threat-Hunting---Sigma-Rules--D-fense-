#!/usr/bin/env python3
"""
Convertit les règles Sigma vers Splunk SPL et Microsoft Sentinel KQL via
`sigma-cli` (https://github.com/SigmaHQ/sigma-cli).

Usage :
    pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto \
        pysigma-pipeline-windows
    python convert_rules.py detections/ --out build/

Sortie :
    build/splunk/<rule_id>.spl
    build/sentinel/<rule_id>.kql
    build/conversion_report.md

Code retour :
    0 : toutes les conversions ont réussi
    1 : au moins une conversion a échoué ou sigma-cli est indisponible

Auteur : SOC Detection Engineering Team
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("[!] PyYAML est requis : pip install -r requirements.txt\n")
    sys.exit(2)


@dataclass
class ConversionResult:
    rule_path: Path
    title: str = ""
    rule_id: str = ""
    splunk_ok: bool = False
    sentinel_ok: bool = False
    splunk_output: Path | None = None
    sentinel_output: Path | None = None
    errors: list[str] = field(default_factory=list)


def check_sigma_cli() -> bool:
    if shutil.which("sigma") is None:
        sys.stderr.write(
            "[!] `sigma` introuvable dans le PATH. Installer :\n"
            "    pip install sigma-cli pysigma-backend-splunk "
            "pysigma-backend-kusto pysigma-pipeline-windows\n"
        )
        return False
    return True


def list_plugins() -> dict:
    try:
        out = subprocess.run(
            ["sigma", "plugin", "list", "--compatible"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        return {"stdout": out.stdout, "stderr": out.stderr, "rc": out.returncode}
    except Exception as exc:
        return {"error": str(exc)}


def convert_one(
    rule_path: Path, target: str, pipelines: list[str], out_path: Path
) -> tuple[bool, str]:
    cmd = ["sigma", "convert", "-t", target]
    for p in pipelines:
        cmd.extend(["-p", p])
    cmd.extend(["-o", str(out_path), str(rule_path)])
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=60
        )
    except subprocess.TimeoutExpired:
        return False, "Timeout (>60s) lors de la conversion."
    except FileNotFoundError:
        return False, "sigma-cli introuvable."

    if proc.returncode == 0:
        return True, proc.stdout.strip() or "OK"
    err = (proc.stderr or proc.stdout or "").strip()
    return False, err


def convert_with_fallback(
    rule_path: Path, target: str, preferred_pipelines: list[str], out_path: Path
) -> tuple[bool, str]:
    """
    Essaye d'abord avec pipelines préférés, puis fallback sans pipeline.
    Très utile en CI quand un plugin de pipeline n'est pas disponible.
    """
    ok, msg = convert_one(rule_path, target, preferred_pipelines, out_path)
    if ok:
        return True, msg
    fallback_ok, fallback_msg = convert_one(rule_path, target, [], out_path)
    if fallback_ok:
        return True, f"Fallback sans pipeline (erreur initiale: {msg})"
    return False, f"{msg}\nFallback failed: {fallback_msg}"


def load_rule_meta(rule_path: Path) -> tuple[str, str]:
    try:
        with rule_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return str(data.get("id") or rule_path.stem), str(data.get("title") or "")
    except Exception:
        return rule_path.stem, ""


def collect_rules(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(
            p for p in (list(target.rglob("*.yml")) + list(target.rglob("*.yaml")))
            if "tests" not in p.parts and p.name.startswith("sigma_rule.")
        )
    return []


def write_report(
    results: list[ConversionResult], report_path: Path, selected_targets: set[str]
) -> None:
    lines = [
        "# Rapport de conversion Sigma → SIEM",
        "",
        f"Total règles : **{len(results)}**",
        "",
        "| Règle | Splunk SPL | Sentinel KQL |",
        "|-------|-----------|--------------|",
    ]
    for r in results:
        sp = ("OK" if r.splunk_ok else "FAIL") if "splunk" in selected_targets else "N/A"
        se = ("OK" if r.sentinel_ok else "FAIL") if "kusto" in selected_targets else "N/A"
        rule_label = f"{r.rule_path.parent.name}/{r.rule_path.name}"
        lines.append(f"| `{rule_label}` — {r.title} | {sp} | {se} |")

    def is_rule_ok_local(r: ConversionResult) -> bool:
        checks = []
        if "splunk" in selected_targets:
            checks.append(r.splunk_ok)
        if "kusto" in selected_targets:
            checks.append(r.sentinel_ok)
        return all(checks) if checks else True

    failures = [r for r in results if not is_rule_ok_local(r)]
    if failures:
        lines.extend(["", "## Échecs détaillés", ""])
        for r in failures:
            lines.append(f"### {r.rule_path}")
            for e in r.errors:
                lines.append(f"- {e}")
            lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convertit les règles Sigma vers SPL/KQL.")
    parser.add_argument("path", type=Path, help="Répertoire ou fichier Sigma.")
    parser.add_argument("--out", type=Path, default=Path("build"), help="Répertoire de sortie.")
    parser.add_argument(
        "--targets", nargs="+", default=["splunk", "kusto"],
        help="Backends sigma-cli (par défaut : splunk kusto).",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Vérifier seulement la disponibilité de sigma-cli et lister les plugins.",
    )
    args = parser.parse_args(argv)

    if not check_sigma_cli():
        return 1

    if args.check:
        info = list_plugins()
        print(json.dumps(info, indent=2))
        return 0 if info.get("rc", 1) == 0 else 1

    rules = collect_rules(args.path)
    if not rules:
        sys.stderr.write(f"[!] Aucune règle dans {args.path}\n")
        return 1

    splunk_dir = args.out / "splunk"
    sentinel_dir = args.out / "sentinel"
    splunk_dir.mkdir(parents=True, exist_ok=True)
    sentinel_dir.mkdir(parents=True, exist_ok=True)

    results: list[ConversionResult] = []
    for rule in rules:
        rid, title = load_rule_meta(rule)
        slug = rule.stem
        res = ConversionResult(rule_path=rule, title=title, rule_id=rid)

        if "splunk" in args.targets:
            out = splunk_dir / f"{slug}.spl"
            ok, msg = convert_with_fallback(
                rule, "splunk", ["splunk_windows"], out
            )
            res.splunk_ok = ok
            res.splunk_output = out if ok else None
            if not ok:
                res.errors.append(f"Splunk: {msg}")

        if "kusto" in args.targets:
            out = sentinel_dir / f"{slug}.kql"
            # Sentinel = backend Kusto. Pipeline microsoft_xdr préféré,
            # fallback automatique sans pipeline si non disponible.
            ok, msg = convert_with_fallback(
                rule, "kusto", ["microsoft_xdr"], out
            )
            res.sentinel_ok = ok
            res.sentinel_output = out if ok else None
            if not ok:
                res.errors.append(f"Sentinel: {msg}")

        status = []
        if "splunk" in args.targets:
            status.append("SPL OK" if res.splunk_ok else "SPL FAIL")
        if "kusto" in args.targets:
            status.append("KQL OK" if res.sentinel_ok else "KQL FAIL")
        print(f"[{' / '.join(status)}] {rule}")
        results.append(res)

    report = args.out / "conversion_report.md"
    selected_targets = set(args.targets)
    write_report(results, report, selected_targets)
    print(f"\nRapport : {report}")

    def is_rule_ok(r: ConversionResult) -> bool:
        checks = []
        if "splunk" in selected_targets:
            checks.append(r.splunk_ok)
        if "kusto" in selected_targets:
            checks.append(r.sentinel_ok)
        return all(checks) if checks else True

    failed = sum(1 for r in results if not is_rule_ok(r))
    print(f"=== {len(results) - failed}/{len(results)} règles converties (cibles sélectionnées) ===")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
