#!/usr/bin/env python3
"""
Génère une couche MITRE ATT&CK Navigator (JSON) à partir des règles Sigma.

La couche peut être importée dans https://mitre-attack.github.io/attack-navigator/
pour visualiser la couverture de détection par technique.

Score = sévérité de la règle :
    informational=10, low=25, medium=50, high=75, critical=100

Couleur : interpolée du jaune au rouge selon le score.
Tooltip : titre + chemin de la règle + chemin du playbook.

Usage :
    python generate_navigator_layer.py rules/ --out coverage/attack_navigator_layer.json

Auteur : SOC Detection Engineering Team
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("[!] PyYAML est requis : pip install -r requirements.txt\n")
    sys.exit(2)


SEVERITY_SCORE = {
    "informational": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}

TID_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def load_rule(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else None
    except Exception as exc:
        sys.stderr.write(f"[!] {path}: {exc}\n")
        return None


def collect_rules(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(
        p for p in (list(target.rglob("*.yml")) + list(target.rglob("*.yaml")))
        if "tests" not in p.parts and p.name.startswith("sigma_rule.")
    )


def extract_techniques(rule: dict) -> list[str]:
    tags = rule.get("tags") or []
    out = []
    for t in tags:
        if not isinstance(t, str):
            continue
        m = TID_RE.match(t)
        if m:
            out.append(m.group(1).upper())
    return out


def find_playbook(rule_path: Path) -> Path | None:
    candidate = rule_path.parent / "playbook.md"
    return candidate if candidate.exists() else None


def build_layer(rules: list[Path], layer_name: str, description: str) -> dict:
    technique_to_rules: dict[str, list[dict]] = defaultdict(list)
    max_score_per_tech: dict[str, int] = {}

    for path in rules:
        rule = load_rule(path)
        if rule is None:
            continue
        title = rule.get("title", path.stem)
        level = (rule.get("level") or "medium").lower()
        score = SEVERITY_SCORE.get(level, 50)
        techniques = extract_techniques(rule)
        playbook = find_playbook(path)

        for tid in techniques:
            technique_to_rules[tid].append(
                {
                    "title": title,
                    "level": level,
                    "rule": str(path).replace("\\", "/"),
                    "playbook": str(playbook).replace("\\", "/") if playbook else None,
                }
            )
            if score > max_score_per_tech.get(tid, -1):
                max_score_per_tech[tid] = score

    techniques_block = []
    for tid, items in sorted(technique_to_rules.items()):
        score = max_score_per_tech[tid]
        comment_lines = [f"{len(items)} règle(s) Sigma :"]
        for it in items:
            base = f"  - [{it['level'].upper()}] {it['title']} ({it['rule']})"
            if it["playbook"]:
                base += f"\n    Playbook: {it['playbook']}"
            comment_lines.append(base)

        techniques_block.append(
            {
                "techniqueID": tid,
                "score": score,
                "color": "",
                "comment": "\n".join(comment_lines),
                "enabled": True,
                "metadata": [
                    {"name": "rules", "value": str(len(items))},
                    {"name": "max_severity", "value": _level_for_score(score)},
                ],
                "showSubtechniques": "." in tid,
            }
        )

    return {
        "name": layer_name,
        "versions": {
            "attack": "14",
            "navigator": "5.0.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS", "IaaS", "Office 365"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "max",
        },
        "hideDisabled": False,
        "techniques": techniques_block,
        "gradient": {
            "colors": ["#fff7bc", "#fec44f", "#d95f0e", "#993404"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "informational (10)", "color": "#fff7bc"},
            {"label": "low (25)", "color": "#fec44f"},
            {"label": "medium (50)", "color": "#fe9929"},
            {"label": "high (75)", "color": "#d95f0e"},
            {"label": "critical (100)", "color": "#993404"},
        ],
        "metadata": [
            {"name": "generator", "value": "generate_navigator_layer.py"},
            {"name": "rule_count", "value": str(len(rules))},
            {"name": "technique_count", "value": str(len(techniques_block))},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _level_for_score(score: int) -> str:
    for name, s in sorted(SEVERITY_SCORE.items(), key=lambda kv: kv[1]):
        if score <= s:
            return name
    return "critical"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Générateur de couche ATT&CK Navigator.")
    parser.add_argument("path", type=Path, help="Répertoire des règles Sigma.")
    parser.add_argument(
        "--out", type=Path,
        default=Path("coverage/attack_navigator_layer.json"),
        help="Fichier JSON de sortie.",
    )
    parser.add_argument(
        "--name", default="SOC Detection Coverage",
        help="Nom de la couche Navigator.",
    )
    parser.add_argument(
        "--description",
        default=(
            "Couverture de détection générée à partir des règles Sigma "
            "internes. Score = sévérité maximale par technique."
        ),
    )
    args = parser.parse_args(argv)

    rules = collect_rules(args.path)
    if not rules:
        sys.stderr.write(f"[!] Aucune règle trouvée dans {args.path}\n")
        return 1

    layer = build_layer(rules, args.name, args.description)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[OK] Couche générée : {args.out}")
    print(f"     Règles analysées      : {len(rules)}")
    print(f"     Techniques couvertes  : {len(layer['techniques'])}")
    if layer["techniques"]:
        print("     Techniques :")
        for t in layer["techniques"]:
            print(f"       - {t['techniqueID']} (score={t['score']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
