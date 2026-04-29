#!/usr/bin/env python3
"""
Validateur de règles Sigma.

Vérifie que chaque fichier YAML d'un répertoire respecte le schéma Sigma :
champs obligatoires, types, valeurs autorisées (level, status), unicité des
identifiants UUID, présence de tags MITRE ATT&CK, cohérence logsource /
detection / condition.

Usage :
    python validate_sigma.py rules/
    python validate_sigma.py rules/process_hollowing/process_hollowing.yml

Code retour :
    0 : toutes les règles sont valides
    1 : au moins une règle est invalide ou un argument est incorrect

Auteur : SOC Detection Engineering Team
Référence : https://github.com/SigmaHQ/sigma-specification
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "[!] PyYAML est requis. Installation : pip install -r requirements.txt\n"
    )
    sys.exit(2)


# --- Schéma Sigma simplifié --------------------------------------------------

REQUIRED_TOP_FIELDS: set[str] = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
}

OPTIONAL_TOP_FIELDS: set[str] = {
    "author",
    "date",
    "modified",
    "references",
    "tags",
    "fields",
    "falsepositives",
    "related",
    "license",
    "name",
    "taxonomy",
}

ALLOWED_LEVELS: set[str] = {"informational", "low", "medium", "high", "critical"}
ALLOWED_STATUS: set[str] = {
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
}

LOGSOURCE_FIELDS: set[str] = {"category", "product", "service", "definition"}

CONDITION_KEYWORDS: set[str] = {
    "and", "or", "not", "1 of", "all of", "them", "(", ")",
}

ATTACK_TAG_RE = re.compile(r"^attack\.[a-z0-9_.]+$")
TID_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


# --- Modèle de résultat ------------------------------------------------------

@dataclass
class ValidationResult:
    path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# --- Fonctions utilitaires ---------------------------------------------------

def load_yaml(path: Path) -> tuple[dict | None, str | None]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return None, f"YAML invalide : {exc}"
    except OSError as exc:
        return None, f"Lecture impossible : {exc}"

    if not isinstance(data, dict):
        return None, "Le document YAML doit être un mapping (dictionnaire) à la racine."
    return data, None


def is_valid_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


def extract_condition_tokens(condition: str) -> set[str]:
    cleaned = re.sub(r"[()|]", " ", condition)
    tokens = set()
    for tok in cleaned.split():
        if tok.lower() in CONDITION_KEYWORDS:
            continue
        if tok.isdigit():
            continue
        tokens.add(tok)
    return tokens


# --- Validateurs spécifiques -------------------------------------------------

def validate_top_fields(rule: dict, result: ValidationResult) -> None:
    keys = set(rule.keys())
    missing = REQUIRED_TOP_FIELDS - keys
    if missing:
        result.errors.append(f"Champs obligatoires manquants : {sorted(missing)}")

    unknown = keys - REQUIRED_TOP_FIELDS - OPTIONAL_TOP_FIELDS
    if unknown:
        result.warnings.append(f"Champs non standard : {sorted(unknown)}")


def validate_id(rule: dict, result: ValidationResult) -> None:
    rid = rule.get("id")
    if rid is None:
        return
    if not is_valid_uuid(rid):
        result.errors.append(
            f"`id` doit être un UUID valide (RFC 4122) — reçu : '{rid}'."
        )


def validate_level_status(rule: dict, result: ValidationResult) -> None:
    level = rule.get("level")
    if level is not None and level not in ALLOWED_LEVELS:
        result.errors.append(
            f"`level` invalide '{level}'. Valeurs autorisées : {sorted(ALLOWED_LEVELS)}"
        )
    status = rule.get("status")
    if status is not None and status not in ALLOWED_STATUS:
        result.errors.append(
            f"`status` invalide '{status}'. Valeurs autorisées : {sorted(ALLOWED_STATUS)}"
        )


def validate_title_description(rule: dict, result: ValidationResult) -> None:
    title = rule.get("title")
    if isinstance(title, str):
        if len(title) > 256:
            result.errors.append(f"`title` trop long ({len(title)} > 256 caractères).")
        if not title.strip():
            result.errors.append("`title` est vide.")
    elif title is not None:
        result.errors.append("`title` doit être une chaîne de caractères.")

    desc = rule.get("description")
    if desc is not None and not isinstance(desc, str):
        result.errors.append("`description` doit être une chaîne de caractères.")


def validate_logsource(rule: dict, result: ValidationResult) -> None:
    ls = rule.get("logsource")
    if ls is None:
        return
    if not isinstance(ls, dict):
        result.errors.append("`logsource` doit être un mapping.")
        return
    if not ls:
        result.errors.append("`logsource` est vide.")
        return
    unknown = set(ls.keys()) - LOGSOURCE_FIELDS
    if unknown:
        result.warnings.append(
            f"`logsource` contient des clés inconnues : {sorted(unknown)}"
        )
    if not any(k in ls for k in ("category", "product", "service")):
        result.errors.append(
            "`logsource` doit définir au moins l'un de : category, product, service."
        )


def validate_detection(rule: dict, result: ValidationResult) -> None:
    det = rule.get("detection")
    if det is None:
        return
    if not isinstance(det, dict):
        result.errors.append("`detection` doit être un mapping.")
        return

    if "condition" not in det:
        result.errors.append("`detection.condition` est obligatoire.")
        return

    condition = det["condition"]
    if not isinstance(condition, str):
        result.errors.append("`detection.condition` doit être une chaîne.")
        return

    if "|" in condition:
        condition_logic = condition.split("|", 1)[0].strip()
    else:
        condition_logic = condition

    selection_names = {k for k in det.keys() if k != "condition" and k != "timeframe"}
    if not selection_names:
        result.errors.append(
            "`detection` doit contenir au moins une définition de selection en plus de `condition`."
        )
        return

    referenced = extract_condition_tokens(condition_logic)
    referenced_clean = set()
    for tok in referenced:
        tok2 = tok.rstrip(",")
        if tok2.endswith("*"):
            prefix = tok2[:-1]
            if any(name.startswith(prefix) for name in selection_names):
                continue
        referenced_clean.add(tok2)

    unknown_refs = {
        tok for tok in referenced_clean
        if tok not in selection_names
        and tok.lower() not in CONDITION_KEYWORDS
        and not tok.isdigit()
        and tok not in {"of", "them"}
    }
    if unknown_refs:
        result.warnings.append(
            f"`detection.condition` référence des selections inconnues : {sorted(unknown_refs)}"
        )

    unused = selection_names - referenced_clean
    unused_real = set()
    for name in unused:
        if any(
            ref.endswith("*") and name.startswith(ref[:-1])
            for ref in referenced_clean
        ):
            continue
        unused_real.add(name)
    if unused_real:
        result.warnings.append(
            f"Selections définies mais non utilisées dans `condition` : {sorted(unused_real)}"
        )


def validate_tags(rule: dict, result: ValidationResult) -> None:
    tags = rule.get("tags")
    if tags is None:
        result.warnings.append(
            "Aucun `tags` défini : ajouter au moins un tag MITRE ATT&CK (`attack.tXXXX`)."
        )
        return
    if not isinstance(tags, list):
        result.errors.append("`tags` doit être une liste.")
        return

    invalid = [t for t in tags if not (isinstance(t, str) and ATTACK_TAG_RE.match(t))]
    if invalid:
        result.errors.append(f"Tags non conformes au namespace `attack.*` : {invalid}")

    has_technique = any(isinstance(t, str) and TID_RE.match(t) for t in tags)
    if not has_technique:
        result.warnings.append(
            "Aucun identifiant de technique ATT&CK (ex: `attack.t1059.001`) trouvé."
        )


def validate_references(rule: dict, result: ValidationResult) -> None:
    refs = rule.get("references")
    if refs is None:
        return
    if not isinstance(refs, list):
        result.errors.append("`references` doit être une liste de chaînes (URLs).")
        return
    for r in refs:
        if not isinstance(r, str):
            result.errors.append(f"Référence invalide (non-string) : {r!r}")


def validate_falsepositives(rule: dict, result: ValidationResult) -> None:
    fp = rule.get("falsepositives")
    if fp is None:
        result.warnings.append("Aucun `falsepositives` documenté.")
        return
    if isinstance(fp, str):
        return
    if isinstance(fp, list):
        if not fp:
            result.warnings.append("`falsepositives` est une liste vide.")
        return
    result.errors.append("`falsepositives` doit être une chaîne ou une liste.")


# --- Pipeline de validation --------------------------------------------------

def validate_rule(path: Path) -> ValidationResult:
    result = ValidationResult(path=path)
    rule, error = load_yaml(path)
    if rule is None:
        result.errors.append(error or "Erreur inconnue de parsing.")
        return result

    validate_top_fields(rule, result)
    validate_id(rule, result)
    validate_level_status(rule, result)
    validate_title_description(rule, result)
    validate_logsource(rule, result)
    validate_detection(rule, result)
    validate_tags(rule, result)
    validate_references(rule, result)
    validate_falsepositives(rule, result)
    return result


def collect_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        all_files = list(target.rglob("*.yml")) + list(target.rglob("*.yaml"))
        return sorted(p for p in all_files if "tests" not in p.parts)
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validateur de règles Sigma (schéma simplifié)."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Fichier .yml ou répertoire contenant les règles Sigma à valider.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Considérer les warnings comme bloquants.",
    )
    args = parser.parse_args(argv)

    target: Path = args.path
    if not target.exists():
        sys.stderr.write(f"[!] Chemin introuvable : {target}\n")
        return 1

    files = collect_files(target)
    if not files:
        sys.stderr.write(f"[!] Aucun fichier YAML trouvé dans {target}\n")
        return 1

    seen_ids: dict[str, Path] = {}
    results: list[ValidationResult] = []

    for f in files:
        res = validate_rule(f)
        rule, _ = load_yaml(f)
        if rule and isinstance(rule.get("id"), str) and is_valid_uuid(rule["id"]):
            rid = rule["id"].lower()
            if rid in seen_ids:
                res.errors.append(
                    f"`id` dupliqué — déjà utilisé par {seen_ids[rid]}."
                )
            else:
                seen_ids[rid] = f
        results.append(res)

    valid_count = 0
    for res in results:
        rel = res.path
        if res.ok and not res.warnings:
            print(f"[OK]    {rel}")
            valid_count += 1
        elif res.ok and res.warnings:
            print(f"[WARN]  {rel}")
            for w in res.warnings:
                print(f"    - {w}")
            if args.strict:
                continue
            valid_count += 1
        else:
            print(f"[FAIL]  {rel}")
            for e in res.errors:
                print(f"    [ERROR]   {e}")
            for w in res.warnings:
                print(f"    [WARNING] {w}")

    total = len(results)
    print()
    print(f"=== {valid_count}/{total} règles valides ===")
    return 0 if valid_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
