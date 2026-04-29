#!/usr/bin/env python3
"""
Détecteur d'anomalies DNS — tunneling / exfiltration.

Utilise un scoring composite combinant :
  - Entropie de Shannon des sous-domaines (encodage = entropie ≥ 3.5)
  - Longueur du label (> 50 chars suspect)
  - Ratio de QType TXT / NULL (> 30% suspect)
  - Volume de requêtes vers le domaine parent (> 100 req/h suspect)
  - Diversité de sous-domaines (cardinalité élevée pour un même parent)

Sortie : JSON Lines avec score 0-10 par (host, parent_domain).
Seuil par défaut : 7.5 (alerte SIEM).

Format CSV d'entrée attendu (colonnes obligatoires) :
    timestamp,host,query_name,qtype

Usage :
    python dns_anomaly_detector.py --input dns_logs.csv \
        --output anomalies.jsonl --threshold 7.5

Auteur : SOC Detection Engineering Team
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

KNOWN_LEGIT_TLDS = {
    "akamai.net", "akamaiedge.net", "cloudfront.net", "azureedge.net",
    "windowsupdate.com", "office.com", "office365.com", "googleusercontent.com",
    "gstatic.com", "amazonaws.com", "fastly.net", "cdn.mozilla.net",
    "googlevideo.com", "ytimg.com",
}

SUSPICIOUS_QTYPES = {"TXT", "NULL", "CNAME"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    s = s.lower()
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_parent(query: str) -> str:
    parts = query.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return query.lower()
    return ".".join(parts[-2:])


def extract_subdomain(query: str) -> str:
    parts = query.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


@dataclass
class DnsAnomaly:
    host: str
    parent_domain: str
    score: float
    total_queries: int
    unique_subdomains: int
    avg_entropy: float
    max_subdomain_length: int
    suspicious_qtype_ratio: float
    top_features: list[str]
    sample_queries: list[str]


def score_group(rows: list[dict]) -> tuple[float, list[str]]:
    n = len(rows)
    subdomains = [extract_subdomain(r["query_name"]) for r in rows]
    non_empty_subs = [s for s in subdomains if s]
    unique_subs = len(set(non_empty_subs))

    entropies = [shannon_entropy(s) for s in non_empty_subs] or [0.0]
    avg_ent = sum(entropies) / len(entropies)
    max_len = max((len(s) for s in non_empty_subs), default=0)

    suspicious_qt = sum(1 for r in rows if r["qtype"].upper() in SUSPICIOUS_QTYPES)
    qt_ratio = suspicious_qt / n if n else 0.0

    features: list[str] = []
    score = 0.0

    if avg_ent >= 4.0:
        score += 3.5
        features.append(f"high_entropy({avg_ent:.2f})")
    elif avg_ent >= 3.5:
        score += 2.0
        features.append(f"elevated_entropy({avg_ent:.2f})")

    if max_len >= 60:
        score += 2.5
        features.append(f"long_subdomain({max_len}c)")
    elif max_len >= 40:
        score += 1.0
        features.append(f"medium_subdomain({max_len}c)")

    if qt_ratio >= 0.5:
        score += 2.0
        features.append(f"txt_null_qtype({qt_ratio:.0%})")
    elif qt_ratio >= 0.3:
        score += 1.0
        features.append(f"qtype_anomaly({qt_ratio:.0%})")

    if n >= 200:
        score += 2.0
        features.append(f"high_volume({n})")
    elif n >= 100:
        score += 1.0
        features.append(f"elevated_volume({n})")

    if unique_subs >= 100:
        score += 1.5
        features.append(f"high_subdomain_diversity({unique_subs})")

    return min(score, 10.0), features


def load_csv(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"timestamp", "host", "query_name", "qtype"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            sys.stderr.write(f"[!] Colonnes manquantes : {sorted(missing)}\n")
            sys.exit(1)
        for r in reader:
            rows.append(r)
    return rows


def detect(
    rows: list[dict], threshold: float, allowlist: set[str]
) -> list[DnsAnomaly]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        parent = extract_parent(r["query_name"])
        if parent in allowlist or any(parent.endswith("." + a) for a in allowlist):
            continue
        groups[(r["host"], parent)].append(r)

    anomalies: list[DnsAnomaly] = []
    for (host, parent), grp in groups.items():
        score, features = score_group(grp)
        if score < threshold:
            continue
        non_empty = [extract_subdomain(r["query_name"]) for r in grp if extract_subdomain(r["query_name"])]
        anomalies.append(
            DnsAnomaly(
                host=host,
                parent_domain=parent,
                score=round(score, 2),
                total_queries=len(grp),
                unique_subdomains=len(set(non_empty)),
                avg_entropy=round(sum(shannon_entropy(s) for s in non_empty) / max(len(non_empty), 1), 2),
                max_subdomain_length=max((len(s) for s in non_empty), default=0),
                suspicious_qtype_ratio=round(sum(1 for r in grp if r["qtype"].upper() in SUSPICIOUS_QTYPES) / len(grp), 2),
                top_features=features,
                sample_queries=[g["query_name"] for g in grp[:3]],
            )
        )

    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Détecteur d'anomalies DNS (UEBA).")
    parser.add_argument("--input", type=Path, required=True,
                        help="CSV des logs DNS (timestamp,host,query_name,qtype)")
    parser.add_argument("--output", type=Path, default=Path("anomalies.jsonl"),
                        help="Fichier JSON Lines de sortie")
    parser.add_argument("--threshold", type=float, default=7.5,
                        help="Score minimum pour alerter (0-10)")
    parser.add_argument("--allowlist", type=Path, default=None,
                        help="Fichier texte de domaines parents à exclure (un par ligne)")
    args = parser.parse_args(argv)

    if not args.input.exists():
        sys.stderr.write(f"[!] Fichier introuvable : {args.input}\n")
        return 1

    allowlist = set(KNOWN_LEGIT_TLDS)
    if args.allowlist and args.allowlist.exists():
        with args.allowlist.open("r", encoding="utf-8") as fh:
            allowlist.update(l.strip() for l in fh if l.strip())

    rows = load_csv(args.input)
    print(f"[*] {len(rows)} requêtes DNS chargées")

    anomalies = detect(rows, args.threshold, allowlist)
    print(f"[*] {len(anomalies)} anomalies détectées (score >= {args.threshold})")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for a in anomalies:
            fh.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")

    print(f"[OK] Sortie écrite : {args.output}")
    if anomalies:
        print("\nTop 5 anomalies :")
        for a in anomalies[:5]:
            print(f"  - {a.host} -> {a.parent_domain} | score={a.score} | {', '.join(a.top_features[:3])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
