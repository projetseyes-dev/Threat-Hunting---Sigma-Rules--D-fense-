#!/usr/bin/env python3
"""
Détecteur d'anomalies de logon — UEBA basé sur IsolationForest.

Détecte les comportements de logon atypiques par utilisateur :
  - Connexions hors heures ouvrées habituelles
  - Géolocalisation inhabituelle
  - Volume anormal d'échecs (brute force lent)
  - Concurrence multi-host inhabituelle
  - "Impossible travel" (pays différent en peu de temps)

Pipeline :
  1. Phase TRAIN : agrégation des events 30 jours par (user, jour) → features
                   → entraînement IsolationForest par user.
  2. Phase SCORE : application du modèle sur events récents → score d'anomalie.

Format CSV d'entrée attendu :
    timestamp,user,result,src_ip,country,host

Usage :
    python logon_anomaly_detector.py --train events_30d.csv \
        --score events_today.csv --output anomalies.jsonl

Auteur : SOC Detection Engineering Team
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    sys.stderr.write(
        "[!] scikit-learn et numpy sont requis : pip install scikit-learn numpy\n"
    )
    sys.exit(2)


@dataclass
class LogonAnomaly:
    user: str
    score: float
    day: str
    total_events: int
    failures: int
    success: int
    unique_hosts: int
    unique_countries: int
    unique_ips: int
    off_hours_ratio: float
    impossible_travel: bool
    sample_hosts: list[str]
    sample_countries: list[str]


FEATURE_NAMES = [
    "total_events",
    "failures",
    "success",
    "unique_hosts",
    "unique_countries",
    "unique_ips",
    "off_hours_ratio",
    "weekend",
    "impossible_travel",
]


def parse_dt(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value.split(".")[0].rstrip("Z"), fmt)
        except ValueError:
            continue
    return None


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        sys.stderr.write(f"[!] Fichier introuvable : {path}\n")
        sys.exit(1)
    rows: list[dict] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"timestamp", "user", "result", "src_ip", "country", "host"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            sys.stderr.write(f"[!] Colonnes manquantes : {sorted(missing)}\n")
            sys.exit(1)
        for r in reader:
            dt = parse_dt(r["timestamp"])
            if dt is None:
                continue
            r["_dt"] = dt
            r["_day"] = dt.strftime("%Y-%m-%d")
            rows.append(r)
    return rows


def has_impossible_travel(events: list[dict]) -> bool:
    by_time = sorted(events, key=lambda e: e["_dt"])
    for i in range(len(by_time) - 1):
        a, b = by_time[i], by_time[i + 1]
        if a["country"] and b["country"] and a["country"] != b["country"]:
            delta = (b["_dt"] - a["_dt"]).total_seconds()
            if delta < 3600:
                return True
    return False


def featurize(events: list[dict]) -> tuple[list[float], dict]:
    if not events:
        return [0.0] * len(FEATURE_NAMES), {}
    total = len(events)
    failures = sum(1 for e in events if e["result"].lower() in {"fail", "failure", "0", "false"})
    success = total - failures
    hosts = {e["host"] for e in events if e["host"]}
    countries = {e["country"] for e in events if e["country"]}
    ips = {e["src_ip"] for e in events if e["src_ip"]}
    off_hours = sum(1 for e in events if e["_dt"].hour < 7 or e["_dt"].hour >= 20)
    off_ratio = off_hours / total if total else 0.0
    weekend = 1.0 if any(e["_dt"].weekday() >= 5 for e in events) else 0.0
    travel = 1.0 if has_impossible_travel(events) else 0.0

    features = [
        float(total),
        float(failures),
        float(success),
        float(len(hosts)),
        float(len(countries)),
        float(len(ips)),
        round(off_ratio, 3),
        weekend,
        travel,
    ]
    metadata = {
        "total_events": total,
        "failures": failures,
        "success": success,
        "unique_hosts": len(hosts),
        "unique_countries": len(countries),
        "unique_ips": len(ips),
        "off_hours_ratio": round(off_ratio, 3),
        "impossible_travel": bool(travel),
        "sample_hosts": sorted(list(hosts))[:5],
        "sample_countries": sorted(list(countries))[:5],
    }
    return features, metadata


def group_by_user_day(events: list[dict]) -> dict[tuple[str, str], list[dict]]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        groups[(e["user"], e["_day"])].append(e)
    return groups


def train_models(train_events: list[dict]) -> dict[str, IsolationForest]:
    groups = group_by_user_day(train_events)
    by_user: dict[str, list[list[float]]] = defaultdict(list)
    for (user, _day), evts in groups.items():
        feats, _ = featurize(evts)
        by_user[user].append(feats)

    models: dict[str, IsolationForest] = {}
    for user, samples in by_user.items():
        if len(samples) < 5:
            continue
        X = np.array(samples)
        model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
        )
        model.fit(X)
        models[user] = model
    return models


def score_events(
    score_events_data: list[dict],
    models: dict[str, IsolationForest],
    threshold: float,
) -> list[LogonAnomaly]:
    groups = group_by_user_day(score_events_data)
    anomalies: list[LogonAnomaly] = []
    for (user, day), evts in groups.items():
        feats, meta = featurize(evts)
        model = models.get(user)
        if model is None:
            anomaly_score = 6.0 if (meta["impossible_travel"] or meta["unique_countries"] > 1) else 0.0
            reason = "no_baseline"
        else:
            raw = model.score_samples(np.array([feats]))[0]
            anomaly_score = round((1.0 - (raw + 0.5)) * 10.0, 2)
            anomaly_score = max(0.0, min(anomaly_score, 10.0))
            reason = "baseline_deviation"

        if meta["impossible_travel"]:
            anomaly_score = max(anomaly_score, 8.5)

        if anomaly_score < threshold:
            continue

        anomalies.append(
            LogonAnomaly(
                user=user,
                score=anomaly_score,
                day=day,
                total_events=meta["total_events"],
                failures=meta["failures"],
                success=meta["success"],
                unique_hosts=meta["unique_hosts"],
                unique_countries=meta["unique_countries"],
                unique_ips=meta["unique_ips"],
                off_hours_ratio=meta["off_hours_ratio"],
                impossible_travel=meta["impossible_travel"],
                sample_hosts=meta["sample_hosts"],
                sample_countries=meta["sample_countries"],
            )
        )
    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Détecteur d'anomalies de logon (UEBA).")
    parser.add_argument("--train", type=Path, required=True,
                        help="CSV d'historique 30j (timestamp,user,result,src_ip,country,host)")
    parser.add_argument("--score", type=Path, required=True,
                        help="CSV d'events à scorer (même format)")
    parser.add_argument("--output", type=Path, default=Path("anomalies.jsonl"),
                        help="Fichier JSON Lines de sortie")
    parser.add_argument("--threshold", type=float, default=6.5,
                        help="Score minimum pour alerter (0-10)")
    args = parser.parse_args(argv)

    train = load_events(args.train)
    print(f"[*] {len(train)} events d'entraînement chargés")
    models = train_models(train)
    print(f"[*] {len(models)} modeles utilisateur entraines (>= 5 jours d'historique)")

    score_data = load_events(args.score)
    print(f"[*] {len(score_data)} events à scorer")

    anomalies = score_events(score_data, models, args.threshold)
    print(f"[*] {len(anomalies)} anomalies détectées (score >= {args.threshold})")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for a in anomalies:
            fh.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")

    print(f"[OK] Sortie écrite : {args.output}")
    if anomalies:
        print("\nTop 5 anomalies :")
        for a in anomalies[:5]:
            tags = []
            if a.impossible_travel:
                tags.append("IMPOSSIBLE_TRAVEL")
            if a.failures > a.success:
                tags.append(f"BRUTE_FORCE({a.failures}f/{a.success}s)")
            if a.off_hours_ratio > 0.5:
                tags.append("OFF_HOURS")
            tag_str = f" [{'/'.join(tags)}]" if tags else ""
            print(f"  - {a.user} ({a.day}) score={a.score}{tag_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
