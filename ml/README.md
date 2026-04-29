# Détection ML / UEBA

Ce dossier contient deux modules de **détection comportementale** (User & Entity Behavior Analytics) qui complètent les règles Sigma signature-based :

| Script | Cible | Approche |
|--------|-------|----------|
| `dns_anomaly_detector.py` | Tunneling / exfiltration DNS | Entropie de Shannon + scoring composite |
| `logon_anomaly_detector.py` | Logon anormal (impossible travel, off-hours, brute force lent) | IsolationForest + features comportementales |

## Pourquoi ML/UEBA ?

Les TTPs sophistiqués (low-and-slow, attaques living-off-the-land, insider threats) **échappent aux règles signature-based** :

- DNS tunneling avec sous-domaines courts évite les seuils statiques.
- Brute force « slow » (1 essai / heure × 1000 comptes) passe sous les fenêtres de corrélation.
- Compte légitime utilisé hors heures ouvrées depuis pays inhabituel.

Le ML détecte les **déviations par rapport au comportement de référence** (baseline 30 jours).

## Pile technique choisie

| Choix | Justification |
|-------|---------------|
| `scikit-learn` IsolationForest | Détection d'anomalies non-supervisée, robuste, interprétable, peu de tuning. |
| Features manuelles | Plus stables qu'un autoencoder en prod SOC. Auditables par les analystes. |
| Sortie JSON Lines | Ingérable par Splunk/Sentinel comme une nouvelle data source. |
| Mode `--score-only` | Pour batch de scoring nocturne sans entraînement. |

## Exécution

```bash
pip install -r ../requirements.txt
pip install scikit-learn pandas numpy

python dns_anomaly_detector.py --input sample_dns.csv --threshold 7.5
python logon_anomaly_detector.py --train events_train.csv --score events_today.csv
```

## Intégration SIEM

1. Cron / Airflow nocturne récupère 24 h de data brute (DNS / 4624-4625) via API SIEM.
2. Script ML génère `anomalies.jsonl`.
3. SIEM HEC / Log Analytics ingère le fichier.
4. Une **règle Sigma** « high anomaly score » alerte sur les events scorés > seuil.

```spl
index=ml_anomalies score>=7.5
| stats count by entity, anomaly_type, top_features
```

## Cycle MLOps minimal

```
 Collecte 30 jours        Entraînement       Scoring temps réel       Tuning
 (logs SIEM)        →     (offline)     →    (batch nocturne)    →    (FP/FN)
                                                    │
                                                    ▼
                                        Alertes SIEM enrichies
```

À terme, intégrer **MLflow** pour le versioning de modèles et **Splunk MLTK** /
**Sentinel UEBA Notebooks** pour orchestration.

## Références

- IsolationForest (Liu, 2008) : <https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf>
- Entropie de Shannon appliquée DNS : SANS Reading Room ID 34152.
- Splunk MLTK : <https://docs.splunk.com/Documentation/MLApp/latest/User/About>
- Microsoft Sentinel UEBA : <https://learn.microsoft.com/azure/sentinel/identify-threats-with-entity-behavior-analytics>
