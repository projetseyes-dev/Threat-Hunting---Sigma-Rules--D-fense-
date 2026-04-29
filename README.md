# Threat Hunting & Sigma Rules - Bibliothèque de Détection

> **Auteur :** SOC Manager / Threat Hunter
> **Objectif :** Fournir une bibliothèque de règles de détection structurée, versionnée et documentée, alignée sur le framework **MITRE ATT&CK**, intégrable dans un SIEM (**Splunk** / **Microsoft Sentinel**) et accompagnée de playbooks de réponse à incident pour les analystes SOC (N1/N2/N3).

---

## Executive Summary

Cette bibliothèque illustre une approche **Detection-as-Code** : les règles de détection sont traitées comme du code (qualité via validation, interopérabilité via Sigma, tests via emulation, documentation via playbooks, et intégration via CI).

Pourquoi c’est indispensable pour un SOC moderne ?
– Les règles restent **cohérentes**, traçables et versionnées : moins d’improvisation, meilleure gouvernance des changements.  
– L’investigation devient **standardisée** grâce aux playbooks : triage N1, analyse N2/N3, containment, eradication et recovery.  
– Le temps de réponse baisse car l’analyste démarre avec une procédure et des requêtes prêtes à l’emploi : amélioration attendue sur le **MTTR (Mean Time To Respond)** (mesuré via KPIs comme MTTD/MTTR/FP rate).

Le résultat : passer d’une détection “isolée” à un pipeline complet **détection → validation → réponse → RETEX**, aligné sur **MITRE ATT&CK**.

## Lab Vitrine Sentinel (5 scénarios critiques)

Pour la démo (sans SIEM actif), le projet inclut un labo “vitrine” :
– `detections/` : 5 scénarios critiques avec règles **Sigma (agnostiques SIEM)** + requêtes **Microsoft Sentinel (KQL)**.
– `playbooks/` : 5 playbooks Markdown d’investigation/remédiation associés.
– `samples/` : logs JSON synthétiques qui simulent l’attaque et **déclenchent** la règle KQL correspondante.
– `scripts/validate_sigma.py` : un script qui valide automatiquement les règles Sigma.

Validation (détection-as-code) :
```bash
python scripts/validate_sigma.py --strict
```

Lecture recruteur :
1. Ouvrir `detections/<scenario>/sentinel_rule.kql`
2. Ouvrir `samples/<scenario>/trigger_logs.json`
3. Lire `playbooks/<scenario>/Incident Response Playbook.md`

## 1. Vision & Philosophie de Détection

Une détection isolée n'a aucune valeur sans :

1. **Un contexte d'attaque** (TTP MITRE ATT&CK).
2. **Un playbook d'investigation et de remédiation** exécutable.
3. **Un mécanisme de validation** garantissant la qualité du code de détection.
4. **Une intégration SIEM testée**.

Cette bibliothèque applique le modèle de **Detection Engineering as Code** : chaque règle est traitée comme un artefact logiciel (review, tests, CI, versioning).

---

## 2. Méthodologie de Threat Hunting (MITRE ATT&CK)

### 2.1 Le cycle PEAK adapté

Nous suivons une boucle inspirée du framework **PEAK** (Prepare, Execute, Act with Knowledge) couplée à la **Pyramid of Pain** de David Bianco :

```
        ┌─────────────────────────────────────────────────────┐
        │  1. THREAT MODELING        (CTI + ATT&CK Navigator) │
        │  2. HYPOTHÈSE              (TTP-Driven Hunt)        │
        │  3. COLLECTE                (Logs, EDR, Netflow)    │
        │  4. INVESTIGATION          (Pivot, Stack Counting)  │
        │  5. DÉTECTION              (Sigma Rule)             │
        │  6. RÉPONSE                (Playbook IR)            │
        │  7. RETEX                  (Tuning, Purple Team)    │
        └─────────────────────────────────────────────────────┘
```

### 2.2 Niveaux de la Pyramid of Pain ciblés

| Niveau | Indicateur | Effort attaquant | Couverture |
|--------|-----------|------------------|------------|
| Hash values | IOC volatile | Trivial | Basse priorité |
| IP / Domain | IOC réseau | Facile | Complémentaire |
| Artefacts hôte | Fichiers, mutex, clés registre | Modéré | Moyenne |
| Outils | Mimikatz, Cobalt Strike | Élevé | Haute |
| **TTPs** | **Comportements ATT&CK** | **Très élevé** | **Cible principale** |

**Toutes nos règles ciblent prioritairement les TTPs** afin d'imposer le maximum de douleur à l'attaquant.

### 2.3 Couverture ATT&CK actuelle

| Règle | Plateforme | Tactique | Technique |
|-------|-----------|----------|-----------|
| Process Hollowing | Windows | Defense Evasion / Privilege Escalation | T1055.012 |
| RDP Brute Force | Windows | Credential Access / Initial Access | T1110.001 |
| DNS Exfiltration | Windows | Exfiltration / C2 | T1048.003 / T1071.004 |
| Credential Dumping LSASS | Windows | Credential Access | T1003.001 |
| Encoded PowerShell | Windows | Execution / Defense Evasion | T1059.001 / T1027 |
| Linux Reverse Shell | Linux | Execution / C2 | T1059.004 |
| macOS LaunchAgent Persistence | macOS | Persistence / PrivEsc | T1543.001 / T1543.004 |
| AWS IAM Persistence | AWS / Cloud | Persistence / PrivEsc | T1098.001 / T1136.003 |
| Azure AAD Privileged Role | Azure / M365 | Persistence / PrivEsc | T1098.003 |
| Kubernetes Privileged Pod | Kubernetes | Privilege Escalation / Defense Evasion | T1611 / T1610 |

Couverture générée automatiquement et visualisable dans **MITRE ATT&CK Navigator** :

```bash
python generate_navigator_layer.py rules/ --out coverage/attack_navigator_layer.json
```

Importer ensuite `coverage/attack_navigator_layer.json` dans <https://mitre-attack.github.io/attack-navigator/>.

---

## 3. Structure du Dépôt

```
.
├── README.md                            # Ce document
├── requirements.txt                     # Dépendances Python
├── validate_sigma.py                    # Validateur de schéma Sigma
├── convert_rules.py                     # Conversion multi-SIEM (sigma-cli)
├── generate_navigator_layer.py          # Génération couche ATT&CK Navigator
├── .github/workflows/sigma-ci.yml       # Pipeline CI complet
├── coverage/
│   └── attack_navigator_layer.json      # (généré) couverture ATT&CK
├── dettect/
│   ├── data_sources.yaml                # Visibilité par data source
│   └── README.md                        # Doc DeTT&CT
├── caldera/
│   ├── adversary_profiles/              # Profils adversaires Purple Team
│   ├── abilities/                       # Abilities Caldera par OS
│   └── README.md                        # Workflow Purple Team trimestriel
├── ml/
│   ├── dns_anomaly_detector.py          # UEBA DNS (entropie, volume, QType)
│   ├── logon_anomaly_detector.py        # UEBA logon (IsolationForest)
│   └── README.md                        # Pipeline MLOps minimal
└── rules/
    ├── process_hollowing/                       # T1055.012 (Windows)
    │   ├── process_hollowing.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── rdp_brute_force/                         # T1110.001 (Windows)
    │   ├── rdp_brute_force.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── dns_exfiltration/                        # T1048.003 (Windows)
    │   ├── dns_exfiltration.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── credential_dumping_lsass/                # T1003.001 (Windows)
    │   ├── credential_dumping_lsass.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── suspicious_powershell_encoded/           # T1059.001 (Windows)
    │   ├── suspicious_powershell_encoded.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── linux_reverse_shell/                     # T1059.004 (Linux)
    │   ├── linux_reverse_shell.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── macos_launchagent_persistence/           # T1543.001 / T1543.004 (macOS)
    │   ├── macos_launchagent_persistence.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── aws_iam_persistence/                     # T1098.001 (AWS)
    │   ├── aws_iam_persistence.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    ├── azure_privileged_role_assignment/        # T1098.003 (Azure / M365)
    │   ├── azure_privileged_role_assignment.yml
    │   ├── playbook.md
    │   └── tests/atomic.yaml
    └── k8s_privileged_pod_creation/             # T1611 / T1610 (Kubernetes)
        ├── k8s_privileged_pod_creation.yml
        ├── playbook.md
        └── tests/atomic.yaml
```

Chaque dossier de règle est **autoportant** :

– `*.yml` - la détection au format Sigma.
– `playbook.md` - la procédure de réponse à incident.
– `tests/atomic.yaml` - le test Atomic Red Team pour valider la règle en lab.

---

## 4. Format Sigma - Pourquoi ?

[Sigma](https://github.com/SigmaHQ/sigma) est le **standard ouvert** de description de règles de détection, agnostique au SIEM. Une règle écrite une fois est compilable vers :

– Splunk SPL (`splunk`)
– Microsoft Sentinel KQL (`microsoft365defender`, `azuremonitor`)
– Elastic ES|QL / EQL
– CrowdStrike, QRadar, Chronicle, etc.

La conversion s'opère via **`sigma-cli`** (basé sur pySigma).

---

## 5. Intégration SIEM

### Conversion automatique (toutes règles)

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto \
            pysigma-pipeline-windows pysigma-pipeline-sysmon

python convert_rules.py rules/ --out build/
```

Sortie :

```
build/
├── splunk/<rule>.spl          # SPL prêt à coller dans Splunk Search
├── sentinel/<rule>.kql        # KQL prêt à coller dans Sentinel Analytics Rules
└── conversion_report.md       # Statut OK/FAIL par règle et par cible
```

### 5.1 Splunk

```bash
sigma convert -t splunk -p splunk_windows \
  rules/process_hollowing/process_hollowing.yml
```

Exemple de pipeline d'ingestion attendu :

| Source | TA Splunk | Sourcetype |
|--------|-----------|------------|
| Sysmon | Splunk_TA_microsoft-sysmon | `xmlwineventlog:microsoft-windows-sysmon/operational` |
| Windows Security | Splunk_TA_windows | `wineventlog:security` |
| DNS Server | Splunk_TA_dns-ms | `MSAD:NT6:DNS` |
| Zeek | TA-zeek | `bro:dns:json`, `bro:conn:json` |

Déploiement recommandé : Enterprise Security (ES) → **Correlation Searches** + **Notable Events** + **Risk-Based Alerting (RBA)**.

### 5.2 Microsoft Sentinel

```bash
sigma convert -t microsoft365defender \
  rules/credential_dumping_lsass/credential_dumping_lsass.yml
```

Tables KQL utilisées :

| Donnée | Table Sentinel / MDE |
|--------|----------------------|
| Process | `DeviceProcessEvents`, `SecurityEvent` (4688) |
| Réseau | `DeviceNetworkEvents`, `CommonSecurityLog` |
| DNS | `DnsEvents`, `DeviceNetworkEvents` (ActionType=DnsQueryResponse) |
| Auth | `SigninLogs`, `SecurityEvent` (4624/4625) |

Workflow de réponse via **Logic Apps / Playbooks Sentinel** (SOAR), déclenchés par **Analytics Rules** générées depuis Sigma.

---

## 6. Validation des règles

Un script Python (`validate_sigma.py`) vérifie chaque YAML contre :

– Le schéma Sigma officiel (champs obligatoires, types, valeurs `level` autorisées, etc.).
– L'unicité des `id` (UUID v4).
– La présence de tags MITRE ATT&CK (`attack.tXXXX`).
– La cohérence `logsource` ↔ `detection.condition`.

Exécution :

```bash
pip install -r requirements.txt
python validate_sigma.py rules/
```

Sortie attendue :

```
[OK]   rules/process_hollowing/process_hollowing.yml
[OK]   rules/rdp_brute_force/rdp_brute_force.yml
...
=== 5/5 règles valides ===
```

## 7. Pipeline CI

Le workflow `.github/workflows/sigma-ci.yml` exécute automatiquement à chaque push/PR :

| Job | Rôle |
|-----|------|
| `lint-yaml` | Lint via `yamllint` (style + cohérence) |
| `validate-sigma` | Schéma Sigma + UUID unique + tags ATT&CK (`--strict`) |
| `convert-multi-siem` | Conversion vers Splunk SPL + Sentinel KQL, artefact uploadé |
| `generate-coverage` | Couche ATT&CK Navigator JSON, artefact uploadé |
| `pr-summary` | Commentaire automatique sur la PR avec récap couverture |

Pre-merge gate : tout merge sur `main` est **bloqué** si une règle est invalide.

## 8. Tests Atomic Red Team

Chaque règle dispose d'un fichier `tests/atomic.yaml` qui décrit :

– Les **prérequis** (logs, EDR mode, isolation lab).
– Plusieurs **tests** reproduisant le TTP avec différentes variantes.
– Les **requêtes de validation** Splunk SPL et Sentinel KQL pour confirmer que l'alerte se déclenche.
– Les références ATT&CK + Atomic Red Team upstream.

Exemple : `rules/credential_dumping_lsass/tests/atomic.yaml` couvre 3 méthodes (comsvcs.dll, ProcDump, Task Manager).

> **Avertissement** : ces tests peuvent générer du bruit ou des credentials en mémoire - exécuter UNIQUEMENT en lab isolé.

## 9. Mesure de visibilité (DeTT&CT)

Le dossier `dettect/` contient un fichier `data_sources.yaml` listant la qualité de chaque data source :

– Process Creation, Process Access, Command Execution, Logon Session, Network Traffic, Domain Name, Cloud Service Modification.
– Scoring 0-5 sur `device_completeness`, `data_field_completeness`, `timeliness`, `consistency`, `retention`.

Croisement **détection × visibilité** permet d'éviter les **fausses couvertures** (règle écrite mais data source absente). Voir `dettect/README.md`.

---

## 10. Cycle de vie d'une règle

```
 Hypothèse de hunt  ──►  PoC en lab (Atomic Red Team / Caldera)
       │                          │
       ▼                          ▼
 Détection écrite (Sigma)  ──►  Validation (CI)
       │                          │
       ▼                          ▼
 Tuning sur données réelles  ──►  Production SIEM
       │                          │
       ▼                          ▼
 Playbook IR documenté    ──►  Mesure : MTTD / MTTR / FP rate
       │
       ▼
 Purple Team review trimestrielle
```

KPIs suivis :

– **MTTD** (Mean Time To Detect) par règle
– **MTTR** (Mean Time To Respond)
– **FP rate** (< 5% cible)
– **Couverture ATT&CK** par tactique (objectif > 70% sur Defense Evasion / Credential Access / Lateral Movement)

---

## 11. Caldera & Purple Team

Le dossier `caldera/` contient :

– Un **adversary profile** (`soc-detection-coverage.yml`) qui rejoue toutes les TTPs couvertes.
– Des **abilities** par OS (Windows, Linux, macOS, AWS, Azure, Kubernetes) mappées 1:1 aux règles Sigma.
– Un workflow **Purple Team trimestriel** documenté avec KPIs (Detection Coverage, MTTD, FN/FP rate).

```bash
# Import des abilities et profile dans une instance Caldera
cp -r caldera/abilities/* /opt/caldera/plugins/stockpile/data/abilities/
cp caldera/adversary_profiles/soc-detection-coverage.yml \
   /opt/caldera/plugins/stockpile/data/adversaries/
```

Permet d'orchestrer la validation **end-to-end** (Caldera execute → SIEM detect → tuning) en 1 clic.

## 12. ML / UEBA

Deux détecteurs comportementaux complètent les règles signature-based :

| Module | Cible | Approche |
|--------|-------|----------|
| `ml/dns_anomaly_detector.py` | Tunneling / exfiltration DNS | Entropie de Shannon + scoring composite (volume, QType, longueur, diversité) |
| `ml/logon_anomaly_detector.py` | Logon anormal | IsolationForest par utilisateur + impossible travel + off-hours |

Sortie au format **JSON Lines**, ré-ingérable dans le SIEM comme nouvelle data source. Voir `ml/README.md` pour le pipeline MLOps.

```bash
pip install scikit-learn numpy pandas
python ml/dns_anomaly_detector.py --input dns_logs.csv --threshold 7.5
python ml/logon_anomaly_detector.py --train events_30d.csv --score events_today.csv
```

## 13. Exploitation (DEX) : comment utiliser le programme

Le flux DEX ci-dessous montre comment passer de la **détection** à la **validation/exécution contrôlée**, puis à l’**exploitation SOC**.

1. **D - Détection (Sigma + Playbooks)**
   – Chaque TTP est décrite en Sigma dans `rules/*/*.yml` avec un `playbook.md` associé.
   – La qualité de schéma est garantie par `validate_sigma.py`.

2. **E - eXploitation contrôlée (Emulation Purple Team)**
   – Chaque règle a un `tests/atomic.yaml` (PoC en lab + requêtes de validation SIEM).
   – Pour une exécution orchestrée : importer Caldera (dossier `caldera/`), puis lancer `soc-detection-coverage` pour rejouer toutes les capacités.

3. **X - eXploitation SOC (triage, remédiation, tuning)**
   – À chaque alerte : appliquer le playbook (N1 → N2/N3 → Containment → Eradication → Recovery).
   – Ajuster les seuils/allowlists et mesurer l’amélioration via la couverture Navigator (et idéalement DeTT&CT).

### Commandes rapides (local)

```bash
# 1) Qualité / schéma Sigma
python validate_sigma.py rules/ --strict

# 2) Couverture ATT&CK Navigator
python generate_navigator_layer.py rules/ --out coverage/attack_navigator_layer.json

# 3) (Optionnel) Conversion vers SIEM (Splunk SPL + Sentinel KQL)
pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto \
            pysigma-pipeline-windows pysigma-pipeline-sysmon
python convert_rules.py rules/ --out build/

# 4) (Optionnel) UEBA / ML
pip install scikit-learn numpy pandas
python ml/dns_anomaly_detector.py --input dns_logs.csv --threshold 7.5
python ml/logon_anomaly_detector.py --train events_30d.csv --score events_today.csv
```

### Exécution Purple Team (Caldera)

```bash
# Import des abilities (dans Caldera / Stockpile)
cp -r caldera/abilities/* /opt/caldera/plugins/stockpile/data/abilities/

# Import du profil multi-TTP
cp caldera/adversary_profiles/soc-detection-coverage.yml \
   /opt/caldera/plugins/stockpile/data/adversaries/
```

Ensuite, depuis l’UI Caldera :
1. déployer les agents (Sandcat) sur les endpoints de lab,
2. lancer l’operation `soc-detection-coverage`,
3. comparer les résultats Caldera (abilities exécutées) vs alertes SIEM,
4. faire le tuning et le RETEX.

## 14. Roadmap

– [x] Ajout de tests Atomic Red Team par règle (`tests/atomic.yaml`).
– [x] Génération automatique de la couche ATT&CK Navigator.
– [x] Pipeline GitHub Actions (lint + validation + conversion multi-SIEM).
– [x] Intégration **DeTT&CT** pour scoring de visibilité.
– [x] Règles Linux (auditd) et Cloud (AWS CloudTrail).
– [x] Règles Azure Activity Log / Microsoft Graph (T1098.003).
– [x] Règles Kubernetes (audit logs, T1611 / T1610).
– [x] Règles macOS ESF (T1543.001 / T1543.004).
– [x] Intégration **Caldera** pour orchestration Purple Team.
– [x] Détection ML/UEBA sur DNS et logon anormaux.
– [ ] Pipeline Caldera CI (workflow_dispatch + corrélation auto SIEM).
– [ ] Versioning des modèles ML (MLflow) + drift monitoring.
– [ ] Couverture ATT&CK ICS / Mobile.

---

## 15. Références

– MITRE ATT&CK : <https://attack.mitre.org/>
– SigmaHQ : <https://github.com/SigmaHQ/sigma>
– Sigma Specification : <https://github.com/SigmaHQ/sigma-specification>
– Pyramid of Pain (D. Bianco) : <https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html>
– PEAK Framework (Splunk) : <https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html>
– Atomic Red Team : <https://github.com/redcanaryco/atomic-red-team>
– MITRE Caldera : <https://github.com/mitre/caldera>
– DeTT&CT : <https://github.com/rabobank-cdc/DeTTECT>
– IsolationForest (Liu, 2008) : <https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf>
– Stratus Red Team (Cloud TTPs) : <https://github.com/DataDog/stratus-red-team>
– Objective-See (macOS tools) : <https://objective-see.org/tools.html>

---

## 16. Licence

Règles publiées sous **Detection Rule License (DRL) 1.1** - réutilisation libre avec attribution.
