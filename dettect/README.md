# DeTT&CT — Mesure de visibilité

[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) (DEtect Tactics, Techniques & Combat Threats) est un framework qui complète MITRE ATT&CK en mesurant **la qualité de la visibilité** dont dispose le SOC sur chaque data source.

## Pourquoi ?

Une règle de détection n'a de valeur que si la **donnée source est ingérée correctement** :

- Présente sur l'asset (`device_completeness`)
- Avec les bons champs (`data_field_completeness`)
- Disponible rapidement (`timeliness`)
- De manière cohérente entre assets (`consistency`)
- Avec une rétention suffisante pour le hunt rétroactif (`retention`)

## Utilisation

```bash
git clone https://github.com/rabobank-cdc/DeTTECT.git
cd DeTTECT
pip install -r requirements.txt
python dettect.py editor
```

Puis charger `data_sources.yaml` depuis ce dossier dans l'éditeur DeTT&CT.

## Génération d'une couche Navigator « visibilité »

```bash
python dettect.py ds -fd dettect/data_sources.yaml -l
```

Sortie : un fichier JSON Navigator qui colorie ATT&CK selon la **couverture de visibilité** réelle.

## Croisement détection × visibilité

L'objectif est de superposer :

1. **Couverture de détection** (généré par `generate_navigator_layer.py`) — où nous avons des **règles**.
2. **Couverture de visibilité** (généré par DeTT&CT) — où nous avons les **données**.

Une technique avec une règle Sigma mais une visibilité < 3 est une **fausse couverture** : la règle ne se déclenchera jamais en production.

## Scoring

| Score | Signification |
|-------|---------------|
| 0 | Aucune visibilité |
| 1 | Très faible (< 25 % des assets, champs partiels) |
| 2 | Faible (25-50 %, qualité moyenne) |
| 3 | Acceptable (50-75 %, qualité bonne) |
| 4 | Bonne (75-95 %, qualité élevée) |
| 5 | Excellente (> 95 %, qualité max) |

**Cible SOC : moyenne ≥ 4 sur les data sources critiques** (Process Creation, Logon Session, Command Execution, Process Access, DNS).
