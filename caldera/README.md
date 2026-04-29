# Caldera — Orchestration Purple Team

[MITRE Caldera](https://github.com/mitre/caldera) est une plateforme d'**adversary emulation** automatisée. Elle déploie des agents (Sandcat / Manx / Ragdoll) sur les endpoints de lab et exécute des chaînes d'**Abilities** mappées à ATT&CK.

Ce dossier wire les **Atomic Tests** de chaque règle Sigma de cette bibliothèque dans un **Adversary Profile** Caldera unique afin d'orchestrer une **campagne Purple Team complète** en 1 clic.

## 1. Arborescence

```
caldera/
├── README.md                              # Ce document
├── adversary_profiles/
│   └── soc-detection-coverage.yml         # Profil multi-TTP qui rejoue toutes les règles
├── abilities/
│   ├── windows/
│   │   ├── t1055.012-process-hollowing.yml
│   │   ├── t1110.001-rdp-brute-force.yml
│   │   ├── t1048.003-dns-exfiltration.yml
│   │   ├── t1003.001-lsass-dump.yml
│   │   └── t1059.001-encoded-powershell.yml
│   ├── linux/
│   │   └── t1059.004-reverse-shell.yml
│   ├── macos/
│   │   └── t1543.001-launchagent.yml
│   ├── azure/
│   │   └── t1098.003-aad-role.yml
│   ├── aws/
│   │   └── t1098.001-iam-persistence.yml
│   └── kubernetes/
│       └── t1611-privileged-pod.yml
└── operations/
    └── purple-team-quarterly.yml          # Operation prête à lancer
```

## 2. Installation Caldera

```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt
python server.py --insecure
```

UI : <https://localhost:8888> (red:admin / blue:admin)

## 3. Import des abilities et profile

```bash
# Copier les abilities dans le plugin "stockpile"
cp -r abilities/* /opt/caldera/plugins/stockpile/data/abilities/

# Copier le profil adversaire
cp adversary_profiles/soc-detection-coverage.yml \
   /opt/caldera/plugins/stockpile/data/adversaries/

# Redémarrer Caldera
python server.py --insecure
```

Dans l'UI :

1. **Campaigns → Adversary Profiles** → vérifier que `soc-detection-coverage` apparaît.
2. **Agents** → déployer Sandcat sur les endpoints de lab.
3. **Operations → Create** → choisir l'adversaire `soc-detection-coverage`.
4. Lancer.

## 4. Workflow Purple Team trimestriel

```
                    ┌─────────────────────────────┐
                    │  Caldera Operation Start    │
                    └──────────────┬──────────────┘
                                   ▼
        ┌──────────────────────────────────────────────┐
        │  Sandcat agents exécutent les abilities      │
        │  (T1055.012 → T1110.001 → T1003.001 → ...)   │
        └──────────────┬───────────────────────────────┘
                       ▼
        ┌──────────────────────────────────────────────┐
        │  Sigma rules détectent (ou pas) chaque TTP   │
        │  → alertes dans Splunk/Sentinel              │
        └──────────────┬───────────────────────────────┘
                       ▼
        ┌──────────────────────────────────────────────┐
        │  Comparaison Caldera-output × SIEM-alerts    │
        │  → rapport PASS/FAIL par règle               │
        └──────────────┬───────────────────────────────┘
                       ▼
        ┌──────────────────────────────────────────────┐
        │  Tuning des règles ratées + RETEX            │
        │  → mise à jour Sigma rules + git commit      │
        └──────────────────────────────────────────────┘
```

## 5. Mapping Atomic Tests ↔ Caldera Abilities

| Règle Sigma | Atomic Test (rules/.../tests/atomic.yaml) | Caldera Ability ID |
|-------------|-------------------------------------------|---------------------|
| Process Hollowing | T1055.012 - PowerShell svchost suspended | `t1055-012-svchost-suspend` |
| RDP Brute Force | T1110.001 - PowerShell NetUseAdd loop | `t1110-001-net-use-bruteforce` |
| DNS Exfiltration | T1048.003 - Long subdomain TXT queries | `t1048-003-dns-tunnel-poc` |
| LSASS Dump | T1003.001 - comsvcs.dll MiniDump | `t1003-001-comsvcs-minidump` |
| Encoded PowerShell | T1059.001 - Bypass + Hidden + EncodedCommand | `t1059-001-encoded-cradle` |
| Linux Reverse Shell | T1059.004 - bash /dev/tcp | `t1059-004-bash-revshell` |
| macOS LaunchAgent | T1543.001 - User-scope plist | `t1543-001-launchagent-create` |
| Azure Role | T1098.003 - Add Global Admin | `t1098-003-aad-role-add` |
| AWS IAM Persistence | T1098.001 - CreateAccessKey | `t1098-001-iam-create-key` |
| K8s Privileged Pod | T1611 - hostPath / privileged | `t1611-priv-pod-create` |

## 6. Métriques Purple Team

À reporter après chaque opération Caldera :

| Métrique | Calcul | Cible |
|----------|--------|-------|
| **Detection Coverage** | (abilities détectées / abilities exécutées) × 100 | ≥ 90% |
| **MTTD per ability** | T(alerte SIEM) − T(ability executed) | < 5 min |
| **False Negatives** | abilities exécutées sans alerte | 0 prioritairement sur P0/P1 |
| **False Positives** | alertes hors abilities | < 5% |
| **Coverage gain trimestriel** | Δ(techniques couvertes) | +5 par trimestre |

## 7. Intégration CI

À terme, intégrer dans la pipeline GitHub Actions :

- Job `purple-team-emulation` (manuel via `workflow_dispatch`).
- Spin-up d'un cluster lab éphémère (Vagrant / Terraform).
- Lancement Caldera operation via API.
- Récupération du rapport et corrélation avec les alertes Splunk/Sentinel.
- Échec du workflow si `Detection Coverage < 90%`.

## 8. Références

- MITRE Caldera : <https://github.com/mitre/caldera>
- Caldera Documentation : <https://caldera.readthedocs.io/>
- Atomic Red Team : <https://github.com/redcanaryco/atomic-red-team>
- Plugin Atomic for Caldera : <https://github.com/mitre/atomic>
- Purple Team Maturity : <https://github.com/scythe-io/purple-team-exercise-framework>
