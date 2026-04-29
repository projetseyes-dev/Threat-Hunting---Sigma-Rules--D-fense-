# Sentinel Vitrine (KQL) — 5 detections + playbooks

Ce dossier sert de **vitrine** pour une démo Microsoft Sentinel (KQL).

Pour chaque détection :
- `sentinel_rule.kql` : requête KQL de Microsoft Sentinel (analytics rule)
- `Incident Response Playbook.md` : étapes d'investigation (SOC analyst)
- `sigma_rule.yml` : copie Sigma correspondante (interop/agnosticité SIEM)

## Prochaine étape (à faire ensuite)
Créer un dossier `samples/` contenant des **faux logs JSON** qui simulent :
- la télémétrie Windows (Sysmon + Security logs) d'une attaque,
- un événement déclencheur par règle (un pattern simple et reproductible).

Ensuite, un recruteur pourra :
1. ouvrir la règle KQL,
2. regarder le log sample associé,
3. constater que la règle “tombe” sur le bon événement.

