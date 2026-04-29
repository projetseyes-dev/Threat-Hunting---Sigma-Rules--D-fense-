# Incident Response Playbook — Process Hollowing (Sentinel KQL)

## Objectif
Valider si la détection KQL a identifié un **Process Hollowing** (T1055.012) ou un faux positif (exécution légitime de processus suspendus).

## 0) Ce que tu dois voir dans les samples
Le log déclencheur attendu (future `samples/`) contient au minimum :
`TimeGenerated`, `Computer`, `EventID=4688`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `Account`.

## 1) Triage N1 (0-15 min)
1. Ouvrir l’alert dans Sentinel.
2. Vérifier :
   - `NewProcFile` est bien un binaire canonique (svchost/explorer/etc.).
   - `CommandLine` contient `CREATE_SUSPENDED` ou un équivalent `-Suspended`.
   - `ParentProcessName` correspond à un parent non attendu (PowerShell/CMD/Office/MSHTA…).
3. Exclure rapidement :
   - parent légitime `services.exe` pour `svchost.exe`
   - parent légitime `userinit.exe` ou `winlogon.exe` pour `explorer.exe`

## 2) Investigation N2/N3 (15-60 min)
1. Pivot sur la machine :
   - Rechercher les 30-60 minutes autour de `TimeGenerated` pour la même `Computer`.
2. Pivot sur la chaîne parent->enfant :
   - identifier les autres processus spawnés par le parent (PowerShell/CMD/WScript…).
3. Vérifier la présence d’indicateurs associés :
   - création de persistance (tâche planifiée, run keys, services)
   - connections sortantes (DNS/HTTP) dans les 5 minutes
   - accès à LSASS / dumping si séquence de post-exploitation

## 3) Containment (N2/N3)
1. Isoler l’endpoint (EDR network isolate).
2. Mettre en quarantaine le binaire concerné (hash/filename).
3. Contenir le parent suspect (kill-process / blocage hash / blocage policy).

## 4) Eradication & Recovery
1. Supprimer toute persistance identifiée.
2. Ré-imager si la chaîne d’infection ne peut pas être tracée de bout en bout.
3. Rechercher d’éventuels implants persistants (scan EDR + IOC search).

## 5) Références & Artefacts
- KQL : `sentinel_vitrine/process_hollowing/sentinel_rule.kql`
- Sigma (agnostique SIEM) : `sentinel_vitrine/process_hollowing/sigma_rule.yml`

