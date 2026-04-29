# Incident Response Playbook — Mimikatz / LSASS Dump (Sentinel KQL)

## Description de la menace
Ce scénario signale une **tentative de dump de LSASS** (T1003.001) via **accès mémoire suspect** (Sysmon EventID 10 / ProcessAccess).
La règle augmente la précision en cherchant :
– une cible `lsass.exe` avec flags `GrantedAccess` caractéristiques, et  
– une source typique d’outils de dumping (rundll32/procdump/taskmgr) et/ou  
– une signature de dump dans `CallTrace` (ex : `MiniDumpWriteDump`, `comsvcs.dll`).

## Sévérité
**Critical**

## Tactique MITRE ATT&CK
– **TA0006 Credential Access**  
– **T1003.001 OS Credential Dumping: LSASS Memory**

## Étapes d’investigation

### 1) Triage (0-15 min)
1. Identifier `Computer`, `User`, `SourceImage`, `GrantedAccess`.
2. Vérifier si la source correspond à un outil de dump (rundll32/procdump/taskmgr) ou si `CallTrace` mentionne `MiniDumpWriteDump` / `comsvcs.dll`.
3. Exclure les sources EDR/AV connues listées dans la règle.

### 2) Analyse (15-45 min)
1. Reconstituer la timeline autour de `TimeGenerated` :
   – processus lancés juste avant/après  
   – création de fichiers `.dmp`  
   – exfiltration (DNS/HTTP/SMB) si vous l’avez en télémétrie
2. Chercher la persistance (tâches planifiées, services, run keys).
3. Déterminer le périmètre : comptes ayant ensuite des sessions, accès à partages, WMI/WinRM.

### 3) Remédiation
1. Containment : isoler l’endpoint et bloquer la source.
2. Révoquer sessions/tickets et **rotations des secrets/MDP** pour les comptes potentiellement exposés.
3. Eradication : recherche d’implants (Mimikatz-like, loaders), suppression de la persistance.
4. Recovery : re-imagerie si LSASS a été dumpé (forte probabilité de compromission).

## Artefacts
– KQL : `detections/mimikatz_lsass_dump/sentinel_rule.kql`  
– Playbook : `playbooks/mimikatz_lsass_dump/Incident Response Playbook.md`  
– Samples : `samples/mimikatz_lsass_dump/trigger_logs.json`

