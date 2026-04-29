# Incident Response Playbook — Suspicious LSASS Process Access (Sysmon EID 10)

## Description de la menace
Accès anormal à `lsass.exe` (Local Security Authority Subsystem Service) via **Sysmon EventID 10** (`ProcessAccess`).
Les flags `GrantedAccess` listés dans la détection correspondent à des primitives utilisées pour lire la mémoire ou préparer un dump.
Cette activité est typiquement associée à des scénarios de vol de credentials (prelude Mimikatz / dumping comsvcs / ProcDump).

## Sévérité
**Critical**

## Tactique MITRE ATT&CK
– **TA0006 Credential Access**  
– **T1003.001 OS Credential Dumping: LSASS Memory**

## Étapes d'investigation

### 1) Triage
1. Ouvrir l’alerte et récupérer :
   – `Computer`, `SourceImage`, `TargetImage`  
   – `GrantedAccess` et éventuellement `CallTrace`  
   – l’utilisateur (`User`)
2. Vérifier si la source est un composant légitime (EDR/AV connu).
3. Vérifier si d’autres événements suivront rapidement (création de dump `.dmp`, exfiltration, persistance).

### 2) Analyse
1. Reconstituer la timeline autour de `TimeGenerated` :
   – autres `ProcessAccess` vers `lsass.exe`  
   – création de fichiers (dumps), processus lancés par la source  
   – connexions réseau (DNS/HTTP) dans les 5 minutes
2. Déterminer la méthode :
   – accès “outil” (rundll32/procdump/taskmgr)  
   – accès “in-memory” (process custom / injection)
3. Identifier les comptes potentiellement compromis (ceux dont les tokens apparaissent après).

### 3) Remédiation
1. Containment : isoler l’endpoint et bloquer la source (kill process + block hash).
2. Rotation/révocation :
   – reset des mots de passe des comptes exposés  
   – révocation sessions/tickets si applicable
3. Eradication :
   – supprimer toute persistance identifiée  
   – re-imagerie si la chaîne n’est pas tracée de bout en bout

