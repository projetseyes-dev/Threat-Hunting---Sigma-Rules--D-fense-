# Incident Response Playbook — RDP Brute Force suivie de succès (Sentinel KQL)

## Description de la menace
Le **brute force RDP** consiste à tenter de deviner des mots de passe sur **TCP/3389** via de nombreuses authentifications échouées (EID `4625`, `LogonType` 10/3), souvent depuis un même `IpAddress`, puis à obtenir un succès (`4624`). Ce pattern est fréquent avant une prise de contrôle et une propagation (credential stuffing / password spraying).

## Sévérité
**Critical**

## Tactique MITRE ATT&CK
– **TA0006 Credential Access**  
– **T1110.001 Password Guessing**

## Étapes d’investigation

### 1) Triage (0-10 min)
1. Identifier `Computer`, `IpAddress`, `TargetUserName` et la fenêtre `window` (5 minutes).
2. Confirmer dans les logs que la salve d’échecs `4625` est bien suivie d’au moins un `4624`.
3. Vérifier si l’IP est interne (scan légitime) ou externe (P0).

### 2) Analyse (10-45 min)
1. Pivot sur le compte ayant eu un succès (`TargetUserName`) :
   – quels processus démarrent après `4624` ?
   – y a-t-il création de tâches planifiées, scripts PowerShell, ou tentative de dump LSASS ?
2. Pivot sur l’IP :
   – y a-t-il d’autres échecs/succès sur d’autres hôtes ?
   – corréler avec SMB/WMI/WinRM (mouvement latéral).

### 3) Remédiation (45-60 min)
1. Containment : bloquer l’IP à la périphérie (FW/WAF/proxy) et isoler l’hôte si besoin.
2. Réinitialiser le mot de passe (ou lock/revoke) du compte compromis.
3. Révoquer les sessions/tickets actifs (Kerberos) et auditer la persistence (tâches planifiées, run keys).
4. Ajouter une allowlist seulement après validation (ITSM ticket + business justification).

## Artefacts
– Règle KQL : `detections/rdp_bruteforce/sentinel_rule.kql`  
– Samples : `samples/rdp_bruteforce/trigger_logs.json`

