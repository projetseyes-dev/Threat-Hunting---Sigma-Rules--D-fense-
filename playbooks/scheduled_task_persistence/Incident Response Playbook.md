# Incident Response Playbook — Scheduled Task Persistence (EID 4698) (Sentinel KQL)

## Description de la menace
Les attaquants utilisent des **tâches planifiées** pour persister et exécuter du code de façon discrète.
L’événement **Windows Security EID 4698** (“A scheduled task was created”) est un signal clé.

Cette détection cible les tâches dont le contenu (TaskContent) contient des marqueurs
typique d’obfuscation/loader (ex : `PowerShell -enc`, `IEX`, chemins `%TEMP%` / `%APPDATA%`, etc.).

## Sévérité
**Critical**

## Tactique MITRE ATT&CK correspondante
– **TA0003 Persistence**  
– **T1053.005 Scheduled Task/Job: Scheduled Task**  

## Étapes d’investigation

### 1) Triage (0-15 min)
1. Valider que l’alerte correspond à un **EventID 4698** sur l’hôte `Computer`.
2. Vérifier :
   – `TaskName` (nom, namespace, propriétaire)  
   – `TargetUserName` / `SubjectUserName` (compte auteur)  
   – `TaskContent` (payload / commande)
3. Exclure les tâches Microsoft (filtre `TaskName !startswith "Microsoft\"`).

### 2) Analyse (15-60 min)
1. Vérifier l’exécution réelle :
   – repérer si la tâche a démarré après création (EID 4702/4699/4104 si PS logging).
2. Chercher les indicateurs associés :
   – création de fichiers (dropper)  
   – lancement d’outils (rundll32, procdump, cmd/powershell)  
   – réseau sortant (DNS/HTTP)
3. Établir si c’est :
   – une persistance initiale,  
   – ou une persistance post-compromise.

### 3) Remédiation (60 min)
1. Supprimer la tâche planifiée (et arrêter le job si actif).
2. Contenir l’hôte (EDR isolate) si exécution confirmée.
3. Révoquer/rotater les secrets si un loader a téléchargé des composants.
4. Re-imager si la chaîne n’est pas traçable.

## Artefacts
– KQL : `detections/scheduled_task_persistence/sentinel_rule.kql`  
– Sigma : `detections/scheduled_task_persistence/sigma_rule.yml`  
– Samples : `samples/scheduled_task_persistence/trigger_logs.json`

