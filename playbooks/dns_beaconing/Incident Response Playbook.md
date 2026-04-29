# Incident Response Playbook — DNS Beaconing (Sysmon EID 22) (Sentinel KQL)

## Description de la menace
Le **DNS beaconing** détourne le DNS pour établir un canal de communication discret.
Les attaquants émettent des requêtes répétitives (souvent encodées) de type **TXT/NULL**
vers un même `QueryName` ou domaine parent, afin d'exfiltrer des données
ou de synchroniser un agent C2.

## Sévérité
**High**

## Tactique MITRE ATT&CK correspondante
– **TA0011 Command and Control**  
– **T1071.004 Application Layer Protocol: DNS**  

## Étapes d’investigation

### 1) Triage (0-15 min)
1. Identifier `Computer`, `QueryName`, `Count` et la fenêtre `TimeGenerated` (bucket 5m).
2. Vérifier la cohérence :
   – `QueryType` = `TXT`/`NULL`  
   – `QueryName` correspond à un pattern long/encodé
3. Identifier le processus émetteur si la table contient `Image` (sinon pivot via EDR).

### 2) Analyse (15-60 min)
1. Chercher la chaîne d’attaque :
   – création de persistance (Scheduled Task / Run keys)  
   – exécution PowerShell encodée  
   – téléchargements / connexions HTTP
2. Estimer l’ampleur :
   – volume DNS (sur 24h)  
   – diversité des sous-domaines

### 3) Remédiation (60 min)
1. Isoler l’hôte (EDR network isolate).
2. Bloquer le domaine parent et/ou sinkhole DNS.
3. Tuer le processus émetteur et supprimer la persistance.
4. Rotation des secrets/tokens si exfiltration confirmée.

## Artefacts
– KQL : `detections/dns_beaconing/sentinel_rule.kql`  
– Sigma : `detections/dns_beaconing/sigma_rule.yml`  
– Samples : `samples/dns_beaconing/trigger_logs.json`

