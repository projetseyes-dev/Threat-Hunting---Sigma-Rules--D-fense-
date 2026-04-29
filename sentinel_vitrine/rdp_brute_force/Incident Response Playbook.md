# Incident Response Playbook — RDP Brute Force (Sentinel KQL)

## Objectif
Valider si l'activité détectée correspond à un brute force RDP (T1110.001) et déterminer si un compte a été compromis.

## 0) Ce que tu dois voir dans les samples
Le log déclencheur attendu (future `samples/`) contient au minimum :
`TimeGenerated`, `Computer`, `EventID`, `LogonType`, `IpAddress`, `TargetUserName`.

## 1) Triage N1 (0-10 min)
1. Identifier l'`IpAddress` et la fenêtre (5 minutes) qui a déclenché l'alerte.
2. Vérifier la cible :
   - asset exposé internet (si applicable),
   - DC / jump host ou serveur critique.
3. Chercher un `4624` (LogonType 10 ou 3) juste après les `4625`.
4. Exclure les faux positifs :
   - scanner interne connu,
   - compte de service avec mot de passe expiré.

## 2) Investigation N2/N3 (10-45 min)
1. Pivot sur le compte `TargetUserName` :
   - événements de création de processus après le succès,
   - authentifications sur d'autres hôtes.
2. Pivot sur l'IP :
   - connexions SMB/WMI/WinRM,
   - tentative d'élévation (création comptes, dump LSASS).

## 3) Containment
1. Bloquer l'IP au firewall / WAF / proxy.
2. Désactiver/lock le compte si succès confirmé.
3. Forcer le reset du mot de passe et révoquer les sessions.

## 4) Eradication & Recovery
1. Vérifier absence de persistence (tâches planifiées, services).
2. Scan EDR complet sur la machine ciblée.
3. Si compromise prouvée : rotation des secrets, re-imagerie si nécessaire.

## 5) Références & Artefacts
- KQL : `sentinel_vitrine/rdp_brute_force/sentinel_rule.kql`
- Sigma : `sentinel_vitrine/rdp_brute_force/sigma_rule.yml`

