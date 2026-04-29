# Incident Response Playbook — Credential Dumping LSASS (Sentinel KQL)

## Objectif
Confirmer une tentative de dumping de credentials depuis `lsass.exe` (T1003.001) et identifier le processus source.

## 0) Ce que tu dois voir dans les samples
Le log déclencheur attendu contient au minimum :
`TimeGenerated`, `Computer`, `EventID=10`, `TargetImage`, `SourceImage`, `GrantedAccess`, `CallTrace`, `User`.

## 1) Triage N1 (0-15 min)
1. Vérifier la cible : `TargetImage` se termine par `\lsass.exe`.
2. Vérifier le flag d'accès : `GrantedAccess` correspond à un des flags suspects de la règle.
3. Vérifier le process source :
   - binaire LOLBin (rundll32/comsvcs.dll, procdump, taskmgr en élevé)
   - chemin temporaire ou non attendu
4. Exclure les faux positifs :
   - sources AV/EDR connues listées dans la règle (MsMpEng, CrowdStrike, SentinelOne, etc.).

## 2) Investigation N2/N3 (15-45 min)
1. Reconstituer la chaîne autour de `TimeGenerated` sur la machine :
   - processus ayant précédé `SourceImage`
   - persistance (tasks, run keys, services)
   - connections réseau sortantes
2. Chercher l'output du dump :
   - création de fichiers `.dmp`
   - archive/compression puis upload
3. Vérifier l'impact :
   - comptes utilisant ensuite des sessions / lateral movement

## 3) Containment
1. Isoler l'endpoint (EDR network-isolate).
2. Tuer le processus source et bloquer le hash/chemin.
3. Révoquer sessions + reset mots de passe des comptes potentiellement exposés.

## 4) Eradication & Recovery
1. Recherche d'autres outils (Mimikatz/Procdump custom) dans la timeline.
2. Si LSASS a été dumpé : privilégier re-imagerie + rotation secrets.

## 5) Références & Artefacts
- KQL : `sentinel_vitrine/credential_dumping_lsass/sentinel_rule.kql`
- Sigma : `sentinel_vitrine/credential_dumping_lsass/sigma_rule.yml`

