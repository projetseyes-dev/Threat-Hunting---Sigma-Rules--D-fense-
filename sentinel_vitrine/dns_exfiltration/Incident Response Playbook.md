# Incident Response Playbook — DNS Exfiltration (Sentinel KQL)

## Objectif
Confirmer une exfiltration via DNS (T1048.003 / T1071.004) et identifier le processus émetteur + la chaîne d'infection.

## 0) Ce que tu dois voir dans les samples
Le log déclencheur attendu contient au minimum :
`TimeGenerated`, `Computer`, `EventID=22`, `QueryName`, `QueryType`, `Image`, `User`, `DestinationIp`.

## 1) Triage N1 (0-15 min)
1. Lire l'alert : domaine parent et longueur/label du `QueryName`.
2. Vérifier :
   - `QueryType` = TXT / NULL / CNAME
   - un grand nombre de requêtes vers un même parent
   - un émetteur (`Image`) non banal (cmd/powershell/loader) si disponible
3. Exclure rapidement les allowlists (CDN : Akamai/Cloudfront/Azureedge, etc.).

## 2) Investigation N2/N3 (15-60 min)
1. Pivot sur l'hôte et le `User`.
2. Chercher des événements corrélés :
   - Process creation (cmd/powershell/hta/wscript)
   - téléchargements (HTTP) dans les minutes précédentes
   - persistance et accès aux secrets (LSASS dump, credentials)
3. Estimer l'ampleur :
   - volume de requêtes
   - diversité des sous-domaines

## 3) Containment
1. Isoler l'endpoint (EDR network isolate).
2. Bloquer le domaine parent (proxy/firewall/DNS sinkhole).
3. Tuer le processus émetteur si identifié.

## 4) Eradication & Recovery
1. Retirer la persistance.
2. Rotation des secrets potentiellement exfiltrés (tokens, cookies).
3. Re-imagerie si la chaîne d'infection est incomplète.

## 5) Références & Artefacts
- KQL : `sentinel_vitrine/dns_exfiltration/sentinel_rule.kql`
- Sigma : `sentinel_vitrine/dns_exfiltration/sigma_rule.yml`

