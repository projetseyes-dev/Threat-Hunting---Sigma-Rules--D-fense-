# Incident Response Playbook — Suspicious Encoded PowerShell (Sentinel KQL)

## Objectif
Valider qu'une exécution PowerShell obfusquée/encodée correspond à une activité malveillante
(T1059.001 / T1027) : download cradle, exécution IEX, chargement en mémoire.

## 0) Ce que tu dois voir dans les samples
Log déclencheur attendu (future `samples/`) :
`TimeGenerated`, `Computer`, `EventID=4688`, `NewProcessName`, `CommandLine`, `ParentProcessName`, `Account`.

## 1) Triage N1 (0-10 min)
1. Vérifier que `NewProcessName` correspond à `powershell.exe`, `pwsh.exe` ou `powershell_ise.exe`.
2. Vérifier la présence d'indices :
   - `CommandLine` contient `-enc` / `-EncodedCommand` / aliases `-e` / `-ec`
   - présence d'un bypass (ExecutionPolicy, -nop, window hidden)
3. Si possible, décoder la charge (base64) :
   - rechercher dans la commande décodée `IEX`, `Invoke-Expression`, `DownloadString`, IP/URL, Mimikatz.

## 2) Investigation N2/N3 (10-45 min)
1. Reconstituer la chaîne :
   - parent (mshta/wscript/office) qui a lancé PowerShell
   - processus fils et téléchargements dans les minutes précédentes
2. Vérifier l'effet :
   - création de fichiers (dropper), exécution d'un binaire (rundll32/procdump)
   - connexions réseau sortantes et DNS
3. Chercher la persistance :
   - scheduled tasks, run keys, services, registry modifications.

## 3) Containment
1. Isoler l'endpoint.
2. Tuer le(s) processus PowerShell suspects et bloquer le hash/binary.
3. Bloquer domaines/IP contactés (proxy/firewall/DNS sinkhole).

## 4) Eradication & Recovery
1. Supprimer persistance.
2. Rotation tokens/credentials si download de secrets.
3. Re-imagerie si la chaîne d'infection est incomplète.

## 5) Références & Artefacts
- KQL : `sentinel_vitrine/suspicious_powershell_encoded/sentinel_rule.kql`
- Sigma : `sentinel_vitrine/suspicious_powershell_encoded/sigma_rule.yml`

