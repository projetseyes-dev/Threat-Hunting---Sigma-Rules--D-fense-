# Incident Response Playbook — Process Hollowing

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `process_hollowing.yml` |
| **MITRE ATT&CK** | T1055.012 — Process Hollowing |
| **Tactique** | Defense Evasion / Privilege Escalation |
| **Sévérité** | High |
| **SLA Triage (N1)** | 15 min |
| **SLA Containment (N2/N3)** | 60 min |

---

## 1. Contexte de la menace

Le **Process Hollowing** consiste à créer un processus légitime en état suspendu (`CREATE_SUSPENDED`), à dé-mapper sa section mémoire principale (`NtUnmapViewOfSection`), à y écrire un payload malveillant (`WriteProcessMemory`), à recalibrer le contexte (`SetThreadContext`), puis à reprendre l'exécution (`ResumeThread`).

Résultat : un processus de confiance (signé Microsoft) exécute du code arbitraire — contournement des AV, des allowlists applicatives (AppLocker/WDAC) et des règles basées sur le nom d'image.

**Familles connues** : Dridex, Emotet, TrickBot, Cobalt Strike (`spawnto`), Meterpreter (`migrate`).

---

## 2. Triage initial (Analyste N1 — 0 à 15 min)

### 2.1 Vérifications immédiates

- [ ] Confirmer que l'alerte n'est pas un **doublon** (corrélation `host`, `parent_pid`, dernières 24 h).
- [ ] Identifier le **propriétaire** de la machine (CMDB / IAM).
- [ ] Identifier la **criticité de l'asset** (DC, serveur métier, poste utilisateur, jump host).
- [ ] Vérifier la signature numérique du **parent** et de l'**image cible**.

### 2.2 Requêtes de pivot

**Splunk SPL :**

```spl
index=sysmon EventCode=1 host=$host$
| where match(ParentImage, "(?i)\\\\(powershell|cmd|wscript|cscript|mshta|winword|excel|outlook)\\.exe$")
| stats count values(CommandLine) values(Hashes) by Image, ParentImage, User, _time
| sort -_time
```

**Sentinel KQL :**

```kql
DeviceProcessEvents
| where DeviceName == "$host$"
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","winword.exe")
| where FileName in~ ("svchost.exe","explorer.exe","notepad.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### 2.3 Critères d'escalade vers N2

- Parent = **Office** (winword/excel/outlook) → **escalade immédiate** (probable phishing).
- Image cible exécutée depuis `%TEMP%`, `%APPDATA%`, `\Users\Public\` → escalade.
- Hash inconnu de VirusTotal / non signé → escalade.
- Connexion réseau sortante du processus enfant dans les 5 min → escalade.

---

## 3. Investigation approfondie (Analyste N2 — 15 à 60 min)

### 3.1 Collecte forensique à chaud

Sur l'endpoint suspect, via l'agent EDR (live response) :

```powershell
Get-Process -Id <PID> | Format-List *
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,8,10,25} -MaxEvents 500
```

Outils recommandés :

| Action | Outil |
|--------|-------|
| Dump mémoire du processus | `procdump64.exe -ma <PID>` |
| Listing des modules chargés | `listdlls.exe <PID>` |
| Détection d'image hollowed | `pe-sieve.exe /pid <PID>` (Hasherezade) |
| Analyse statique du dump | `volatility3 -f mem.raw windows.malfind` |

### 3.2 Indicateurs à extraire

- Hash SHA256 du **parent**, de l'**enfant**, de tout DLL injecté.
- Connexions réseau sortantes (Sysmon EID 3) du processus suspect.
- Persistance créée : Run keys, Scheduled Tasks (Sysmon EID 12-13, EID 1 vers `schtasks.exe`).
- Comptes utilisés (User, IntegrityLevel).
- Mouvement latéral : EID 4624 type 3/10, SMB sessions, WMI (EID 19-21).

### 3.3 Hunt élargi (organisation entière)

```spl
index=sysmon EventCode=1 earliest=-7d
| where match(ParentImage, "(?i)(winword|excel|outlook)\\.exe$")
  AND match(Image, "(?i)\\\\(svchost|rundll32|regsvr32)\\.exe$")
| stats dc(host) as nb_hosts values(host) as hosts by Hashes
| where nb_hosts > 1
```

> Si `nb_hosts > 1` : suspicion de campagne en cours → **déclencher CSIRT**.

---

## 4. Containment (N2/N3 — < 60 min)

| # | Action | Outil | Réversible |
|---|--------|-------|-----------|
| 1 | Isoler l'endpoint du réseau | EDR (Defender/CrowdStrike/SentinelOne `network-isolate`) | Oui |
| 2 | Tuer le processus malveillant | EDR `kill-process` | Oui |
| 3 | Désactiver le compte utilisateur compromis | AD `Disable-ADAccount` | Oui |
| 4 | Révoquer les sessions Kerberos | `klist purge` + reset TGT (KRBTGT si DC compromis) | Partiel |
| 5 | Bloquer les IOC réseau | Firewall / proxy / DNS sinkhole | Oui |
| 6 | Mettre les hashes en blocklist | EDR / AV global | Oui |

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression de la persistance (registre, tâches planifiées, services, WMI subscriptions).
   - Suppression des fichiers droppés (chemin issu de Sysmon EID 11).
   - Si le compte avait des privilèges privilégiés : **rotation KRBTGT × 2** + reset des comptes de service.
2. **Recovery**
   - Restauration depuis golden image si l'asset est critique ou si la persistance est incertaine.
   - Réintégration AD après validation EDR (scan complet + 24 h sans alerte).
3. **Validation** : exécuter un test Atomic Red Team `T1055.012` après remédiation pour s'assurer que la détection fonctionne toujours.

---

## 6. Communication

| Audience | Canal | Délai |
|----------|-------|-------|
| Manager SOC | Ticket + Slack #soc-incidents | Immédiat |
| RSSI | Email + briefing | < 2 h si Sev=High |
| Métier impacté | Ticketing ITSM | < 4 h |
| CERT-FR / régulateur | Notification CNIL si données perso | Selon RGPD (72 h) |

---

## 7. Lessons Learned

À documenter dans le RETEX (post-mortem sous 5 jours ouvrés) :

- Vecteur initial confirmé (phishing ? exploit ? supply chain ?).
- Faille de détection (combien de temps avant alerte ?).
- Tuning de la règle Sigma (faux positifs identifiés ?).
- Mise à jour des contrôles préventifs (politique Office, ASR rules, AppLocker).
- Création d'une règle Sigma dérivée si nouveau TTP observé.

---

## 8. Références

- ATT&CK T1055.012 : <https://attack.mitre.org/techniques/T1055/012/>
- PE-sieve (Hasherezade) : <https://github.com/hasherezade/pe-sieve>
- Atomic Test T1055.012 : <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md>
- Elastic Security Labs — Process Hollowing : <https://www.elastic.co/security-labs/process-hollowing-detection>
