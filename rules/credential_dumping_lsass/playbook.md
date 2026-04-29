# Incident Response Playbook — LSASS Credential Dumping

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `credential_dumping_lsass.yml` |
| **MITRE ATT&CK** | T1003.001 — LSASS Memory |
| **Tactique** | Credential Access |
| **Sévérité** | **Critical** |
| **SLA Triage (N1)** | 5 min |
| **SLA Containment (N2/N3)** | 15 min |

---

## 1. Contexte de la menace

`lsass.exe` (Local Security Authority Subsystem Service) maintient en mémoire :

- Hashes NTLM et clés Kerberos de tous les comptes connectés.
- Tickets TGT/TGS Kerberos.
- Credentials des services en cours.
- WDigest plaintext (si activé / Windows ≤ 2008R2).

Un dump LSASS réussi = **élévation de privilèges immédiate** et fondation pour :

- **Pass-the-Hash** (T1550.002)
- **Pass-the-Ticket / Golden Ticket** (T1558)
- **DCSync** (T1003.006) si admin domaine récupéré
- **Lateral Movement** étendu

> **Toute alerte LSASS Dump est traitée en CRITIQUE jusqu'à preuve du contraire.**

**Outils typiques** : Mimikatz (`sekurlsa::logonpasswords`), ProcDump (`-ma lsass.exe`), comsvcs.dll (`MiniDump`), nanodump, dumpert, pypykatz, Task Manager (Create Dump File).

---

## 2. Triage initial (N1 — 0 à 5 min)

### 2.1 Vérifications express

- [ ] Identifier le **processus source** (`SourceImage`).
- [ ] Vérifier la **signature** du source process (Microsoft, EDR connu, signé ?).
- [ ] Identifier l'**utilisateur** ayant lancé l'action.
- [ ] Vérifier si `GrantedAccess` correspond à un flag de **lecture mémoire** (0x1010, 0x1410, etc.).
- [ ] Présence de **CallTrace** suspect (UNKNOWN, dbgcore.dll, dbghelp.dll en provenance d'un process non-debugger).

### 2.2 Requêtes de pivot

**Splunk SPL :**

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where match(GrantedAccess, "(?i)0x(1010|1410|1438|143A|1FFFFF|101010|1F1FFF|1F2FFF)")
| eval signed=if(match(SourceImage, "(?i)\\\\(MsMpEng|MsSense|csrss|wininit|services|smartscreen)\\.exe$"),"yes","no")
| where signed="no"
| stats count values(SourceImage) values(CallTrace) by host, User, _time
```

**Sentinel KQL :**

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass.exe"
| extend GrantedAccess = tostring(parse_json(AdditionalFields).DesiredAccess)
| where GrantedAccess in ("0x1010","0x1410","0x1438","0x143A","0x1FFFFF","0x1F1FFF")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessSHA256, GrantedAccess
| order by Timestamp desc
```

### 2.3 Critères d'escalade

**Toute alerte non clairement allowlistée = escalade immédiate.**

- Source = process LOLBin (`rundll32`, `comsvcs.dll`, `procdump`, `taskmgr`) → CRITIQUE.
- Source dans `%TEMP%`, `%APPDATA%`, `\Users\Public\` → CRITIQUE.
- Cible = **Domain Controller** → CRITIQUE + CSIRT.
- CallTrace contenant `UNKNOWN(0x...)` → injection in-memory → CRITIQUE.

---

## 3. Investigation N2/N3

### 3.1 Reconstitution de la chaîne d'attaque

```kql
let host="$DeviceName$";
let t0=$Timestamp$;
DeviceProcessEvents | where DeviceName==host
  and Timestamp between (t0 - 1h .. t0 + 30m)
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

À identifier :

- **Vecteur initial** (phishing, exploit, credential reuse, supply chain).
- **Élévation de privilèges** ayant permis l'ouverture de LSASS (token SeDebugPrivilege).
- **Persistence** déjà déposée.
- **Mouvement latéral** ultérieur (logon events, SMB, WMI).

### 3.2 Recherche de dump fichier

LOLBin classique : `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full`

```spl
index=sysmon EventCode=11 (TargetFilename="*lsass*.dmp" OR TargetFilename="*\\dump*.dmp")
| stats values(Image) values(host) by TargetFilename, _time
```

```kql
DeviceFileEvents
| where FileName endswith ".dmp"
| where FolderPath has_any ("Temp","AppData","Public","ProgramData")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.3 Recherche d'exfiltration du dump

- Sysmon EID 3 vers IP externes après l'événement.
- Création d'archives (.zip, .rar, .7z) contenant `.dmp`.
- Upload via `curl`, `Invoke-WebRequest`, `bitsadmin`, `certutil -urlcache`.
- Connexions SMB sortantes.

### 3.4 Hunt latéral

**Tous les comptes dont les credentials étaient en mémoire au moment du dump sont à considérer compromis.**

```kql
DeviceLogonEvents
| where DeviceName == "$host$" and Timestamp between (t0 - 24h .. t0)
| where ActionType == "LogonSuccess"
| summarize make_set(AccountName), make_set(LogonType) by DeviceName
```

→ **Tous les comptes listés doivent voir leur mot de passe rotaté.**

---

## 4. Containment (< 15 min)

| # | Action | Priorité |
|---|--------|----------|
| 1 | **Isoler immédiatement l'endpoint** (EDR network-isolate) | P0 |
| 2 | **Tuer le processus source** | P0 |
| 3 | **Bloquer le hash** du binaire impliqué | P0 |
| 4 | **Désactiver les comptes** présents en mémoire LSASS | P0 |
| 5 | **Révoquer les sessions Kerberos** (`klist purge` global) | P1 |
| 6 | **Forcer rotation** des mots de passe des comptes exposés | P1 |
| 7 | Si Domain Admin exposé → **rotation KRBTGT × 2** (≥ 10 h d'écart) | P0 |
| 8 | Préparer **dump mémoire** + **disque image** pour forensique | P2 |

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression de la persistance.
   - Recherche d'**implants** restant (Cobalt Strike, BRC4, Sliver) via scan EDR + YARA.
   - Validation : aucune alerte EDR/SIEM sur l'asset 24 h après nettoyage.
2. **Recovery**
   - **Re-imagerie systématique** recommandée pour tout asset où LSASS a été dumpé.
   - Restauration AD :
     - Rotation KRBTGT × 2.
     - Audit DCSync (EID 4662 sur DCs avec GUID 1131f6aa, 1131f6ad, 89e95b76).
     - Recherche de Golden Tickets (anomalies EID 4769 — ticket lifetime > 10 h, encryption RC4).
3. **Tier-zero hardening**
   - Activation **Credential Guard** (VBS).
   - Activation **Protected Process Light (PPL)** sur lsass.exe (`RunAsPPL=1`).
   - Activation **ASR rule** "Block credential stealing from lsass" (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`).
   - Désactivation **WDigest** plaintext (`UseLogonCredential=0`).
   - Implémentation **LSA Protection** (registry `RunAsPPL`).

---

## 6. Communication

| Audience | Délai | Canal |
|----------|-------|-------|
| Manager SOC + RSSI | Immédiat | Téléphone + Slack |
| CSIRT / CERT interne | < 30 min | Conf-call |
| Direction si DA compromis | < 1 h | Brief crise |
| CNIL si données perso impactées | ≤ 72 h | Notification officielle |
| ANSSI / CERT-FR si APT | < 24 h | Plateforme dédiée |

---

## 7. Métriques

- **MTTD** ciblé : < 2 min (alerte EDR temps réel).
- **MTTR containment** : < 15 min.
- **Taux de re-imagerie** post-LSASS dump : 100 %.
- **Couverture Credential Guard** sur le parc : > 95 %.

---

## 8. Lessons Learned

- Comment l'attaquant a-t-il obtenu **SeDebugPrivilege** ?
- Pourquoi Credential Guard / PPL n'était-il pas actif ?
- L'ASR rule était-elle déployée mais en **mode audit** seulement ?
- Mise à jour de la **politique Tier 0** : où les DA se sont-ils connectés au cours des 30 derniers jours ?

---

## 9. Références

- ATT&CK T1003.001 : <https://attack.mitre.org/techniques/T1003/001/>
- Microsoft — Credential Guard : <https://learn.microsoft.com/windows/security/identity-protection/credential-guard/>
- ASR rules : <https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference>
- Atomic Test T1003.001 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1003.001>
- ANSSI — Recommandations sécurisation AD : <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-active-directory>
