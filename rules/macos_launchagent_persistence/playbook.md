# Incident Response Playbook — macOS LaunchAgent / LaunchDaemon Persistence

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `macos_launchagent_persistence.yml` |
| **MITRE ATT&CK** | T1543.001 / T1543.004 |
| **Tactique** | Persistence / Privilege Escalation |
| **Sévérité** | High |
| **SLA Triage (N1)** | 15 min |
| **SLA Containment (N2/N3)** | 60 min |

---

## 1. Contexte

`launchd` (PID 1) est le processus de démarrage et de gestion des services sur macOS. Tout fichier `.plist` placé aux emplacements suivants est chargé automatiquement :

| Chemin | Scope | Privilèges |
|--------|-------|-----------|
| `~/Library/LaunchAgents/` | User | Utilisateur |
| `/Library/LaunchAgents/` | All users | Utilisateur courant |
| `/Library/LaunchDaemons/` | System | **root** |
| `/System/Library/LaunchAgents/` | Apple only (SIP-protégé) | — |

C'est la méthode de persistance **#1** utilisée par les malwares macOS (XCSSET, ChromeLoader, RustBucket/RUSTYDOOR, KandyKorn, Atomic Stealer, Pipemon).

**Indicateurs caractéristiques :**

- `.plist` créé hors apps légitimes (chemin `/Users/Shared/`, `/private/tmp/`).
- Binaire référencé dans `ProgramArguments` situé hors `/Applications/*.app/Contents/MacOS/`, `/usr/bin`, `/usr/sbin`.
- Naming d'apparence Apple mais incorrect (`com.appie.update`, `com.adobee.helper`).
- **Non signé** ou signé par un Team ID jamais vu.

---

## 2. Triage initial (N1 — 0 à 15 min)

### 2.1 Vérifications immédiates

- [ ] **Path du .plist** : user-scope (`~/Library/`) ou system-scope (`/Library/LaunchDaemons/` → privilèges root requis pour l'écrire).
- [ ] **Process créateur** : `bash`, `curl`, `python`, `osascript`, navigateur ? Ou installeur signé Apple ?
- [ ] **`process_team_id`** : Apple Developer ID connu (DRA4OY7..., 9SBQ27Z...) ou inconnu/absent ?
- [ ] **Nom du .plist** : ressemble à un service Apple (`com.apple.X`) sans en être un = très suspect.

### 2.2 Requêtes de pivot

**Sentinel KQL (Defender for Endpoint macOS) :**

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where DeviceName == "$host$"
| where FolderPath has_any ("/Library/LaunchAgents","/Library/LaunchDaemons")
| where FileName endswith ".plist"
| project Timestamp, FileName, FolderPath, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessSignatureStatus
| order by Timestamp desc
```

**Splunk SPL (Elastic Security / SentinelOne / Jamf Protect) :**

```spl
index=macos_esf event_type IN ("ES_EVENT_TYPE_NOTIFY_CREATE","ES_EVENT_TYPE_NOTIFY_WRITE")
target_path IN ("/Library/LaunchAgents/*","/Library/LaunchDaemons/*","*/LaunchAgents/*")
| table _time, host, target_path, process_path, process_command_line, process_team_id, user_name
| sort -_time
```

### 2.3 Critères d'escalade

- `.plist` dans `/Library/LaunchDaemons/` créé par un process **non-installeur Apple** → P0 (root déjà obtenu).
- Process créateur = navigateur (`Safari`, `Google Chrome Helper`) ou Office (`Word`, `Excel`) → P0 (drive-by/macro).
- Binaire référencé dans `/private/tmp/`, `/Users/Shared/`, `~/Library/Caches/` → P0.
- Signature absente / Team ID inconnu → P0.
- Activité Gatekeeper bypass (`spctl --master-disable`, xattr -d com.apple.quarantine) → P0.

---

## 3. Investigation N2/N3

### 3.1 Inspection du .plist

```bash
plutil -p /path/to/suspicious.plist
codesign -dv --verbose=4 "$(plutil -extract ProgramArguments.0 raw /path/to/suspicious.plist)"
spctl -a -vvv "$(plutil -extract ProgramArguments.0 raw /path/to/suspicious.plist)"
xattr -p com.apple.quarantine "$(plutil -extract ProgramArguments.0 raw /path/to/suspicious.plist)"
```

Champs à analyser :

- `Label` — convention Apple = reverse domain ; un nom étrange est suspect.
- `ProgramArguments` — chemin du binaire + arguments.
- `RunAtLoad` / `KeepAlive` — true = exécution automatique.
- `StartInterval` / `StartCalendarInterval` — beaconing.
- `WatchPaths` — déclenchement sur modification fichier.

### 3.2 Analyse du binaire

```bash
file /path/to/binary
otool -L /path/to/binary
codesign -dv --verbose=4 /path/to/binary
shasum -a 256 /path/to/binary
```

Soumettre hash à VirusTotal / Intezer / OSXCollector.

### 3.3 Reconstitution de la chaîne d'infection

Outils :

- **`KnockKnock`** (Objective-See) : énumère TOUS les mécanismes de persistance.
- **`RansomWhere?`** : monitoring fichiers.
- **`Aulr`** / **`mac_apt`** : forensics complet.
- **`log show`** : `log show --last 24h --predicate 'eventMessage contains "launchd"'`.

```bash
log show --last 1h --predicate 'process == "launchd"' --info
log show --last 1h --predicate 'eventMessage contains "submitted"' --info
fs_usage -w -f filesys $PID
```

### 3.4 Hunt élargi

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/Library/LaunchAgents","/Library/LaunchDaemons")
| where FileName endswith ".plist"
| where InitiatingProcessSignatureStatus != "Signed"
   or InitiatingProcessFileName in~ ("bash","sh","zsh","python","python3","curl","wget","osascript")
| summarize Hosts = dcount(DeviceName), make_set(DeviceName, 50) by FileName
| where Hosts > 1
```

> Si `Hosts > 1` : **campagne en cours**.

### 3.5 Recherche de mécanismes adjacents (souvent combinés)

| Persistance | Emplacement |
|-------------|-------------|
| LoginItems | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent` |
| Login Hooks | `defaults read com.apple.loginwindow LoginHook` |
| Cron / at | `crontab -l`, `/usr/lib/cron/tabs/` |
| Periodic | `/etc/periodic/` |
| Configuration profiles | `/Library/Managed Preferences/`, `profiles list` |
| Dylib hijacking | analyse `otool -L` des apps signées |
| Emond (déprécié 13.x) | `/etc/emond.d/rules/` |

---

## 4. Containment

| # | Action | Commande |
|---|--------|----------|
| 1 | Décharger le service | `launchctl bootout system/<label>` ou `launchctl unload <path>` |
| 2 | Tuer le process actif | `kill -9 $PID` |
| 3 | Quarantaine du .plist + binaire | `mv` vers répertoire isolé read-only |
| 4 | Isoler l'endpoint | EDR network-isolate |
| 5 | Bloquer le hash binaire | EDR / Gatekeeper / Santa policy |
| 6 | Bloquer les domaines C2 | Firewall / proxy / DNS |
| 7 | Désactiver le compte utilisateur impacté | si phishing confirmé |

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression de TOUS les artefacts (LaunchAgent, LaunchDaemon, LoginItems, Cron, Profiles).
   - Audit `KnockKnock` complet sur l'endpoint.
   - Vérification de l'absence de **dylib hijacking** dans les apps légitimes.
2. **Recovery**
   - Re-imagerie via DEP/MDM si root persistait (LaunchDaemon en `/Library/LaunchDaemons/`).
   - Reset des credentials Keychain (potentiellement volés).
   - Audit iCloud / iCloud Keychain (sync vers d'autres devices).
3. **Hardening**
   - **Gatekeeper enforcing** (refus binaires non notarisés).
   - **System Integrity Protection (SIP)** activé (`csrutil status` → enabled).
   - **EDR avec ESF** : SentinelOne, Defender, CrowdStrike Falcon, Jamf Protect.
   - **Santa** (Google) : binary allowlisting.
   - **MDM (Jamf/Kandji/Mosyle)** avec restriction des LaunchAgents non signés.
   - **FileVault** activé.
   - **Login items audit** trimestriel sur la flotte.

---

## 6. Communication

- Si endpoint d'un VIP / dirigeant → escalade immédiate (cible privilégiée).
- Si malware financier (stealer Keychain) → réinitialiser tous les mots de passe stockés.
- Si APT pressentie (ex: Lazarus, BlueNoroff) → CERT-FR.

---

## 7. Lessons Learned

- L'utilisateur a-t-il téléchargé un installeur depuis source non officielle ?
- Gatekeeper était-il en `enforcing` ?
- L'EDR ESF couvrait-il bien les events `NOTIFY_CREATE` sur les chemins LaunchAgents ?
- Y avait-il des **profiles MDM** restrictifs ?
- Mesure du **dwell time** entre création persistance et détection.

---

## 8. Références

- ATT&CK T1543.001 : <https://attack.mitre.org/techniques/T1543/001/>
- ATT&CK T1543.004 : <https://attack.mitre.org/techniques/T1543/004/>
- Objective-See (P. Wardle) : <https://objective-see.org/tools.html>
- The Art of Mac Malware (P. Wardle) : <https://taomm.org/>
- SentinelLabs — macOS Threat Reports : <https://www.sentinelone.com/labs/category/macos-malware/>
- Atomic Test T1543.001 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1543.001>
