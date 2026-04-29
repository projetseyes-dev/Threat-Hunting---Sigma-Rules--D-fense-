# Incident Response Playbook — Suspicious Encoded PowerShell

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `suspicious_powershell_encoded.yml` |
| **MITRE ATT&CK** | T1059.001 / T1027 |
| **Tactique** | Execution / Defense Evasion |
| **Sévérité** | High |
| **SLA Triage (N1)** | 10 min |
| **SLA Containment (N2/N3)** | 45 min |

---

## 1. Contexte de la menace

PowerShell est l'un des **LOLBins** les plus utilisés par les attaquants : présent partout, signé Microsoft, capable d'opérations en mémoire (fileless), avec un riche écosystème offensif (Empire, PoshC2, Nishang, Powersploit, Invoke-Mimikatz).

L'**obfuscation** vise à contourner :

- Les antivirus signature-based.
- Les règles AppLocker / WDAC.
- Les inspections de ligne de commande basiques.

**Indicateurs comportementaux :**

- `-EncodedCommand` (alias `-enc`, `-e`) avec base64.
- `-ExecutionPolicy Bypass` + `-WindowStyle Hidden` + `-NoProfile`.
- `IEX (New-Object Net.WebClient).DownloadString(...)`.
- Reflective loading : `[Reflection.Assembly]::Load([Convert]::FromBase64String(...))`.
- Concaténation/inversion de chaînes : `('iex' | iex)`, `[char[]]`, etc.

---

## 2. Triage initial (N1 — 0 à 10 min)

### 2.1 Décodage immédiat

Si la commande contient `-EncodedCommand <BASE64>` :

```powershell
$b64 = "<BASE64_ICI>"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
```

Ou en bash :

```bash
echo "<BASE64>" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

> Une commande décodée révélant `IEX`, `DownloadString`, `Mimikatz`, `Invoke-`, des IPs externes, ou du **shellcode binaire** = **escalade immédiate**.

### 2.2 Contextualisation

- [ ] **Parent process** : `winword.exe`, `outlook.exe`, `excel.exe` → phishing (CRITIQUE).
- [ ] **Parent process** : `mshta.exe`, `wscript.exe`, `cscript.exe` → loader script (CRITIQUE).
- [ ] **Utilisateur** : compte admin / service / utilisateur standard ?
- [ ] **Heure** : exécution hors heures ouvrées ?
- [ ] **Hash** PowerShell.exe : version officielle Microsoft ?

### 2.3 Requêtes de pivot

**Splunk SPL :**

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| eval encoded=if(match(CommandLine,"(?i)\\s-(enc|e|ec)\\s"),"yes","no")
| where encoded="yes"
| stats count values(CommandLine) values(ParentImage) values(User) by host
| sort -count
```

**Sentinel KQL :**

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(enc|e|ec|EncodedCommand)\s"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### 2.4 Critères d'escalade

- Commande décodée contient `IEX`, `DownloadString`, IPs externes → P0.
- Parent = Office / mshta / scripts → P0 (phishing/macros).
- Hash inconnu de VirusTotal → P1.
- Téléchargement effectif observé (Sysmon EID 3) → P0.

---

## 3. Investigation N2/N3

### 3.1 Activation de la télémétrie PowerShell complète

Si pas déjà actif, **activer immédiatement** sur les endpoints à risque :

| Mécanisme | EventID | Source |
|-----------|---------|--------|
| Module Logging | 4103 | Microsoft-Windows-PowerShell/Operational |
| **Script Block Logging** | **4104** | Microsoft-Windows-PowerShell/Operational |
| Transcription | N/A | Fichiers `.txt` |
| AMSI | 4104 (warnings) | Defender ATP |

Configuration GPO :
`Computer Configuration > Admin Templates > Windows Components > PowerShell > Turn on PowerShell Script Block Logging`

### 3.2 Analyse du Script Block (EID 4104)

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104 host=$host$
| table _time, ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal
| sort _time
```

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where DeviceName == "$host$"
| project Timestamp, AdditionalFields
| extend Script = tostring(parse_json(AdditionalFields).Command)
| where Script has_any ("Invoke-Mimikatz","DownloadString","FromBase64String",
                        "Reflection.Assembly","Net.Sockets.TCPClient")
```

### 3.3 De-obfuscation avancée

Outils :

- **PowerDecode** : <https://github.com/Malandrone/PowerDecode>
- **Revoke-Obfuscation** (Mandiant) : <https://github.com/danielbohannon/Revoke-Obfuscation>
- **CyberChef** : recettes "From Base64" + "Decode Text UTF-16LE" + "Strings".

### 3.4 Recherche d'IOC dans la chaîne

- **URLs / IPs** dans la commande décodée → vérification CTI + sinkhole DNS.
- **Hashes** des binaires téléchargés.
- **Mutex / Named Pipes** (signatures Cobalt Strike `MSSE-...-server`, `postex_...`).
- **User-Agents** atypiques dans les logs proxy/EDR.

---

## 4. Containment

| # | Action |
|---|--------|
| 1 | Isolation EDR de l'endpoint |
| 2 | Tuer toutes les instances PowerShell suspectes (`Stop-Process`) |
| 3 | Bloquer les domaines/IP contactés (firewall, proxy, DNS) |
| 4 | Bloquer les hashes des binaires téléchargés |
| 5 | Désactiver le compte utilisateur le temps de l'investigation |
| 6 | Snapshot mémoire si EDR le permet (timeline complète) |
| 7 | Si phishing confirmé : **rappeler les emails** via M365 ZAP, **bloquer l'expéditeur** |

---

## 5. Eradication & Recovery

1. Identifier et supprimer la **persistance** :
   - Run/RunOnce keys.
   - Tâches planifiées avec PowerShell encodé.
   - WMI Event Subscriptions (T1546.003).
   - Services / drivers déposés.
2. Recherche de **mouvements latéraux** :
   - WinRM / Invoke-Command.
   - PsExec, PowerShell remoting.
   - Comptes touchés ces 24 dernières heures.
3. Reset des credentials des comptes ayant exécuté du PS suspect (mémoire potentiellement compromise).
4. Re-imagerie de l'endpoint si la chaîne d'infection n'est pas traçable de bout en bout.

---

## 6. Durcissement

- [ ] Activer **Constrained Language Mode** pour les utilisateurs standards.
- [ ] Activer **AMSI** + Defender ATP intégration.
- [ ] **WDAC / AppLocker** : restreindre l'exécution PowerShell aux scripts signés.
- [ ] Désactiver **PowerShell v2** (legacy, contourne le logging) :
      `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindows-PowerShellV2Root`.
- [ ] Activer **Script Block Logging** + **Module Logging** + **Transcription** par GPO.
- [ ] **ASR rules** :
  - `D1E49AAC-8F56-4280-B9BA-993A6D77406C` (Block process creations originating from PSExec and WMI commands)
  - `D3E037E1-3EB8-44C8-A917-57927947596D` (Block JavaScript or VBScript from launching downloaded executable content)
  - `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` (Block execution of potentially obfuscated scripts)

---

## 7. Communication

- Si phishing : alerter les utilisateurs (campagne sensibilisation).
- Si compte privilégié compromis : RSSI + briefing direction.
- Si APT suspectée : CERT-FR / partenaires sectoriels (CSIRT pairs).

---

## 8. Lessons Learned

- L'EID 4104 était-il bien activé et ingéré dans le SIEM ?
- AMSI a-t-il bloqué une partie de la chaîne ?
- Les utilisateurs standards avaient-ils légitimement besoin d'un PowerShell non contraint ?
- Combien de variantes obfusquées la règle Sigma a-t-elle manquées ? → tuning continu via Purple Team.

---

## 9. Références

- ATT&CK T1059.001 : <https://attack.mitre.org/techniques/T1059/001/>
- Mandiant — PowerShell Obfuscation : <https://www.mandiant.com/resources/blog/powershell-obfuscation>
- Microsoft — PowerShell Logging : <https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows>
- Atomic Test T1059.001 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.001>
- Revoke-Obfuscation : <https://github.com/danielbohannon/Revoke-Obfuscation>
