# Incident Response Playbook — RDP Brute Force

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `rdp_brute_force.yml` |
| **MITRE ATT&CK** | T1110.001 — Password Guessing |
| **Tactique** | Credential Access / Initial Access |
| **Sévérité** | High |
| **SLA Triage (N1)** | 10 min |
| **SLA Containment (N2/N3)** | 30 min |

---

## 1. Contexte de la menace

Le **brute force RDP** (port TCP/3389) est l'un des vecteurs d'intrusion les plus utilisés par les groupes ransomware (Conti, LockBit, BlackCat, Akira). Les attaquants exploitent :

- Des **credentials valides** issus de fuites (combolists).
- Du **password spraying** (1 mot de passe × N utilisateurs) qui contourne les politiques de lockout par compte.
- Des **bots distribués** (réseaux de proxies / résidentiels) pour échapper aux blocages par IP.

Un brute force réussi sur un compte privilégié = **compromission complète probable en < 24 h**.

---

## 2. Triage initial (N1 — 0 à 10 min)

### 2.1 Caractérisation

- [ ] L'IP source est-elle **interne** ou **externe** ?
- [ ] L'IP est-elle déjà connue (CTI / abuseipdb / blocklist) ?
- [ ] La cible est-elle un **DC**, un **jump host**, un **serveur exposé** ?
- [ ] Un EID **4624** (succès) est-il survenu **après** la rafale d'échecs ?

### 2.2 Requêtes de pivot

**Splunk SPL :**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
  src_ip="$IpAddress$" earliest=-1h
| eval result=if(EventCode=4624,"SUCCESS","FAIL")
| stats count by _time, result, user, dest, src_ip
| sort _time
```

**Sentinel KQL :**

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4624, 4625) and LogonType in (10, 3)
| where IpAddress == "$IpAddress$"
| summarize Failures=countif(EventID==4625),
            Successes=countif(EventID==4624),
            TargetedAccounts=dcount(TargetUserName),
            Accounts=make_set(TargetUserName, 50)
            by IpAddress, Computer, bin(TimeGenerated, 5m)
| order by TimeGenerated desc
```

### 2.3 Critères d'escalade vers N2

- ✅ **Au moins 1 EID 4624** après la salve → **escalade immédiate** (compte compromis).
- IP externe avec > 100 échecs / 5 min → escalade.
- Cible = **compte admin** (Domain Admins, local Administrator, comptes de service privilégiés) → escalade.
- Pattern de **password spraying** (> 50 utilisateurs ciblés depuis la même IP) → escalade.

---

## 3. Investigation N2/N3

### 3.1 Si compromission confirmée (4624 réussi)

**Suivre la chaîne d'actions du compte compromis :**

```kql
SecurityEvent
| where TargetUserName == "$compte$" and TimeGenerated > ago(24h)
| project TimeGenerated, EventID, Activity, Computer, IpAddress, LogonType, ProcessName

DeviceProcessEvents
| where AccountName == "$compte$" and Timestamp > ago(24h)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName

DeviceLogonEvents
| where AccountName == "$compte$" and Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| summarize make_set(DeviceName), make_set(RemoteIP) by AccountName
```

### 3.2 Recherche d'outils post-exploitation

À partir du moment du 4624, chercher :

- Exécution de `mimikatz`, `lazagne`, `secretsdump`, `procdump lsass`.
- Création de comptes locaux/AD (EID 4720, 4732).
- Outils RMM (AnyDesk, ScreenConnect, TeamViewer) installés.
- Utilisation de **PsExec**, **WMI**, **WinRM** (mouvement latéral).
- Désactivation de **Defender** ou de l'EDR (EID 1102 - clear log, EID 7045 - service install).

### 3.3 Hunt sur l'historique de l'IP source (1 mois)

```spl
index=wineventlog EventCode=4625 src_ip="$IpAddress$" earliest=-30d
| stats count dc(dest) as nb_targets dc(user) as nb_users by src_ip
```

---

## 4. Containment

### 4.1 Action immédiate (< 30 min)

| # | Action | Détail |
|---|--------|--------|
| 1 | **Bloquer l'IP** au firewall périmétrique | Inclure l'AS/CIDR si bot multiple |
| 2 | **Désactiver le compte** ciblé (si succès) | `Disable-ADAccount -Identity <user>` |
| 3 | **Forcer la déconnexion** des sessions actives | `quser` puis `logoff <ID>` |
| 4 | **Reset du mot de passe** + révocation tickets Kerberos | `Set-ADAccountPassword`, `klist purge` |
| 5 | **Isoler la cible RDP** si exécution post-auth | EDR network-isolate |

### 4.2 Durcissement à chaud

- [ ] Restreindre RDP via **Network Level Authentication (NLA)**.
- [ ] Imposer **MFA RDP** (Azure MFA NPS / Duo / RDP Gateway).
- [ ] Couper l'exposition Internet → **Bastion / VPN / RDP Gateway** uniquement.
- [ ] Activer **Account Lockout Policy** (5 tentatives / 15 min).
- [ ] Activer **Windows Defender Network Protection** + **ASR rule** "Block credential stealing from lsass".

---

## 5. Eradication & Recovery

1. Si la machine cible a été utilisée comme tête de pont : **dump mémoire LSASS**, recherche d'outils, scan EDR complet, ré-imagerie si doute.
2. Si compte de service compromis : **rotation immédiate**, audit des SPN, vérification des délégations Kerberos (TrustedForDelegation).
3. Si DC compromis : **rotation KRBTGT × 2** (intervalle ≥ 10 h), audit complet AD (DCSync, Golden Ticket → vérifier EID 4769 anormaux).

---

## 6. Métriques à reporter

| Métrique | Calcul | Cible |
|----------|--------|-------|
| MTTD | T(alerte) − T(1ère tentative) | < 5 min |
| MTTR | T(blocage IP) − T(alerte) | < 30 min |
| Couverture MFA RDP | % serveurs avec MFA / total exposés | 100% |
| Exposition RDP Internet | nb d'IP publiques avec port 3389 | 0 |

---

## 7. Communication

- Slack `#soc-alerts` : ping immédiat avec IP, cible, statut.
- Si succès d'authentification : **incident formel** ouvert + RSSI averti < 1 h.
- Si données sensibles potentiellement accédées : process **RGPD** (notification CNIL ≤ 72 h).

---

## 8. Lessons Learned

- Pourquoi le RDP était-il exposé ? Cartographie périmétrique à mettre à jour.
- La politique de mot de passe a-t-elle tenu ? Audit de la complexité / longueur.
- Le lockout policy était-il actif ?
- Mesurer le **dwell time** entre 1ère tentative et détection.

---

## 9. Références

- ATT&CK T1110.001 : <https://attack.mitre.org/techniques/T1110/001/>
- Microsoft — RDP Brute Force : <https://www.microsoft.com/security/blog/2020/04/16/threat-protection-rdp-brute-force-attacks/>
- Atomic Test T1110.001 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.001>
- ANSSI — Recommandations RDP : <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-active-directory>
