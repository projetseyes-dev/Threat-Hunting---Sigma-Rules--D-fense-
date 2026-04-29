# Incident Response Playbook — DNS Exfiltration

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `dns_exfiltration.yml` |
| **MITRE ATT&CK** | T1048.003 / T1071.004 |
| **Tactique** | Exfiltration / Command and Control |
| **Sévérité** | High |
| **SLA Triage (N1)** | 15 min |
| **SLA Containment (N2/N3)** | 60 min |

---

## 1. Contexte de la menace

Le **DNS tunneling** détourne le protocole DNS (UDP/53, parfois DoH/DoT) pour exfiltrer des données ou maintenir un canal C2. Le DNS est rarement bloqué et souvent peu inspecté → vecteur idéal pour passer sous les radars.

**Signaux caractéristiques :**

- Sous-domaines très longs encodés (base32/base64).
- Volume anormal de requêtes vers un même domaine parent (RPM élevé).
- QType atypiques : `TXT`, `NULL`, `CNAME`.
- Faible TTL côté serveur faisant autorité.
- Domaines récemment enregistrés (NRD < 30 jours).

**Outils connus** : `dnscat2`, `iodine`, `DNSExfiltrator`, `DNSStager`, Cobalt Strike DNS beacon, APT34/OilRig DNSpionage.

---

## 2. Triage initial (N1 — 0 à 15 min)

### 2.1 Caractérisation rapide

- [ ] Identifier le **domaine parent** (eTLD+1) ciblé.
- [ ] Évaluer la **réputation** : `whois`, VirusTotal, URLhaus, PassiveDNS.
- [ ] Vérifier la **date de création** (NRD = Newly Registered Domain → suspect).
- [ ] Identifier le **processus émetteur** (Sysmon EID 22 - DnsQuery).
- [ ] Compter le **volume** : > 100 req/min = très suspect.

### 2.2 Requêtes de pivot

**Splunk SPL (Sysmon EID 22) :**

```spl
index=sysmon EventCode=22 host=$host$
| eval len=len(QueryName)
| stats count avg(len) as avg_len max(len) as max_len
        values(Image) as processes by QueryName
| where count > 50 OR avg_len > 60
| sort -count
```

**Sentinel KQL :**

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "DnsQueryResponse" or RemotePort == 53
| extend QueryLen = strlen(RemoteUrl)
| summarize Total=count(),
            AvgLen=avg(QueryLen),
            MaxLen=max(QueryLen),
            UniqueQueries=dcount(RemoteUrl)
            by DeviceName, InitiatingProcessFileName, parent_domain=tostring(split(RemoteUrl, ".")[-2])
| where Total > 100 or AvgLen > 60
| order by Total desc
```

### 2.3 Critères d'escalade

- Domaine parent NRD (< 30 j) → escalade.
- Volume > 500 requêtes / 5 min vers un même parent → escalade.
- Processus émetteur **non-navigateur** (cmd, powershell, rundll32, mshta, nslookup en boucle) → escalade.
- Pic d'activité hors heures ouvrées → escalade.

---

## 3. Investigation N2/N3

### 3.1 Caractérisation du tunnel

```spl
index=sysmon EventCode=22 host=$host$ QueryName=*$parent_domain$*
| stats count by QueryName, QueryType
| sort -count
| head 50
```

À analyser :

- **Entropie de Shannon** des sous-domaines (>= 3.5 bits/char → encodé).
- **Distribution** des QType (forte proportion de TXT/NULL = anormal).
- **Périodicité** (beacon régulier toutes les X secondes ?).

### 3.2 Calcul d'entropie (script ad-hoc)

```python
import math
def entropy(s):
    p = [s.count(c)/len(s) for c in set(s)]
    return -sum(x*math.log2(x) for x in p)
```

> Sur un échantillon de sous-domaines, entropie moyenne **> 3.5** = exfiltration probable.

### 3.3 Identification du processus malveillant

- Sysmon EID 22 → `Image` du processus émetteur.
- Sysmon EID 1 → ligne de commande, parent, user.
- Sysmon EID 3 → connexions sortantes annexes.
- EDR : timeline complète sur 24 h.

### 3.4 Estimation du volume exfiltré

```
volume_exfil ≈ nb_requetes × longueur_moyenne_subdomain × log2(36) / 8 (octets)
```

Exemple : 10 000 requêtes × 50 chars utiles ≈ **300 Ko** exfiltrés.

---

## 4. Containment

| # | Action | Outil |
|---|--------|-------|
| 1 | **Sinkhole DNS** du domaine parent | DNS interne (BIND/RPZ, AD-DNS, Pi-hole, Infoblox) |
| 2 | **Bloquer le domaine** côté proxy/firewall | Palo Alto, Fortinet, Zscaler, Umbrella |
| 3 | **Isoler l'endpoint émetteur** | EDR network-isolate |
| 4 | **Tuer le processus** identifié | EDR kill-process |
| 5 | **Bloquer le hash** du binaire malveillant | EDR blocklist |
| 6 | **Forcer DNS interne** + bloquer DoH/DoT externe | Firewall : block 853/tcp, 443/tcp vers résolveurs publics |

---

## 5. Eradication & Recovery

1. **Identifier la persistance** :
   - Tâches planifiées (Sysmon EID 1 vers `schtasks.exe`).
   - Run keys / services / WMI subscriptions.
   - DLL search order hijacking.
2. **Inventaire des données accédées** :
   - Logs d'accès aux fichiers (4663) sur les partages.
   - Historique navigateur, clipboard, screenshots.
3. **Mesure d'impact** :
   - Volume estimé × type de données (PII, secrets, IP) → impact RGPD/business.
4. **Rotation des secrets** potentiellement exfiltrés (cookies de session, tokens API, credentials).
5. **Re-imagerie** de l'endpoint si la chaîne d'infection n'est pas tracée intégralement.

---

## 6. Durcissement post-incident

- [ ] Filtrage DNS sortant **uniquement** via résolveurs internes.
- [ ] Blocage **DoH (Cloudflare 1.1.1.1, Google 8.8.8.8)** sortant.
- [ ] Mise en place d'une **threat intel feed** (NRD, DGA, tunneling).
- [ ] Activation **Sysmon EID 22** sur tous les endpoints (config Olaf Hartong / SwiftOnSecurity).
- [ ] Limite de **longueur de label DNS** côté résolveur (drop > 60 chars).
- [ ] Détection ML (entropie, volume, périodicité) — Splunk MLTK / Sentinel UEBA.

---

## 7. Communication

- Si données sensibles confirmées exfiltrées → **notification CNIL ≤ 72 h**.
- Si IP / propriété intellectuelle → DSI + juridique + direction.
- CERT-FR si APT suspectée.

---

## 8. Lessons Learned

- Pourquoi le DNS sortant n'était-il pas inspecté ?
- Quelle visibilité existait sur les flux DNS (full PCAP ? logs résolveur ?) ?
- Le NDR / firewall de nouvelle génération aurait-il dû déclencher ?
- Tuner la règle Sigma : ajuster seuils, allowlists CDN, métriques d'entropie.

---

## 9. Références

- ATT&CK T1048.003 : <https://attack.mitre.org/techniques/T1048/003/>
- ATT&CK T1071.004 : <https://attack.mitre.org/techniques/T1071/004/>
- Unit 42 — DNS Tunneling : <https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/>
- SANS — Detecting DNS Tunneling : <https://www.sans.org/white-papers/34152/>
- Atomic Test T1048.003 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1048.003>
