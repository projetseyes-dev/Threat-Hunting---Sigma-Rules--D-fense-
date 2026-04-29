# Incident Response Playbook — Azure AD Privileged Role Assignment

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `azure_privileged_role_assignment.yml` |
| **MITRE ATT&CK** | T1098.003 — Additional Cloud Roles |
| **Tactique** | Persistence / Privilege Escalation |
| **Sévérité** | **Critical** |
| **SLA Triage (N1)** | 5 min |
| **SLA Containment (N2/N3)** | 15 min |

---

## 1. Contexte

L'attribution **permanente** d'un rôle Azure AD privilégié hors PIM est l'un des **TTPs préférés des opérateurs cloud** (Storm-0558, Midnight Blizzard / NOBELIUM, Octo Tempest). Une fois `Global Administrator` obtenu, l'attaquant peut :

- Lire/exporter toutes les boîtes Exchange Online (`MailItemsAccessed`).
- Créer des **Application Registrations** avec `Mail.Read`, `Files.Read.All` (consent admin).
- Désactiver les **policies de sécurité** (Conditional Access, MFA).
- Créer des **federations malveillantes** (Backdoor via SAML — Solorigate).
- Compromettre l'AD on-prem via **Pass-the-PRT** ou Azure AD Connect.

**Toute attribution permanente d'un rôle critique HORS PIM est traitée en P0.**

---

## 2. Triage initial (N1 — 0 à 5 min)

### 2.1 Vérifications immédiates

- [ ] **`initiatedBy.user.userPrincipalName`** — qui a effectué l'attribution ?
- [ ] **Cible** — quel utilisateur reçoit le rôle ?
- [ ] **Rôle** — quel niveau de privilège ?
- [ ] **`ipAddress`** — IP corporate, VPN connu, ou IP suspecte (ASN datacenter, hosting, Tor) ?
- [ ] **Heure** — heure ouvrée pour l'admin déclencheur ?
- [ ] **Ticket ITSM/RSA correspondant** — y a-t-il une demande légitime documentée ?

### 2.2 Requêtes de pivot

**Sentinel KQL :**

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName has_any ("Add member to role","Add eligible member to role")
| extend RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Initiator, TargetUPN, RoleName,
          IpAddress = tostring(InitiatedBy.user.ipAddress), CorrelationId
| order by TimeGenerated desc
```

**Splunk SPL (M365 Cloud App Security / Azure Audit) :**

```spl
index=azure_audit operationName="Add member to role*"
| spath path=targetResources{}.modifiedProperties{}.newValue output=role
| spath path=initiatedBy.user.userPrincipalName output=initiator
| table _time, operationName, initiator, role, result, ipAddress
| sort -_time
```

### 2.3 Critères d'escalade

- **Toute attribution Global Administrator hors PIM = P0 immédiat.**
- Initiateur = compte récemment créé (< 30 jours) → P0.
- IP source non-corporate → P0.
- Initiateur lui-même cible (auto-attribution) → P0.
- Plusieurs attributions en rafale (5 min) → P0 + suspicion campagne.

---

## 3. Investigation N2/N3

### 3.1 Reconstitution de la chaîne d'authentification de l'initiateur

```kql
SigninLogs
| where UserPrincipalName == "$initiator$" and TimeGenerated > ago(48h)
| project TimeGenerated, AppDisplayName, IPAddress, Location,
          AuthenticationRequirement, ConditionalAccessStatus, ResultType,
          UserAgent, ClientAppUsed, IsRiskyOrInitiated = RiskState
| order by TimeGenerated desc
```

À identifier :

- **Token theft** ? (anomalie géographique impossible)
- **MFA fatigue** ? (rafale de prompts MFA acceptés)
- **Phishing AiTM** (Adversary-in-the-Middle, ex: EvilProxy / Tycoon) — UserAgent + IP atypiques.
- **OAuth illicit consent** ? (`Consent to application` events).

### 3.2 Hunt sur les actions du compte cible (élevé)

```kql
AuditLogs
| where TimeGenerated > ago(72h)
| where InitiatedBy.user.userPrincipalName == "$target_upn$"
   or TargetResources[0].userPrincipalName == "$target_upn$"
| project TimeGenerated, OperationName, Result, TargetResources, InitiatedBy
| order by TimeGenerated desc
```

Actions à scruter prioritairement :

| Action | Risque |
|--------|--------|
| `Add app role assignment grant to user` | Backdoor App Registration |
| `Consent to application` | OAuth abuse |
| `Update application – Certificates and secrets management` | Persistance via certificat |
| `Add service principal credentials` | Idem |
| `Set federation settings on domain` | Backdoor SAML (Solorigate) |
| `Update Conditional Access policy` | Désactivation MFA |
| `Add owner to application` | Élévation indirecte |
| Inbox forwarding rules | Exfiltration mail |

### 3.3 Recherche de persistance dans Exchange Online

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in~ ("New-InboxRule","Set-Mailbox","Set-InboxRule",
                       "Add-MailboxPermission","Set-TransportRule")
| project TimeGenerated, UserId, Operation, Parameters, ClientIP
```

### 3.4 Recherche de Service Principal backdoors

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ServicePrincipalCredentialKeyId != ""
| summarize Logins = count(), make_set(IPAddress, 50)
            by ServicePrincipalName, AppId
| where Logins > 100 or array_length(set_IPAddress) > 5
```

---

## 4. Containment (< 15 min)

| # | Action | Méthode |
|---|--------|---------|
| 1 | **Retirer le rôle** privilégié récemment attribué | `Remove-MgDirectoryRoleMemberByRef` |
| 2 | **Désactiver le compte** cible | `Disable-MgUser` ou Portal AAD |
| 3 | **Révoquer les sessions et tokens** | `Revoke-MgUserSignInSession` (purge tous tokens) |
| 4 | **Bloquer l'IP source** dans une CA policy d'urgence | Conditional Access — block by IP/location |
| 5 | **Désactiver le compte initiateur** s'il est lui-même suspecté | Idem |
| 6 | **Forcer reset MFA** (delete authentication methods) | `Reset-MfaUser` |
| 7 | **Geler les créations d'apps** | Tenant settings — limit App Registrations |

### Snippets utiles (Microsoft Graph PowerShell)

```powershell
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","User.ReadWrite.All"

Get-MgDirectoryRoleMember -DirectoryRoleId <RoleId> |
  Where-Object { $_.Id -eq "<TargetUserId>" } |
  ForEach-Object { Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId <RoleId> -DirectoryObjectId $_.Id }

Revoke-MgUserSignInSession -UserId "$target_upn$"
Update-MgUser -UserId "$target_upn$" -AccountEnabled:$false
```

---

## 5. Eradication & Recovery

1. **Eradication**
   - Audit complet des **App Registrations** créées dans les 30 derniers jours :
     ```kql
     AuditLogs
     | where TimeGenerated > ago(30d)
     | where OperationName == "Add application"
     ```
   - Vérification des **federation settings** sur tous les domaines (`Get-MgDomainFederationConfiguration`).
   - Recherche d'inbox rules malicieuses (forwarding externe).
   - Audit des **service principals** avec credentials récemment ajoutés.
2. **Recovery**
   - Reset complet des credentials (mots de passe + MFA) du compte initiateur ET cible.
   - Rotation des secrets de toutes les apps potentiellement compromises.
   - Si Solorigate-like (federation tampering) : refed du domaine via certificat propre.
3. **Hardening**
   - **Imposer PIM** pour tout rôle privilégié (élimination des assignments permanents).
   - **Restricted Management Administrative Units** sur les comptes Tier 0.
   - **CA policy** : bloquer toute connexion admin hors IP/locations corporate + token binding.
   - **Phishing-resistant MFA** (FIDO2 / Windows Hello / certificat) pour les rôles privilégiés.
   - **Workload Identity Federation** au lieu de secrets long-terme pour les apps.
   - **Microsoft Defender for Identity** + **Defender for Cloud Apps** activés.
   - **Token Protection** (preview) pour limiter le replay de PRT.
   - Limiter le nombre de **Global Administrators** à ≤ 5 (recommandation Microsoft).

---

## 6. Communication

- RSSI + DPO + DSI immédiatement (rôle critique).
- Microsoft Support si compromission tenant suspectée (Premier Support / Unified).
- ANSSI / CERT-FR si APT pressentie.
- CNIL ≤ 72 h si données personnelles potentiellement exposées.

---

## 7. Lessons Learned

- Le compte initiateur était-il **PIM-eligible** mais a contourné le workflow ?
- Avait-il **MFA résistant au phishing** ?
- Les **Conditional Access policies** étaient-elles appliquées sur ce compte ?
- Combien de comptes disposent de Global Administrator permanent ? (cible : 0 hors break-glass)
- Le SIEM ingérait-il **AuditLogs** + **SigninLogs** + **AADServicePrincipalSignInLogs** + **OfficeActivity** ?

---

## 8. Références

- ATT&CK T1098.003 : <https://attack.mitre.org/techniques/T1098/003/>
- Microsoft — Securing privileged access : <https://learn.microsoft.com/security/privileged-access-workgroup/security-rapid-modernization-plan>
- Mandiant — Remediation and Hardening Strategies for Microsoft 365 : <https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452>
- AADInternals : <https://github.com/Gerenios/AADInternals>
- Stratus Red Team — Azure attacks : <https://stratus-red-team.cloud/attack-techniques/list/#azure>
