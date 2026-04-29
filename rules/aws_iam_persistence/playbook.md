# Incident Response Playbook — AWS IAM Persistence

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `aws_iam_persistence.yml` |
| **MITRE ATT&CK** | T1098.001 / T1136.003 |
| **Tactique** | Persistence / Privilege Escalation |
| **Sévérité** | High |
| **SLA Triage (N1)** | 10 min |
| **SLA Containment (N2/N3)** | 30 min |

---

## 1. Contexte

Une fois des credentials AWS compromis (clé exposée GitHub, exfiltration EC2 IMDS, phishing console), l'attaquant établit rapidement de la **persistance IAM** :

- Création d'une nouvelle **access key** sur un utilisateur existant.
- Création d'un **login profile** (mot de passe console) sur un user de service.
- Attachement de **AdministratorAccess** à un compte secondaire.
- Création d'un **utilisateur backdoor** ou rôle assumable cross-account.
- Ajout d'une **trust policy** qui autorise un compte attaquant à assume le rôle.

Ces actions sont visibles dans **CloudTrail** mais souvent noyées dans le bruit IaC.

**Cas réels** : DangerDev (2024), Codecov (2021), nombreuses fuites de tokens GitHub.

---

## 2. Triage initial (N1 — 0 à 10 min)

### 2.1 Caractérisation

- [ ] **userIdentity.arn** : qui a effectué l'action ? Compte humain ? Rôle assumé ? Root ?
- [ ] **sourceIPAddress** : IP corporate, VPN, EC2 interne, ou IP externe inconnue ?
- [ ] **userAgent** : `aws-cli/2.x`, `Boto3`, `console.amazonaws.com`, ou outil suspect (`Mozilla/5.0`, scanner) ?
- [ ] **awsRegion** : région utilisée habituellement par le compte ?
- [ ] **eventTime** : heure ouvrée ?
- [ ] Action sur compte privilégié, root, ou service critique ?

### 2.2 Requêtes de pivot

**Splunk SPL :**

```spl
index=cloudtrail eventSource=iam.amazonaws.com earliest=-1h
| where match(eventName, "(?i)(CreateAccessKey|CreateLoginProfile|AttachUserPolicy|AddUserToGroup|CreateUser|CreateRole)")
| table _time, eventName, userIdentity.arn, sourceIPAddress, userAgent,
        requestParameters.userName, requestParameters.policyArn
| sort -_time
```

**Sentinel KQL (CloudTrail via Sentinel data connector) :**

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where EventSource == "iam.amazonaws.com"
| where EventName in ("CreateAccessKey","CreateLoginProfile","UpdateLoginProfile",
                      "AttachUserPolicy","AttachRolePolicy","PutUserPolicy",
                      "AddUserToGroup","CreateUser","CreateRole")
| project TimeGenerated, EventName, UserIdentityArn, UserIdentityUserName,
          SourceIpAddress, UserAgent, RequestParameters, ResponseElements, AwsRegion
| order by TimeGenerated desc
```

### 2.3 Critères d'escalade

- IP externe inconnue (non corporate, non IaC) → **P0**.
- Action **CreateAccessKey** sur un utilisateur **autre que** le caller → **P0** (signature classique d'escalade).
- Attachement de `AdministratorAccess` ou `IAMFullAccess` → **P0**.
- Création d'un **rôle cross-account** avec trust policy externe → **P0**.
- Identité = **root** account → **P0 critique**.

---

## 3. Investigation N2/N3

### 3.1 Reconstitution complète

```kql
AWSCloudTrail
| where UserIdentityArn == "$arn$" or
        UserIdentityAccessKeyId == "$access_key$"
| where TimeGenerated > ago(24h)
| project TimeGenerated, EventName, EventSource, AwsRegion,
          SourceIpAddress, UserAgent, ErrorCode, RequestParameters
| order by TimeGenerated asc
```

À reconstituer :

- **Source d'authentification initiale** : login console MFA ? assume role ? key statique ?
- **Liste exhaustive des actions** depuis le compte compromis (24-72 h).
- **Ressources créées** : EC2 instances, S3 buckets, Lambda functions, RDS snapshots.
- **Données accédées** : `GetObject` sur S3 (exfiltration ?), `DescribeSecret` SecretsManager.

### 3.2 Hunt sur les comportements typiques d'attaquants

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h) and UserIdentityArn == "$arn$"
| where EventName in ("CreateInstance","RunInstances","CreateBucket","PutBucketPublicAccessBlock",
                      "CreateFunction","CreateSnapshot","CopySnapshot","ShareSnapshot",
                      "GetSecretValue","ListSecrets","AssumeRole","GetCallerIdentity",
                      "ListUsers","ListRoles","ListAccessKeys")
| summarize EventCount=count(), Events=make_set(EventName) by SourceIpAddress, UserAgent
```

### 3.3 Recherche d'IOC AWS-spécifiques

- **EC2 instances** créées dans des régions inhabituelles (mining, DDoS).
- **S3 buckets** rendus publics (`PutBucketAcl` avec `public-read`).
- **Lambda backdoor** déployée.
- **Exfiltration via S3** (`GetObject` massif depuis IP externe ou nouveau rôle).
- **Disablement** de CloudTrail / GuardDuty / Config (`StopLogging`, `DeleteTrail`).

### 3.4 Vérification GuardDuty / Detective

GuardDuty génère des findings spécifiques utiles :

- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- `Persistence:IAMUser/AnomalousBehavior`
- `PrivilegeEscalation:IAMUser/AnomalousBehavior`

---

## 4. Containment (< 30 min)

| # | Action | Méthode |
|---|--------|---------|
| 1 | **Désactiver les access keys** créées par l'attaquant | `aws iam update-access-key --status Inactive` |
| 2 | **Détacher les policies** suspicieusement attachées | `aws iam detach-user-policy` |
| 3 | **Supprimer les login profiles** créés | `aws iam delete-login-profile` |
| 4 | **Désactiver l'utilisateur** initial compromis | `aws iam update-login-profile --password-reset-required` + désactiver les keys |
| 5 | **Révoquer les sessions IAM actives** | `aws iam put-user-policy` avec deny `AWSRevokeOlderSessions` |
| 6 | **Bloquer l'IP attaquante** | WAF / Security Groups |
| 7 | Si root compromis : **réinitialiser MFA root** | Console root + nouveau token MFA hardware |

### Snippet de révocation rapide des sessions

```bash
USER="$compte_compromis$"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-user-policy --user-name "$USER" \
  --policy-name AWSRevokeOlderSessions \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*",
      "Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$TIMESTAMP'"}}
    }]
  }'
```

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression de toutes les ressources créées par l'attaquant (EC2, Lambda, S3, IAM users/roles).
   - Audit complet des trust policies (cross-account roles autorisés).
   - Audit des access keys de TOUS les utilisateurs (`aws iam list-access-keys` × users).
2. **Recovery**
   - Rotation **complète** des credentials de l'utilisateur compromis et des comptes adjacents (équipe).
   - Rotation des secrets potentiellement accédés (SecretsManager, Parameter Store).
   - Restauration depuis backup si données S3/RDS modifiées ou supprimées.
3. **Hardening post-incident**
   - **MFA obligatoire** pour tous les utilisateurs IAM (et root).
   - **SCP** (Service Control Policies) au niveau Organization bloquant `iam:CreateAccessKey` hors comptes IaC.
   - **AWS Config rules** : `iam-user-mfa-enabled`, `iam-no-inline-policy-check`, `access-keys-rotated`.
   - **GuardDuty** activé multi-region + multi-account.
   - **CloudTrail** organization trail, S3 + KMS, log file integrity validation.
   - Adoption d'**IAM Identity Center (SSO)** : suppression des users IAM long-terme au profit de rôles temporaires.
   - **Permission Boundaries** sur tous les rôles susceptibles d'être compromis.
   - Scan régulier des dépôts publics (`trufflehog`, `gitleaks`) pour clés exposées.

---

## 6. Communication

- Si données client exfiltrées → notification CNIL ≤ 72 h.
- Si tokens partenaires/fournisseurs touchés → notification du SOC pair.
- AWS Trust & Safety si compte tiers utilisé pour attaque.

---

## 7. Lessons Learned

- Comment les credentials initiaux ont-ils fui ? (commit GitHub, IMDS v1, phishing, supply chain ?)
- L'**IMDSv2** était-il imposé sur les EC2 ?
- GuardDuty / CloudTrail étaient-ils ingérés dans le SIEM avant l'incident ?
- Le **dwell time** depuis la 1ère action malveillante ?
- Faut-il migrer vers **IAM Identity Center + AssumeRoleWithWebIdentity** pour les pipelines (OIDC GitHub Actions) ?

---

## 8. Références

- ATT&CK T1098.001 : <https://attack.mitre.org/techniques/T1098/001/>
- AWS Security Incident Response Guide : <https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/>
- Stratus Red Team — AWS attacks : <https://github.com/DataDog/stratus-red-team>
- CloudTrail Best Practices : <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html>
- Hacking the Cloud : <https://hackingthe.cloud/>
