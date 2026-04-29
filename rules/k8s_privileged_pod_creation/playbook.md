# Incident Response Playbook — Kubernetes Privileged Pod

| Champ | Valeur |
|-------|--------|
| **Règle associée** | `k8s_privileged_pod_creation.yml` |
| **MITRE ATT&CK** | T1611 (Escape to Host), T1610 (Deploy Container) |
| **Tactique** | Privilege Escalation / Defense Evasion |
| **Sévérité** | High |
| **SLA Triage (N1)** | 10 min |
| **SLA Containment (N2/N3)** | 30 min |

---

## 1. Contexte

Un **pod privilégié** dans Kubernetes équivaut à un **root sur le node** :

- `privileged: true` → désactive les protections runtime (cgroups, seccomp).
- `hostPID: true` → vue sur tous les processus du node, possibilité de dumper la mémoire des autres pods.
- `hostNetwork: true` → accès au plan de contrôle, sniffing inter-pod, contournement NetworkPolicy.
- `hostPath: /` ou `/var/run/docker.sock` → accès direct au filesystem ou au runtime → **container escape immédiat**.
- Capabilities `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH` → équivalent root.

**Cas réels** : Hildegard (TeamTNT, mining), Siloscape (premier malware Windows containers), Kinsing, attaques contre clusters EKS/AKS/GKE exposés.

---

## 2. Triage initial (N1 — 0 à 10 min)

### 2.1 Caractérisation

- [ ] **`user.username`** : human (`oidc:alice@corp`), serviceaccount (`system:serviceaccount:ns:sa`), kubelet (`system:node:...`) ?
- [ ] **`sourceIPs`** : IP corporate ? Pod existant ? Externe ?
- [ ] **`userAgent`** : `kubectl/v1.x`, `kube-controller-manager`, `terraform`, ou outil suspect (`go-resty`, `python-requests`, `curl`) ?
- [ ] **Namespace cible** : système, applicatif, ou namespace inhabituel ?
- [ ] **Image conteneur** : registry corporate ou public/inconnu ?

### 2.2 Requêtes de pivot

**Splunk SPL (kubernetes audit logs ingérés) :**

```spl
index=k8s_audit verb=create objectRef.resource=pods earliest=-1h
| spath path=requestObject.spec output=spec
| where match(spec, "(?i)(privileged.*true|hostPID.*true|hostNetwork.*true|/var/run/docker.sock|SYS_ADMIN)")
| table _time, user.username, sourceIPs{}, userAgent,
        objectRef.namespace, objectRef.name, spec
| sort -_time
```

**Sentinel KQL (via Defender for Containers / Microsoft Sentinel K8s connector) :**

```kql
KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| where Verb in ("create","update","patch")
| where ObjectRef has "pods"
| extend Spec = tostring(parse_json(RequestObject).spec)
| where Spec has_any ("\"privileged\":true","\"hostPID\":true","\"hostNetwork\":true",
                      "docker.sock","SYS_ADMIN","SYS_PTRACE")
| project TimeGenerated, UserName, SourceIPs, UserAgent,
          Namespace = tostring(parse_json(ObjectRef).namespace),
          PodName = tostring(parse_json(ObjectRef).name), Spec
```

### 2.3 Critères d'escalade

- ServiceAccount applicatif (non-DevOps) créant un pod privilégié → **P0** (probable RCE en chaîne).
- IP source = pod existant (autre pod a forge un Service Account token) → **P0**.
- HostPath = `/` ou `docker.sock` → **P0** (escape direct).
- Image depuis registry public inconnu (`quay.io/hacktool`, ghcr d'un repo perso) → P0.
- Hors heures ouvrées → P0.

---

## 3. Investigation N2/N3

### 3.1 Reconstitution du pod

```bash
kubectl get pod $POD -n $NS -o yaml > /tmp/pod_dump.yaml
kubectl describe pod $POD -n $NS
kubectl logs $POD -n $NS --all-containers
kubectl get events -n $NS --field-selector involvedObject.name=$POD
```

### 3.2 Identité du créateur

```bash
kubectl auth can-i --list --as=$USERNAME -n $NS
kubectl get rolebindings,clusterrolebindings -A -o json |
  jq '.items[] | select(.subjects[]?.name=="'$USERNAME'") |
      {name:.metadata.name,kind:.kind,role:.roleRef.name}'
```

Si SA d'un autre pod : ce pod a-t-il été compromis lui aussi ? (chaîne de pivot)

### 3.3 Investigation node-side

Si pod privilégié déjà actif :

```bash
NODE=$(kubectl get pod $POD -n $NS -o jsonpath='{.spec.nodeName}')
kubectl debug node/$NODE -it --image=busybox

ss -tnp
ps auxf | grep -v grep
ls -la /var/lib/kubelet/pods/
journalctl -u kubelet --since "1 hour ago" | tail -100
```

Recherche d'artefacts :

- **Cryptominers** (xmrig, kdevtmpfsi).
- **Reverse shells** (cf. règle `linux_reverse_shell`).
- **Service Account tokens volés** sur d'autres pods (mounted at `/var/run/secrets/...`).
- **Modifications kubelet config** (`/var/lib/kubelet/config.yaml`).
- **Manipulation iptables** / **eBPF programs** (`bpftool prog show`).

### 3.4 Hunt latéral

```kql
KubernetesAuditLogs
| where TimeGenerated > ago(24h)
| where UserName == "$creator$"
| summarize Verbs=make_set(Verb), Resources=make_set(ObjectRef),
            Namespaces=make_set(tostring(parse_json(ObjectRef).namespace))
            by UserName, SourceIPs
```

Recherche de :

- Création de **ClusterRoleBinding** vers `cluster-admin`.
- `exec` / `attach` sur pods existants (T1609).
- Lecture de **Secrets** (`get secrets` en masse).
- Création de **CronJobs** (persistance).
- Modification d'**admission controllers** / **MutatingWebhookConfigurations** (backdoor cluster).

---

## 4. Containment

| # | Action |
|---|--------|
| 1 | **Cordoner le node** : `kubectl cordon $NODE` |
| 2 | **Supprimer le pod** : `kubectl delete pod $POD -n $NS --force --grace-period=0` |
| 3 | **Révoquer le SA compromis** : supprimer ses RoleBindings / rotation du token |
| 4 | **Bloquer la création de pods privilégiés** : `PodSecurityAdmission` profile `restricted` |
| 5 | **Isoler le namespace** via `NetworkPolicy` egress-deny + ingress-deny |
| 6 | **Drainer puis ré-imager le node** si breakout suspecté |
| 7 | **Bloquer l'image** au niveau du registry / admission controller |

### Snippet — révocation SA token (tokens projetés volatiles, mais pour les LegacyTokens) :

```bash
kubectl delete secret -n $NS $SA-token-XXXX
kubectl rollout restart deployment -n $NS  # invalide les tokens montés
```

---

## 5. Eradication & Recovery

1. **Eradication**
   - Suppression du pod malveillant et de son ReplicaSet/Deployment parent.
   - Audit complet des **CronJobs**, **DaemonSets**, **MutatingWebhooks** créés sur la fenêtre.
   - Recherche de **container images backdoorées** dans le registry.
2. **Recovery**
   - Re-imagerie du node si escape probable (containerd / runc CVE, mount dangereux).
   - Rotation des **secrets cluster-wide** (Kubernetes Secrets, registry credentials, GitOps tokens).
   - Restauration des CRDs / RBAC depuis GitOps source of truth.
3. **Hardening**
   - **Pod Security Admission** en `restricted` sur tous les namespaces non-système.
   - **OPA Gatekeeper** / **Kyverno** : policies refusant `privileged`, `hostPID`, `hostPath`.
   - **Falco** runtime detection (rules `Launch Privileged Container`, `Container Drift Detected`).
   - **Image signing** (cosign) + admission policy refusant images non signées.
   - **NetworkPolicy default-deny** par namespace.
   - **AuditPolicy** détaillée + ingestion temps réel SIEM.
   - **etcd encryption at rest**, certificats courts (≤ 1 an).
   - **API server** : `--anonymous-auth=false`, **OIDC** + **MFA** pour les humains.
   - Désactivation des **legacy service account tokens** (Kubernetes ≥ 1.24).

---

## 6. Communication

- DSI/RSSI immédiat — un breakout cluster peut compromettre tous les workloads.
- Si cluster multi-tenant : notification des autres tenants / clients.
- Si cluster cloud managé (EKS/AKS/GKE) : ouvrir un ticket cloud provider.

---

## 7. Lessons Learned

- Pourquoi `PodSecurityAdmission` autorisait-il ce pod ?
- Le ServiceAccount avait-il vraiment besoin de `pods/create` ?
- Falco / Defender for Containers avait-il alerté indépendamment ?
- Mesure du **dwell time** (création pod → détection).
- L'image du conteneur a-t-elle un scan de vulnérabilités passé (Trivy / Snyk / Defender) ?

---

## 8. Références

- ATT&CK Containers Matrix : <https://attack.mitre.org/matrices/enterprise/containers/>
- Microsoft — Threat matrix for Kubernetes : <https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/>
- Falco Default Rules : <https://github.com/falcosecurity/rules>
- Kyverno Policies : <https://kyverno.io/policies/>
- Atomic Test T1611 : <https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1611>
- Kubernetes Security Cheatsheet : <https://kubernetes.io/docs/concepts/security/security-checklist/>
