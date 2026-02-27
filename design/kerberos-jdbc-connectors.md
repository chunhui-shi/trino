# Kerberos Authentication for JDBC Connectors

## Overview

The Oracle and PostgreSQL connectors support Kerberos (GSS/SPNEGO) authentication
via a shared infrastructure in `trino-base-jdbc` and `trino-plugin-toolkit`.
This document covers the design, the Kerby vs. standard-JAAS trade-off, and
the Kubernetes patterns for provisioning credentials.

---

## Architecture

### Shared components (`trino-base-jdbc` / `trino-plugin-toolkit`)

```
KerberosConfig               — connector properties: principal, keytab source
KerberosAuthenticationModule — Guice module; selects auth provider from config
KerberosAuthenticationProvider (interface)
  ├── KerbyKerberosAuthentication   — base64/in-memory path (uses Apache Kerby)
  └── KerberosAuthentication        — file path (uses JDK Krb5LoginModule)
CachingKerberosAuthentication — caches Subject; re-authenticates before expiry
KerberosConnectionFactory     — wraps a ConnectionFactory; runs openConnection()
                                inside Subject.callAs() for JGSS-aware drivers
```

### Connector-specific wiring

| Connector  | Connection factory | Why custom? |
|---|---|---|
| PostgreSQL | `KerberosConnectionFactory` (generic) | pgjdbc picks up active Subject via JGSS automatically |
| Oracle     | `OracleKerberosConnectionFactory` (custom) | Oracle JDBC requires an explicit `GSSCredential` extracted from the Subject |

Both connectors install `KerberosAuthenticationModule` (from `trino-base-jdbc`)
which provides the `CachingKerberosAuthentication` singleton. The module selection
is driven by `JdbcAuthenticationType` (in `trino-base-jdbc`):

```properties
# Oracle
oracle.authentication.type=KERBEROS

# PostgreSQL
postgresql.authentication.type=KERBEROS
```

---

## Two Authentication Paths

`KerberosAuthenticationModule` selects the provider based on which config
property is set:

```
kerberos.client.keytab-base64   →  KerbyKerberosAuthentication   (Kerby path)
kerberos.client.keytab          →  KerberosAuthentication         (JAAS path)
kerberos.client.credential-cache.location  →  KerberosAuthentication (JAAS path)
```

### Path A — Standard JAAS (`KerberosAuthentication`)

Uses the JDK's built-in `com.sun.security.auth.module.Krb5LoginModule` via a
programmatic `Configuration` (no JAAS config file required). The flow:

1. `LoginContext` runs `Krb5LoginModule` with `useKeyTab=true`, `storeKey=true`
2. JDK performs AS-REQ/AS-REP with the KDC
3. Returns a populated `Subject`; `CachingKerberosAuthentication` caches it
4. `KerberosConnectionFactory` calls `Subject.callAs(subject, () -> driver.connect(...))`

**Requirements:**
- Keytab must be a **file path** accessible to the Trino process
- `java.security.krb5.conf` JVM property must point to a krb5.conf file
  (or `/etc/krb5.conf` exists) — this setting is **JVM-global**

### Path B — Kerby (`KerbyKerberosAuthentication`)

Uses [Apache Kerby](https://directory.apache.org/kerby/) as a pure-Java Kerberos
client. The keytab bytes are decoded from base64 in memory; the KDC exchange
happens entirely within the JVM. The resulting `TgtTicket` is converted to a
standard JDK `KerberosTicket` and placed in a `Subject`.

**Requirements:**
- `kerberos.client.keytab-base64` — base64-encoded keytab content
- `kerberos.client.krb5-config-base64` (optional) — base64-encoded krb5.conf;
  when absent, Kerby falls back to `java.security.krb5.conf` JVM property

---

## Trade-off: Kerby vs. Standard JAAS

| Dimension | Kerby (`keytab-base64`) | Standard JAAS (`keytab` file) |
|---|---|---|
| **Keytab on disk** | No — bytes stay in JVM heap | Yes — file path required |
| **krb5.conf on disk** | Optional — can be base64 too | Yes — JVM-global file |
| **Secrets-manager friendly** | Yes — use `${ENV:VAR}` in properties | Requires file mount |
| **Per-connector KDC config** | Yes — each connector has its own `KrbClient` | No — JVM-global `java.security.krb5.conf` |
| **Encryption types** | etype 17/18 only (AES-SHA1, RFC 3961) | All etypes (17–20, including RFC 8009 SHA256/SHA384) |
| **Modern KDC defaults** | Requires keytab restricted to etype 18 | Works out of the box |
| **Maintenance** | Requires Kerby fork in classpath | Zero — JDK built-in |
| **Multi-realm Trino** | Fully isolated per connector | Shared krb5.conf must cover all realms |

### The etype limitation

Kerby 2.1.x implements only etypes 17 and 18 (AES128/256-CTS-HMAC-SHA1-96,
RFC 3961). Modern KDCs (FreeIPA 4.x, Active Directory 2008+) default to
etypes 19 and 20 (AES128/256-CTS-HMAC-SHA256/384, RFC 8009).

**Workaround:** When generating keytabs for Kerby-backed connectors, restrict
to etype 18:

```bash
# FreeIPA
ipa-getkeytab -s freeipa.example.com -p trino@EXAMPLE.COM \
  -k /tmp/trino.keytab -e aes256-cts-hmac-sha1-96

# MIT krb5 / kadmin
ktadd -e aes256-cts-hmac-sha1-96:normal -k /tmp/trino.keytab trino@EXAMPLE.COM
```

Without this restriction, Kerby will fail with `KeytabEntry.getKey() is null`
when the KDC selects an unsupported etype during pre-authentication.

---

## Kubernetes Provisioning Patterns

The following patterns are ordered from least to most secure.

### Pattern 1 — ConfigMap (not recommended for keytabs)

```yaml
# Do NOT store keytabs in ConfigMaps
# ConfigMaps are plaintext in etcd and on the node filesystem.
# base64 is encoding, not encryption.
```

Keytabs in a ConfigMap are accessible to anyone with `kubectl get configmap`
in the namespace and are stored unencrypted in etcd. Only use for non-sensitive
config (e.g. a multi-realm `krb5.conf` that contains no keys).

---

### Pattern 2 — Secret volume mount → standard JAAS path

The keytab is mounted as a file. Kubernetes kubelet can back Secret volumes
with `tmpfs`, so the keytab never touches the node's persistent disk.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: trino-keytabs
type: Opaque
data:
  trino.keytab: <base64-encoded keytab>      # base64 -w0 trino.keytab
  postgres.keytab: <base64-encoded keytab>
```

```yaml
# Trino Deployment / StatefulSet
volumes:
  - name: keytabs
    secret:
      secretName: trino-keytabs
      defaultMode: 0400   # owner-read only
  - name: krb5-conf
    configMap:
      name: trino-krb5-conf   # krb5.conf has no secrets — ConfigMap is fine

containers:
  - name: trino
    volumeMounts:
      - name: keytabs
        mountPath: /etc/trino/keytabs
        readOnly: true
      - name: krb5-conf
        mountPath: /etc/trino/krb5.conf
        subPath: krb5.conf
        readOnly: true
```

```properties
# /etc/trino/catalog/postgres.properties
connector.name=postgresql
connection-url=jdbc:postgresql://postgres.example.com:5432/db
postgresql.authentication.type=KERBEROS
kerberos.client.principal=trino@EXAMPLE.COM
kerberos.client.keytab=/etc/trino/keytabs/trino.keytab
```

```properties
# jvm.config
-Djava.security.krb5.conf=/etc/trino/krb5.conf
```

**Security properties:**
- Keytab in etcd: encrypted at rest if cluster has etcd encryption enabled for Secrets
- Keytab on node disk: only in tmpfs (RAM) — never written to persistent storage
- Keytab visible inside container: yes, as a file at the mount path
- Full etype support — standard JDK Kerberos handles 17–20

---

### Pattern 3 — Secret → env var → `keytab-base64` → Kerby path

The keytab bytes are stored in a Secret and injected as an environment variable.
The catalog properties file uses `${ENV:VAR}` substitution, keeping the
plaintext out of the properties file itself.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: trino-keytabs
type: Opaque
stringData:
  TRINO_KEYTAB_B64: <base64-encoded keytab, single line, no newlines>
```

```yaml
containers:
  - name: trino
    env:
      - name: TRINO_KEYTAB_B64
        valueFrom:
          secretKeyRef:
            name: trino-keytabs
            key: TRINO_KEYTAB_B64
```

```properties
# /etc/trino/catalog/postgres.properties
connector.name=postgresql
connection-url=jdbc:postgresql://postgres.example.com:5432/db
postgresql.authentication.type=KERBEROS
kerberos.client.principal=trino@EXAMPLE.COM
kerberos.client.keytab-base64=${ENV:TRINO_KEYTAB_B64}
```

The catalog properties file contains only the `${ENV:VAR}` placeholder and
can safely live in a ConfigMap or a container image.

**Security properties:**
- Keytab in etcd: encrypted at rest if etcd encryption is enabled for Secrets
- Keytab on node disk: no — env vars are not written to disk by kubelet
- Keytab visible inside container: via `/proc/self/environ` (world-readable by
  processes running as the same UID); weaker than a 0400 file
- Etype restriction required: keytab must be etype 18 only (Kerby limitation)

---

### Pattern 4 — External secrets manager CSI driver (most secure)

Integrates with Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault
via the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/).
The keytab is never stored in etcd at all.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: trino-keytabs
spec:
  provider: vault    # or aws, gcp, azure
  parameters:
    roleName: trino
    objects: |
      - objectName: trino-keytab-b64
        secretPath: secret/data/trino/keytabs
        secretKey: trino_keytab_b64
  secretObjects:
    - secretName: trino-keytab-secret
      type: Opaque
      data:
        - objectName: trino-keytab-b64
          key: TRINO_KEYTAB_B64
```

```yaml
volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: trino-keytabs

containers:
  - name: trino
    env:
      - name: TRINO_KEYTAB_B64
        valueFrom:
          secretKeyRef:
            name: trino-keytab-secret
            key: TRINO_KEYTAB_B64
    volumeMounts:
      - name: secrets-store
        mountPath: /mnt/secrets-store
        readOnly: true
```

**Security properties:**
- Keytab source: external secret store (Vault/AWS/GCP/Azure) — not in etcd
- Keytab on node disk: no — injected directly as env var
- Rotation: secrets-store CSI driver can poll for updates and re-inject

---

## Pattern Comparison

| | ConfigMap | Secret volume mount | Secret → env var | CSI driver |
|---|---|---|---|---|
| Keytab in etcd | Plaintext | Encrypted (if configured) | Encrypted (if configured) | Not in etcd |
| On node disk | Yes (overlayfs) | No (tmpfs) | No | No |
| Auth path | — | Standard JAAS | Kerby | Kerby |
| Etype restriction needed | — | No | Yes (etype 18 only) | Yes (etype 18 only) |
| Rotation support | Manual | Manual Secret update | Manual Secret update | Automatic |
| Ops complexity | Low | Low | Low | High |
| Recommended | No | Yes | Yes | For regulated envs |

---

## Multi-Realm Configuration

When both Oracle (e.g. `TEST1.EXAMPLE.COM`) and PostgreSQL (`EXAMPLE.COM`)
connectors are active in the same Trino process:

**Standard JAAS path:** A single `krb5.conf` must cover all realms. Since
`java.security.krb5.conf` is JVM-global, all connectors share it.

```ini
# /etc/trino/krb5.conf
[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false

[realms]
  EXAMPLE.COM = {
    kdc = freeipa.example.com
  }
  TEST1.EXAMPLE.COM = {
    kdc = kdc.test1.example.com
  }

[domain_realm]
  .example.com = EXAMPLE.COM
  example.com = EXAMPLE.COM
  .test1.example.com = TEST1.EXAMPLE.COM
  test1.example.com = TEST1.EXAMPLE.COM
```

**Kerby path:** Each connector builds its own `KrbClient` instance from either
`kerberos.client.krb5-config-base64` (per-connector) or falls back to the JVM
`java.security.krb5.conf`. Per-connector base64 config allows full isolation.

---

## Configuration Reference

### Shared properties (all KERBEROS connectors)

| Property | Required | Description |
|---|---|---|
| `kerberos.client.principal` | Yes | Kerberos principal, e.g. `trino@REALM` |
| `kerberos.client.keytab` | One of three | Path to keytab file on disk |
| `kerberos.client.keytab-base64` | One of three | Base64-encoded keytab (Kerby path) |
| `kerberos.client.credential-cache.location` | One of three | Path to ccache file |
| `kerberos.client.krb5-config-base64` | No | Base64-encoded krb5.conf (Kerby path only) |

Exactly one of the three keytab-source properties must be set.

### Connector authentication type

```properties
oracle.authentication.type=KERBEROS        # oracle connector
postgresql.authentication.type=KERBEROS    # postgresql connector
```

### JVM property (required for all paths)

```
-Djava.security.krb5.conf=/etc/trino/krb5.conf
```

Required for both JAAS and Kerby paths (Kerby falls back to this when
`kerberos.client.krb5-config-base64` is absent).

---

## Relevant Source Files

| File | Role |
|---|---|
| `plugin/trino-base-jdbc/.../kerberos/KerberosConfig.java` | Config properties |
| `plugin/trino-base-jdbc/.../kerberos/KerberosAuthenticationModule.java` | Provider selection |
| `plugin/trino-base-jdbc/.../kerberos/KerberosConnectionFactory.java` | JGSS-aware connector wrapper |
| `plugin/trino-base-jdbc/.../jdbc/JdbcAuthenticationType.java` | Shared PASSWORD/KERBEROS enum |
| `lib/trino-plugin-toolkit/.../authentication/KerbyKerberosAuthentication.java` | Kerby AS exchange |
| `lib/trino-plugin-toolkit/.../authentication/KerberosAuthentication.java` | JAAS LoginContext |
| `lib/trino-plugin-toolkit/.../authentication/CachingKerberosAuthentication.java` | TGT cache + renewal |
| `plugin/trino-oracle/.../OracleKerberosConnectionFactory.java` | Oracle-specific GSSCredential wiring |
| `plugin/trino-postgresql/.../PostgreSqlConnectionFactoryModule.java` | PostgreSQL auth module |
| `plugin/trino-oracle/.../OracleClientModule.java` | Oracle auth module |
