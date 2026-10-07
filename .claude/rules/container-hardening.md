---
paths:
  - "**/Dockerfile"
  - "k8s/**"
  - "demo/**/k8s/**"
---

# Container and pod hardening baseline

Apply these rules when you add or edit a Dockerfile or a k8s manifest.

## Non-root user

All AIAC service images run as **non-root UID 10001**. Each service Dockerfile
adds the user before `CMD`, the same as the `authbridge/sparc-service` pattern:

```dockerfile
# Drop privileges.
RUN useradd --no-create-home --uid 10001 aiac
USER 10001
```

## Volume ownership

A volume that is mounted over a directory hides the Dockerfile `chown` of that
directory. The kubelet keeps emptyDir and PVC volumes owned by root by default.
Thus a service that writes to a mounted volume (PVC or emptyDir) also needs a
pod-level `securityContext`, so that the kubelet gives the volume to the
non-root user:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001   # makes the mounted volume group-writable by UID 10001
```

To find these services:

```bash
grep -rlniE 'volumeMounts|volumeClaimTemplates|emptyDir|persistentVolumeClaim' k8s/
```

A service with no volumes still needs the Dockerfile `USER` directive, but not
the `fsGroup` block.

## Pod-security baseline

Each workload in `k8s/` and in the demo manifests has a hardened
`securityContext`.

Pod level:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001        # 1001 for the demo github-agent
    seccompProfile:
      type: RuntimeDefault
```

Exception: the demo `github-agent` has no pod-level block. Its injected
AuthBridge sidecar runs as UID 1337, and a pod-level `runAsUser` would change
it. Set the hardening per container there.

Container level, on each app container:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

- With `readOnlyRootFilesystem: true`, give the container a writable `/tmp`
  emptyDir (and its real data mount, for example `/data` or `/rego`).
- Exception: the demo `github-agent` has no `readOnlyRootFilesystem`, because
  its runtime (`uv` / `litellm` / `crewai`) writes caches under `HOME=/app`.

## Probes and resources

- Each core workload has a readiness probe **and** a liveness probe: `httpGet
  /health` if the service has that endpoint, else `tcpSocket` (the demo
  workloads).
- Each workload has CPU and memory requests and limits.
- The Controller also has a `startupProbe`. It serves `/health` only after its
  start sequence (combiner check, resync) is complete.
