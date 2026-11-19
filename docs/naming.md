# Naming

## The proxy VM was also called the mirror VM

One machine had two names. The code and paths said proxy —
`deploy/proxy-vm/`, `scripts/proxy-vm-up.sh`, `XENTRY_PROXY_IP`,
`PROXY_VM_IP` — while the unit, the docs and much of the broker said mirror:
`xentry-mirror.service`, "the mirror VM", `mirror_url`, `mirror_port`. Nothing
switched on the difference, so the two names were pure cost: a reader could not
tell whether a function that took `mirror_port` and a script that took
`proxy_url` were talking about the same thing. They were — `runtime.py` built
`mirror_url` as `f"http://{proxy_ip}:{mirror_port}"` and handed it to
`setup-generic.sh`, which received it as `proxy_url`.

Everything about that machine and the packages it serves is now **proxy**:

| was | is |
|---|---|
| `xentry-mirror.service` | `xentry-proxy.service` |
| "the mirror VM" | the proxy VM |
| `mirror_url`, `mirror_port`, `mirror_ports` | `proxy_url`, `proxy_port`, `proxy_ports` |
| `mirror_vm_unconfigured` | `proxy_vm_unconfigured` |

## Two things kept the word mirror, deliberately

**The artifact mirror** (`broker/mirror.py`, `ArtifactMirror`, `MirrorError`,
`/var/lib/xentry/mirror`, `XENTRY_START_MIRROR`) is a static, allowlisted local
copy of pinned artifacts served to a provisioning guest. It runs on the host,
it is not the proxy VM, and it is not a proxy — it mirrors files that were
fetched and hashed in advance. Renaming it would have merged two different
things under one word, which is the problem this change exists to remove.

**`MIRROR_IP` became `GATEWAY_IP`, not `proxy_ip`.** It was `10.42.0.1`, a job
network's gateway address, while `PROXY_VM_IP` is `10.44.0.2`. Those are
different addresses and `proxy_ip` was already taken by the second. Calling
both `proxy_ip` would have been a rename that introduced a bug.
