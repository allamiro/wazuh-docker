# Running the stack on rootless Podman

The stack runs under **rootless Podman** (4.6+) with a few host preparations.
The scripts invoke `docker` and `docker compose`; on Podman hosts install the
shim so the same commands work unchanged:

```bash
sudo dnf install podman podman-docker docker-compose   # RHEL/Alma/Rocky/Fedora
systemctl --user enable --now podman.socket            # compose talks to this
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
loginctl enable-linger "$USER"                         # containers survive logout
```

(`podman compose` with the docker-compose provider is equivalent; either way
the compose files are used as-is.)

## Host prerequisites (rootless specifics)

```bash
# OpenSearch requirement (host-wide, same as Docker)
sudo sysctl -w vm.max_map_count=262144

# rootless processes cannot bind ports < 1024 - the dashboard publishes 443
echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/99-wazuh-rootless.conf
sudo sysctl --system

# memlock: rootless users often cannot raise RLIMIT_MEMLOCK. Either allow it:
sudo tee /etc/security/limits.d/wazuh.conf <<'EOF'
*  soft  memlock  unlimited
*  hard  memlock  unlimited
EOF
# ...or disable memory locking for the indexers in multi-node/.env:
#   MEMORY_LOCK=false
```

## SELinux (RHEL-family hosts)

Bind-mounted configs/certs are blocked by SELinux labels under rootless
Podman. Two options:

1. **Simple** — disable label separation for these containers with the
   shipped override:
   ```bash
   docker compose -f docker-compose.yml -f podman-compose.override.yml up -d
   ```
2. **Stricter** — relabel the bind mounts instead (private `:Z` for per-node
   files, shared `:z` for files mounted into several containers, e.g.
   `root-ca.pem`, `internal_users.yml`, `indexer-init.sh`). One-time rewrite
   of the compose file:
   ```bash
   sed -i -E 's|(- \./config/[^:]+:[^:]+)$|\1:z|; s|(- \./scripts/[^:]+:[^:]+:ro)$|\1,z|' docker-compose.yml
   ```
   then review the diff before starting.

## Notes and known differences

- `user: "0"` on the indexers is **rootless-safe**: "root" inside the
  container maps to *your* unprivileged user on the host; the init wrapper
  does its setup and the entrypoint still drops to `wazuh-indexer`.
- Static manager IPs (`10.77.0.11-15`) work with Podman 4.x netavark
  networks, including rootless.
- `cpu_shares` needs cgroups v2 with user delegation
  (`systemd.unified_cgroup_hierarchy`, default on EL9/Fedora); otherwise
  Podman logs a warning and ignores it — harmless.
- `deploy.resources.limits.memory` is honored by rootless Podman on
  cgroups v2.
- For boot-time autostart, generate systemd user units (or Quadlet files)
  once the stack is up: `podman generate systemd --new --files --name <ctr>`
  into `~/.config/systemd/user/`.

Everything else — the PKI lifecycle, `wazuh-deploy.sh`, the archive and ML
modules, verification — behaves identically to Docker.
