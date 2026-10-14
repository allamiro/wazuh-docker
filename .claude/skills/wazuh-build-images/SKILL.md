---
name: wazuh-build-images
description: Build the Wazuh Docker images (manager, indexer, dashboard, agent) with build-docker-images/build-images.sh and docker-bake.hcl. Use when asked to build, rebuild, tag, push, or modify an image, a Dockerfile, or the build scripts, including dev builds and unsigned packages.
---

# Build Wazuh images

Images are built by `build-docker-images/build-images.sh`, which downloads an artifact URL list, derives per-component tags, and runs `docker buildx bake -f docker-bake.hcl`. Run it **from `build-docker-images/`**.

```bash
cd build-docker-images
./build-images.sh -v 5.1.0                  # all four, in parallel, local single-arch (--load)
./build-images.sh -c wazuh-manager          # one component: wazuh-indexer|wazuh-manager|wazuh-dashboard|wazuh-agent
./build-images.sh -a my_artifacts.yaml      # use your own package URL list instead of downloading
./build-images.sh -m -rg <registry>         # multi-arch (amd64+arm64): pushes, cannot --load
./build-images.sh -h
```

## Side effects to know before running

- It **overwrites the tracked `../.env`** (`WAZUH_VERSION`, `WAZUH_IMAGE_VERSION`, `WAZUH_REGISTRY`, `IMAGE_TAG`). Run `git diff ../.env` afterwards and revert if you did not intend to change it.
- It writes `artifact_urls.yaml` and `artifacts_env.txt` (gitignored) every run, overwriting the previous ones.
- It builds with `--no-cache`.
- The default `WAZUH_IMAGE_VERSION` and `IMAGE_TAG` are hardcoded at the top of the script and in `docker-bake.hcl`. They are bumped by `tools/repository_bumper.sh` (see the wazuh-version-bump skill).

## Where packages come from

Without `-a`, the script checks GitHub for release tag `v<version>` of `wazuh/wazuh-docker`:

- 200: production, `packages.wazuh.com/production/<major>.x/artifact-urls/artifact_urls_<ver>.yaml`.
- 403 (rate limit) or 404: pre-release, `packages-staging.xdrsiem.wazuh.info/pre-release/...`, with `-<stage>` from `VERSION.json` appended to the filename.

Keys of the YAML are turned into shell vars (`-` and `.` become `_`), for example `wazuh_manager_x86_64_rpm`. They are consumed as bake args.

## Tags

| Flags | Tag |
| - | - |
| none | `<ver>` |
| `-d beta1` | `<ver>-beta1` |
| `--dev` | `<ver>[-stage]-<commit>`, with commit `latest` by default |
| `--dev -refs '["i","m","d","a"]'` | per-component commit (order: indexer, manager, dashboard, agent) |
| `--dev -c wazuh-agent -refs '["abc123"]'` | with `-c`, exactly **one** ref |

`--dev` is required for `-refs` and `--skip-signature-check`. Without `-c`, `-refs` must have exactly 4 items.

## Package signature check

Every Dockerfile installs its RPM only after `build-docker-images/shared/verify-package-signature.sh` verifies it against the pinned Wazuh GPG fingerprints. Unsigned or foreign-signed packages **fail the build**. Package URLs must be `https://`.

Commit-built dev packages are unsigned:

```bash
./build-images.sh --dev --skip-signature-check -c wazuh-agent
```

`--skip-signature-check` without `--dev` is rejected. Never use it for release builds.

`tini` in the manager and agent Dockerfiles is pinned by SHA-256 (`TINI_SHA256_AMD64`, `TINI_SHA256_ARM64`). Updating `TINI_VERSION` means updating both hashes.

## Image layout (when editing)

```
build-docker-images/
  docker-bake.hcl            targets: _common (platforms, shared context), one per component
  shared/                    verify-package-signature.sh, used via COPY --from=shared
  wazuh-manager/ Dockerfile + config/{entrypoint.sh, etc/cont-init.d/0-wazuh-init,1-credentials,2-manager,
                             permanent_data.{env,sh}, password-tool.sh, install-credentials.sh, wazuh-api-users.py}
  wazuh-indexer/ Dockerfile + config/{entrypoint.sh, config.sh, securityadmin.sh, password-tool.sh, install-credentials.sh}
  wazuh-dashboard/ Dockerfile + config/{entrypoint.sh, wazuh_dashboard_config.sh, install-credentials.sh}
  wazuh-agent/   Dockerfile + config/{entrypoint.sh, etc/cont-init.d/0-wazuh-init,1-agent, permanent_data.*}
```

- The manager `entrypoint.sh` supervises the daemons and exits non-zero if one dies, so `restart: always` can recover. Keep that behavior when editing.
- `permanent_data.*` copies a baked snapshot into empty volumes on first start. When you add a persisted path, update `permanent_data.env` and the matching compose volume.
- The manager runs in `/var/wazuh-manager`, the agent in `/var/ossec`.
- Env-var names and semantics are documented in `docs/ref/configuration/environment-variables.md`. Update it when you add or change one.

## CI build

The `(5.x) Build and push images` workflow wraps this script. See `docs/dev/workflow-usage.md` and the wazuh-ci-tests skill.
