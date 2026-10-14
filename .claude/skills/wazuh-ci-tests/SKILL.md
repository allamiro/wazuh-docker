---
name: wazuh-ci-tests
description: Understand and trigger this repo's GitHub Actions - the 5.x image build/push workflow, the Docker integration tests (PR labels test/docker*), the changelog check, and the legacy 4.x PR check. Use when asked about CI, how to test a PR, which label to add, workflow inputs, or why a check failed.
---

# CI workflows (`.github/workflows/`)

| Workflow | File | Trigger | Purpose |
| - | - | - | - |
| (5.x) Build and push images | `5_build_and_push_images.yml` | `workflow_dispatch` | Multi-arch images to ECR (dev) or Docker Hub (prod) |
| (5.x) PR Check - Docker Integration Tests | `5_check_integration_tools.yml` | PR label, `workflow_dispatch` | Build from PR branch, deploy on an AWS VM, run integration tests |
| 5.x Changelog check | `5_changelog_check.yml` | every PR event | Validates `CHANGELOG.md` additions |
| Repository bumper (5.x) | `5_bumper_repository.yml` | `workflow_dispatch` | Runs `tools/repository_bumper.sh`, opens a PR |
| 4.x variants | `4_*.yml` | legacy | Maintenance branches. `4_pr_check.yml` uses `.github/{single,multi}-node-log-check.sh` |

## Testing a pull request

Add a label to a **non-draft** PR from a branch **of this repository** (forks do not get secrets/OIDC):

| Label | Deployments tested |
| - | - |
| `test/docker` | single-node and multi-node |
| `test/docker-single` | single-node |
| `test/docker-multi` | multi-node |

To re-run after pushing: remove the label and add it again. A label added while the PR is a draft is ignored. Images are always built from the PR branch and pushed to ECR. Then an AWS VM is provisioned and the suite runs over SSH. Details and flow diagrams: `docs/ref/integration_test/docker_integration_tests.md`, `docs/dev/run-tests.md`.

Manual run: Actions, "(5.x) PR Check - Docker Integration Tests", Run workflow. Inputs: branch of wazuh-docker, branch of `wazuh-automation`, deployment type, and optionally `version` plus `stage` (stage required if version is set) and registry (ECR for dev, Docker Hub for prod).

Can be driven with `gh`:

```bash
gh pr edit <n> --add-label test/docker-single
gh workflow run "(5.x) PR Check - Docker Integration Tests" --ref <branch>
gh run list --workflow 5_check_integration_tools.yml -L 5
gh run view <run-id> --log-failed
```

Only do this when the user asks. Labels and dispatches spend AWS resources and are visible to the team.

## Build and push images workflow

Inputs (see `docs/dev/workflow-usage.md`): `image_tag`, `docker_reference`, `wazuh_automation_reference`, `products` (comma list), `commit_list` (JSON array of 4 refs, dev only), `assistant_revision`, `id`, `dev` (default true), `skip_signature_check` (dev only).

- `dev: true`: pushes to ECR, uses pre-signed S3 package URLs, adds the commit ref to tags.
- `dev: false`: pushes to Docker Hub from public repositories, supports stages (rc, beta).
- All packages must be Wazuh-signed unless `skip_signature_check` is set.

## Checks that run without CI

```bash
cd single-node && ../tools/tests/check-default-credentials.sh      # needs a running deployment, no AWS
bash -n build-docker-images/build-images.sh tools/repository_bumper.sh   # quick syntax check
docker compose -f single-node/docker-compose.yml config -q               # compose validity (needs config/credentials present for secrets)
```

`.github/.goss.yaml` holds file-permission/user expectations for the manager image (for example `wazuh-manager-control` is `0750 root:root`, `wazuh-manager.conf` is `0660 root:wazuh-manager`). Keep it in sync if the Dockerfile changes ownership or modes.

## Debugging a failed run

1. `gh run view <id> --log-failed`. The logs for failed integration tests are collected automatically (ERROR/WARNING/CRITICAL from manager logs).
2. Reproduce locally with the wazuh-deploy skill, then `docker compose logs <service>`.
3. Changelog failure: see the wazuh-changelog skill, or add the `no-changelog` label if justified.
4. Workflow permissions: workflows declare explicit `permissions:` blocks (least privilege on `GITHUB_TOKEN`). Keep that when editing them.
