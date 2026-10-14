---
name: wazuh-version-bump
description: Bump the repository version, stage, branch references, or image tags with tools/repository_bumper.sh (and the 5.x bumper workflow). Use when asked to change the Wazuh version, move to a new stage (alpha/beta/rc), prepare a release branch, or switch references to tag-style.
---

# Version bumping

`tools/repository_bumper.sh` rewrites version strings across the repo. It reads the current version and stage from `VERSION.json` and uses `sed -i` on files found with `grep -R`. **Run it on a clean working tree on a throwaway branch**, then review `git diff` before committing. It is not idempotent-safe against an unclean tree.

## Usage

```bash
# Branch mode: both flags required
tools/repository_bumper.sh --version 5.2.0 --stage alpha0

# Keep branch references on `main`, bump values only
tools/repository_bumper.sh --version 5.2.0 --stage alpha0 --set-as-main

# Tag mode: references become tag-like (v5.2.0-beta1), docker image tags become 5.2.0-beta1
tools/repository_bumper.sh --tag --stage beta1            # --version defaults to the one in VERSION.json
tools/repository_bumper.sh --tag                          # no stage -> plain release tag v5.2.0
```

Validation: version must be `X.Y.Z`; stage must match `alpha[N]|beta[N]|rc[N]|stable`, and is lowercased. `--tag` and `--set-as-main` are mutually exclusive.

## What it changes

| Step | Effect |
| - | - |
| main refs | `: 'main'` becomes `: '<REFERENCE>'` (skipped with `--set-as-main`) |
| version | `X.Y.Z`, `vX.Y.Z`, `X.Y` (only on lines without a full X.Y.Z) and `X.x` to the new values |
| stage | the old stage string (from `VERSION.json`) becomes the new one, everywhere except `README.md` |
| tag mode | `: 'v?ver(-stage)?'` references normalized; every `wazuh/wazuh-*:<tag>` image reference retagged |

Excluded from rewriting: `CHANGELOG.md`, `repository_bumper.sh`, `*_bumper_repository.yml`, `mermaid*.js`, `repository_bumper_*.log`. Output goes to `tools/repository_bumper_<timestamp>.log` (gitignored via `*.log`), which lists edited files.

Version literals live in many places: `VERSION.json`, `.env`, `single-node|multi-node|wazuh-agent/docker-compose.yml` image tags, `build-docker-images/build-images.sh`, `docker-bake.hcl`, and the docs (download URLs such as `wazuh-certs-tool-5.1.0-1.sh`).

## After running

1. `git diff --stat`, then confirm `VERSION.json`, `.env`, all three compose files, `build-images.sh` and `docker-bake.hcl` agree.
2. `grep -rn "<old version>" . --exclude-dir=.git` should only show historical or intentional hits (`CHANGELOG.md`, prior-version links).
3. Fix `CHANGELOG.md` by hand. The script's skeleton insert depends on a header line that is not in the file and uses `- None` / `### Deleted`, whereas the file uses tables and `### Removed`. Use the wazuh-changelog skill for the format.
4. The `docs/dev/*.md` pages say "version 5.1.0" in prose, and the bumper covers those.

## CI

`.github/workflows/5_bumper_repository.yml` (workflow_dispatch) runs the script and opens a PR. Inputs: `version`, `stage`, `tag`, `set_as_main`, `issue-link` (`https://github.com/wazuh/<repo>/issues/<n>`), `id`, and `revert` (with `bump-issue-link`) to undo a bump. The 4.x counterpart is `4_bumper_repository.yml`.

## Do not

Edit `tools/repository_bumper.sh` regexes casually. They are broad `sed` rewrites over the whole tree, so test any change on a scratch clone with a diff review.
