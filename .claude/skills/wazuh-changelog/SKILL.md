---
name: wazuh-changelog
description: Add or validate a CHANGELOG.md entry for a change in this repo so the "5.x Changelog check" PR workflow passes. Use whenever preparing a PR, committing a user-visible change, or when asked to update the changelog.
---

# CHANGELOG.md entries

PRs to this repo must add a changelog entry unless labeled `no-changelog`. The check is `.github/workflows/5_changelog_check.yml`; it diffs `CHANGELOG.md` against `origin/<base>...HEAD` and validates every **added** line.

## Format

Under the current version heading (`## [X.Y.Z]`), add a row to the right section table (`### Added`, `### Changed`, `### Removed`, `### Fixed`):

```markdown
| [#1234](https://github.com/wazuh/wazuh-docker/issues/1234) | Short imperative description of the change |
```

Rules the CI enforces on each added line that starts with `|` or `-`. It must match one of:

- Table row: `^\| \[#[0-9]+\]\(https://github\.com/[^)]+/(issues|pull)/[0-9]+\) \| .+ \|$`. The number must be linked, and the URL may point to any `github.com/<org>/<repo>` (internal-devel-requests is used).
- Table header: `| Issue | Comment |` or `| - | - |`.
- `- None`.
- Prior-version link: `- [vX.Y.Z](https://github.com/<org>/<repo>/blob/<ref>/CHANGELOG.md)`.

Anything else fails. Typical mistakes: unlinked `#123`, a bare bullet, a missing trailing `|`, a description with a literal `|` inside it, or a row placed under a heading that does not exist.

## Workflow

1. Find the issue or PR number. If there is none, ask the user. Do not invent one.
2. Open `CHANGELOG.md` and find the top `## [X.Y.Z]` section, matching `VERSION.json`.
3. Pick the section: new capability = Added, behavior change = Changed, removal = Removed, bug = Fixed.
4. Put the new row at the **top** of that table body, after the `| - | - |` separator, matching the existing style (sentence case, no trailing period, backticks for files/vars).
5. Leave empty sections as the `| Issue | Comment |` / `| - | - |` header only.

Existing rows are the style guide, for example `| [#2652](https://github.com/wazuh/wazuh-docker/issues/2652) | Mount the Wazuh manager agent listener certificate, and forward `--agent-san` ... |`.

## Local check

```bash
git diff -U0 origin/main...HEAD -- CHANGELOG.md | grep -E '^\+[^+]'
```

Every printed line (minus the leading `+`) has to match one of the forms above.

## Caveat

`tools/repository_bumper.sh` inserts a `- None` / `### Deleted` skeleton after a line "All notable changes to this project will be documented in this file.", which the current `CHANGELOG.md` does not contain, and the file uses `### Removed`. After a version bump, check the changelog by hand. See the wazuh-version-bump skill.
