# Hermes GitHub App

Native, policy-bound GitHub tools for Hermes agents. App keys and repository-scoped installation tokens remain on the host. This repository implements the [configuration contract](docs/spec/github-app-configuration.md); it does not configure a live GitHub App or install itself.

## Configuration

Copy [allowlist.yaml](examples/allowlist.yaml), [all-except.yaml](examples/all-except.yaml), or the opt-in [inline-review.yaml](examples/inline-review.yaml) to a protected host directory. Replace App/installation IDs and the absolute private-key path. Select it with the host environment variable `HERMES_GITHUB_APP_CONFIG`. YAML is strict: unknown/duplicate fields, tags, aliases, interpolation, nulls, and legacy JSON-schema fields are rejected.

```yaml
version: 1
auth:
  app_id: 12345
  installation_id: 67890
  private_key_path: /srv/hermes-private/github-app.pem
policy:
  repositories:
    mode: all
    exclude: [acme/private]
  default_access: write
  deny_actions: [pr_merge]
  repository_rules:
    acme/archive:
      access: read
```

Repository exclusions always win. `allowlist` selects exact `owner/repo` and `owner/*` entries; an empty/missing allowlist denies all. `all` permits installation-accessible repositories except exclusions. Names are case-insensitive.

For each selected repository:

```
(profile(repo.access or default_access) + global allow_actions + repo allow_actions)
  - (global deny_actions + repo deny_actions)
```

`read` is a baseline, not a ceiling: inherited/global allowances still apply. An empty repository rule inherits; it does not deny. Action lists default to empty; unknown actions and wildcards are errors. Version 1 retains its fourteen-action catalog. Version 2 adds only `pr_review_comment`, which requires an explicit `allow_actions` entry. Both versions keep the same frozen read and write profile expansions; upgrading or selecting version 2 does not grant inline comments automatically. Version 1 rejects `pr_review_comment` in configuration action lists.

| Profile | Actions |
| --- | --- |
| read | `repo_get`, `contents_read`, `issue_list`, `issue_get`, `issue_comments_list`, `pr_list`, `pr_get`, `pr_comments_list` |
| write | All read actions plus `issue_create`, `issue_comment`, `pr_create`, `pr_comment`, `branch_create` |
| explicit allowance only | `pr_merge`; version 2 also permits `pr_review_comment` |

Each operation is a separate native tool with the same name as its policy action. Arguments are flat: for example, `issue_comment` takes `{repo, number, body}` and `pr_merge` takes `{repo, number, expected_head_sha, merge_method}`. There is no generic action dispatcher or legacy operation alias. The tool schema describes each operation's closed argument set; the specification defines bounds and refusal behavior. There is no raw REST/GraphQL, credential export, file write, git push/clone, review submission or diff-reading API, PR edit/delete, auto-merge, or merge queue. PR creation/merge supports same-repository branches. Branch creation is pinned to a verified source SHA and never overwrites existing refs. `contents_read` uses named branches/tags and limits regular files to 1 MiB, returning base64 bytes.

## Inline PR comments

`pr_comment` writes a conversation comment. To comment on a line of a PR diff, opt in to configuration `version: 2` and allow `pr_review_comment` globally or for the selected repository. The read/write profiles do not include this new action. [inline-review.yaml](examples/inline-review.yaml) shows a read baseline with a repository-specific allowance and a global merge denial.

```json
{"repo":"acme/demo","number":42,"body":"Could this handle an empty input?","commit_id":"0123456789abcdef0123456789abcdef01234567","path":"src/parser.py","line":27,"side":"RIGHT"}
```

All seven fields are required. `line` is a JSON integer from 1 through 2147483647; `side` is exactly `LEFT` (old diff side) or `RIGHT` (new diff side). A multiline comment also supplies both `start_line` and `start_side`, on the same side with `start_line < line`. The path is a nonempty relative file path of at most 4096 Unicode code points without backslashes, empty/dot/parent segments, or control characters. `commit_id` is a full 40- or 64-character hexadecimal commit ID, normalized to lowercase. The body follows the same nonblank 65536-code-point limit as conversation comments.

The host confirms that the target is an open PR in the selected repository (fork-head PRs are permitted) and that its head matches `commit_id` before sending one request with `pull_requests:write` permission. GitHub validates that the requested path and line form a valid diff location. The head can change after the host check; the submitted comment remains bound to the supplied commit, so this is not an atomic current-head guarantee. A successfully created comment may return `uncertain_outcome` if a concurrent head advance changes the returned commit or line fields after the POST; it is never retried automatically. Success returns only available `id`, `html_url`, `pull_request_url`, `commit_id`, `path`, `line`, `side`, `start_line`, `start_side`, and `created_at` metadata, excluding raw diff content, body text, and user objects. Replies, batched reviews, file-level comments, review-comment editing/deletion, and reading review comments or diffs are outside this tool. See the [inline-comment contract](docs/spec/pr-inline-review-comments.md).

## Host boundary

The plugin registers fourteen tools for configuration version 1 and fifteen for version 2 through Hermes's public `register(ctx)` and `ctx.register_tool` API. It does not depend on a Hermes source revision, private agent objects, or a hash of host files. Existing host tools, hooks, delegation, and Docker container reuse stay in place; enable `github_app` alongside them.

```yaml
toolsets: [terminal, file, delegation, github_app]
```

Add `github_app` to the toolsets the host already uses. The plugin does not read that list and does not require other entries to be removed. A host that gives a child agent only part of the parent's toolsets, including Gormes Orpheus, needs `github_app` on the parent route before the child can call these tools.

Gormes also has an existing host security allowlist. Its current policy does not include these tool names, so registration alone does not permit their use. Before enabling them, explicitly add the exact names in the table above to that allowlist, preserving its existing entries and checks. Keep the security hook enabled; the plugin's repository/action policy continues to apply to every permitted call.

Every call rechecks the configuration and private-key files. The plugin enforces repository and action policy through its own tools, keeps App credentials and tokens in the host process, and returns only authorized GitHub results. Its interface provides no credential export or arbitrary host-file access. It does not add mounts, forward environment variables, or change Docker reuse. Administrators keep the config and key outside agent-reachable workspaces and mounts. A local terminal backend, a mounted Docker socket, a host volume that contains these files, or another process running as the Hermes account can read a Hermes-owned `0600` key. The plugin does not detect those setups.

Accepted modes are Hermes-owned `0400`/`0600`, or root-owned `0440`/`0640` readable through a trusted Hermes group. Final files and ancestors cannot be symlinks. Parent directories must be root/Hermes-owned without group/other write access. `/tmp` and symlinked paths are unsuitable. Group membership and the decision not to mount these files remain administrator responsibilities.

## Merge policy

All bundled examples deny `pr_merge` globally. To enable it for selected repositories, configure an explicit allowance without a conflicting global or repository denial. Merge uses the same host-enforced policy as other actions; there is no separate approval adapter or platform-specific configuration.

A merge requires the PR number, expected head SHA, and explicit merge method. The host verifies the target and immediately rechecks protected-file metadata, policy, base/head branches, and head SHA before one dispatch. GitHub atomically checks the head SHA; its API cannot atomically bind the base branch, so retargeting after the final check remains possible. An uncertain mutation is never automatically retried.

GitHub enforces repository protections. **Administrators must keep the App free of applicable bypass grants.** The plugin does not independently audit protection/ruleset bypass status and cannot guarantee protection if that prerequisite is violated. It neither requests administrative permissions nor exposes protection configuration. Tokens are scoped to the same installation, target repository, and operation permissions.

## Packaging and lifecycle

This repository is a Hermes directory plugin (`plugin.yaml`, root `__init__.py`) and a Python package. A future administrator installation must use the same dependency runtime as Hermes, enable `hermes-github-app`, and select the `github_app` toolset. Merely copying or reviewing this repository does not enable it.

Configuration and key contents are startup snapshots. Restart the plugin's Hermes process to change policy or credentials. Every operation checks file presence, regular-file status, ownership, modes, symlinks, and parent-directory permissions; a failed check refuses the call. These checks do not detect exposure through mounts or other host tools. Restoring safe files does not change the loaded contents. Invalid startup omits this plugin's tool and leaves Hermes running. Diagnostics never echo raw credentials or rejected config values.

## Development verification

```sh
python -m pip install -e '.[test]'
python -m pytest -q
HERMES_GITHUB_APP_HERMES_SOURCE=/absolute/path/to/hermes-agent python -m pytest tests/test_plugin.py::test_native_plugin_api_dispatch -q
```

The native smoke registers the tools through Hermes's public `PluginContext`, then dispatches them through Hermes's normal tool path with a fake GitHub service. It checks that string integers, string booleans, and unknown fields are rejected, and that an existing security hook can still block a call. No live GitHub operations, production secrets, or installed profile changes are used.

The operator-run [`tools/gormes_coexistence_probe.py`](tools/gormes_coexistence_probe.py) requires a prepared, fresh isolated profile. It exercises the installed Gormes hooks and Orpheus adapter with deterministic GitHub HTTP responses and a deterministic child lifecycle, plus real Docker execution and same-process container reuse. It distinguishes refusal by the unchanged host allowlist from an in-memory candidate that adds the current catalog names; it makes no production policy or profile changes. The probe uses version 2 with a read baseline and no new action allowance to check registration of the fifteen-tool catalog; it does not execute inline-comment HTTP requests. Cross-process container reuse is not tested. Set `HERMES_GITHUB_APP_GORMES_RECEIPT` to a saved probe receipt to enable its optional pytest validation, which binds the evidence to hashes of the current product modules and probe source.
