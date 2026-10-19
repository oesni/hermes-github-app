# Hermes GitHub App

Native, policy-bound GitHub tools for Hermes agents. App keys and repository-scoped installation tokens remain on the host. This repository implements the approved [v1 configuration contract](docs/spec/github-app-configuration.md); it does not configure a live GitHub App or install itself.

## Configuration

Copy [allowlist.yaml](examples/allowlist.yaml) or [all-except.yaml](examples/all-except.yaml) to a protected host directory. Replace App/installation IDs and the absolute private-key path. Select it with the host environment variable `HERMES_GITHUB_APP_CONFIG`. YAML is strict: unknown/duplicate fields, tags, aliases, interpolation, nulls, and legacy JSON-schema fields are rejected.

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

`read` is a baseline, not a ceiling: inherited/global allowances still apply. An empty repository rule inherits; it does not deny. Action lists default to empty; unknown actions and wildcards are errors. The fourteen-action v1 catalog and profile expansions are fixed across upgrades.

| Profile | Actions |
| --- | --- |
| read | `repo_get`, `contents_read`, `issue_list`, `issue_get`, `issue_comments_list`, `pr_list`, `pr_get`, `pr_comments_list` |
| write | All read actions plus `issue_create`, `issue_comment`, `pr_create`, `pr_comment`, `branch_create` |
| explicit allowance only | `pr_merge` — explicit policy allowance required |

Each operation is a separate native tool with the same name as its policy action. Arguments are flat: for example, `issue_comment` takes `{repo, number, body}` and `pr_merge` takes `{repo, number, expected_head_sha, merge_method}`. There is no generic action dispatcher or legacy operation alias. The tool schema describes each operation's closed argument set; the specification defines bounds and refusal behavior. There is no raw REST/GraphQL, credential export, file write, git push/clone, review/diff API, PR edit/delete, auto-merge, or merge queue. PR creation/merge supports same-repository branches. Branch creation is pinned to a verified source SHA and never overwrites existing refs. `contents_read` uses named branches/tags and limits regular files to 1 MiB, returning base64 bytes.

## Host boundary

The plugin registers its fourteen tools through Hermes's public `register(ctx)` and `ctx.register_tool` API. It does not depend on a Hermes source revision, private agent objects, or a hash of host files. Existing host tools, hooks, delegation, and Docker container reuse stay in place; enable `github_app` alongside them.

```yaml
toolsets: [terminal, file, delegation, github_app]
```

Add `github_app` to the toolsets the host already uses. The plugin does not read that list and does not require other entries to be removed. A host that gives a child agent only part of the parent's toolsets, including Gormes Orpheus, needs `github_app` on the parent route before the child can call these tools.

Every call rechecks the configuration and private-key files. The plugin keeps JWTs and installation tokens in the host process and returns only the authorized GitHub result. It does not add mounts, forward environment variables, or change Docker reuse. Administrators keep the config and key outside agent-reachable workspaces and mounts. A local terminal backend, a mounted Docker socket, a host volume that contains these files, or another process running as the Hermes account can read a Hermes-owned `0600` key. The plugin does not detect those setups.

Accepted modes are Hermes-owned `0400`/`0600`, or root-owned `0440`/`0640` readable through a trusted Hermes group. Final files and ancestors cannot be symlinks. Parent directories must be root/Hermes-owned without group/other write access. `/tmp` and symlinked paths are unsuitable. Group membership and the decision not to mount these files remain administrator responsibilities.

## Merge policy

Both bundled examples deny `pr_merge` globally. To enable it for selected repositories, configure an explicit allowance without a conflicting global or repository denial. Merge uses the same host-enforced policy as other actions; there is no separate approval adapter or platform-specific configuration.

A merge requires the PR number, expected head SHA, and explicit merge method. The host verifies the target and immediately rechecks isolation, policy, base/head branches, and head SHA before one dispatch. GitHub atomically checks the head SHA; its API cannot atomically bind the base branch, so retargeting after the final check remains possible. An uncertain mutation is never automatically retried.

GitHub enforces repository protections. **Administrators must keep the App free of applicable bypass grants.** The plugin does not independently audit protection/ruleset bypass status and cannot guarantee protection if that prerequisite is violated. It neither requests administrative permissions nor exposes protection configuration. Tokens are scoped to the same installation, target repository, and operation permissions.

## Packaging and lifecycle

This repository is a Hermes directory plugin (`plugin.yaml`, root `__init__.py`) and a Python package. A future administrator installation must use the same dependency runtime as Hermes, enable `hermes-github-app`, and select the `github_app` toolset. Merely copying or reviewing this repository does not enable it.

Configuration and key contents are startup snapshots. Restart the plugin's Hermes process to change policy or credentials. Files are still checked on every operation for presence/ownership/mode/isolation; removing or exposing them refuses calls. Restoring safe files does not change the loaded contents. Invalid startup omits this plugin's tool and leaves Hermes running. Diagnostics never echo raw credentials or rejected config values.

## Development verification

```sh
python -m pip install -e '.[test]'
python -m pytest -q
HERMES_GITHUB_APP_HERMES_SOURCE=/absolute/path/to/hermes-agent python -m pytest tests/test_plugin.py::test_native_plugin_api_dispatch -q
```

The native smoke registers the tools through Hermes's public `PluginContext`, then dispatches them through Hermes's normal tool path with a fake GitHub service. It checks that string integers, string booleans, and unknown fields are rejected, and that an existing security hook can still block a call. No live GitHub operations, production secrets, or installed profile changes are used.
