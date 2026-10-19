# Hermes GitHub App

Native, policy-bound GitHub tools for Docker-backed Hermes agents. App keys and repository-scoped installation tokens remain on the host. This repository implements the approved [v1 configuration contract](docs/spec/github-app-configuration.md); it does not configure a live GitHub App or install itself.

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
  deny_actions: [pulls.merge]
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
| read | `repo.get`, `contents.read`, `issues.list`, `issues.get`, `issues.comments.list`, `pulls.list`, `pulls.get`, `pulls.comments.list` |
| write | All read actions plus `issues.create`, `issues.comment`, `pulls.create`, `pulls.comment`, `branches.create` |
| explicit allowance only | `pulls.merge` — separate human confirmation required |

`github_app_action` takes exactly `{action, repo, params}`. The tool schema describes each operation's closed argument set; the specification defines bounds and refusal behavior. There is no raw REST/GraphQL, credential export, file write, git push/clone, review/diff API, PR edit/delete, auto-merge, or merge queue. PR creation/merge supports same-repository branches. Branch creation is pinned to a verified source SHA and never overwrites existing refs. `contents.read` uses named branches/tags and limits regular files to 1 MiB, returning base64 bytes.

## Supported Hermes host boundary

Compatibility is verified against Hermes source commit `190e1ffac976ee5fc41c9f1845ba8fd886a827b1`. Integration uses native `PluginContext.register_tool`, execution middleware, the live CLI/gateway agent binding, and Docker configuration/inspection APIs. The relied-upon source files are checked against bundled SHA256 fingerprints on every call; an unreviewed Hermes upgrade fails closed.

The exhaustive supported agent-facing surfaces are:

- Native `terminal` executed by Docker and `process` limited to processes owned by the calling sandbox. Any reachable host process entry refuses operation.
- Native `read_file`, `write_file`, `patch`, and `search_files` using the same Docker backend.
- This plugin's `github_app_action`.

Interactive CLI roots and live gateway root agents are supported when the host exposes their actual agent/session binding. Unregistered standalone agents, delegated contexts without that binding, `execute_code`, delegation/Orpheus, MCP, tool-search bridges, host hooks, skill management/execution tools, and other native/plugin tools are unsupported. Their presence in the calling agent's enabled tools refuses GitHub calls. This is a deliberate published compatibility boundary, not a claim that arbitrary tools have been audited. Agent shell scripts executed by the supported terminal remain inside Docker.

Set explicit narrow Hermes toolsets before enabling the plugin:

```yaml
toolsets: [terminal, file, github_app]
plugins:
  disabled: [raft-platform]
platform_toolsets:
  cli: [terminal, file, github_app]
  discord: [terminal, file, github_app]
terminal:
  backend: docker
  docker_volumes: []
  docker_env: {}
  docker_forward_env: []
  docker_extra_args: []
  docker_mount_cwd_to_workspace: false
  docker_persist_across_processes: false
```

Every configured platform must use only the supported toolsets. Disable the bundled Raft platform hooks and any other host-hook plugins. Multiplexed gateway profiles and desktop `read_terminal` are unsupported. Startup validates known configuration; every call verifies the actual live agent tool set, native handler identities, cancellation/session binding, protected files, task overrides, active containers, and file-tool cached environments. Direct registry calls without the trusted middleware binding are refused. Local and other remote backends, custom mounts/arguments, credential/environment forwarding, task overrides, and cross-process container reuse are refused. Automatic skill/cache mounts must not expose protected paths. Persistent Docker workspaces are supported when safely isolated. Before a first file operation, the middleware initializes the environment through the terminal path so that the supported Hermes revision cannot accidentally reuse a cross-process container.

Keep config/key files outside every sandbox/mount. Accepted modes are Hermes-owned `0400`/`0600`, or root-owned `0440`/`0640` readable through a trusted Hermes group. Final files and ancestors cannot be symlinks. Parent directories must be root/Hermes-owned without group/other write access (a conservative subset of trusted-directory layouts). `/tmp` and symlinked paths are unsuitable. Group membership and trusted host/Docker integrity remain administrator responsibilities. The host Python/plugin code must not be writable by the agent. No other credentials or host control services should bypass this boundary.

## Human merge confirmation

Both bundled policy examples deny merges globally. Explicitly allowing `pulls.merge` still does not authorize one. A separately configured `merge_approval.approvers` list must contain stable human Discord user IDs; see [merge-approvers.yaml](examples/merge-approvers.yaml). Empty lists leave merge unavailable. Bot accounts, usernames, roles, and other platforms cannot approve.

The adapter uses the existing running Hermes Discord client's authenticated interactions. It sends host-owned DMs with Approve/Deny buttons to configured approvers; it never starts another bot or reads its token. Message/channel bindings and actor identity are checked. Ordinary chat messages, agent arguments, and forged approval flags cannot approve. CLI-originated calls can use this adapter only when a live gateway client exists in that host process; otherwise merge returns `approval_required_unavailable`.

The confirmation shows repository, PR, base/head branch, expected head SHA, method, escaped untrusted title, and the remaining base-retarget race. Approval is tied to one call/session/target and expires ten minutes after presentation. Configure host tool timeouts for that window plus the bounded API operation. Interruption/session replacement cancels pending requests. GitHub atomically checks the head SHA; it cannot atomically bind the base branch. An uncertain mutation is never automatically retried.

GitHub enforces repository protections. **Administrators must keep the App free of applicable bypass grants.** The plugin does not independently audit protection/ruleset bypass status and cannot guarantee protection if that prerequisite is violated. It neither requests administrative permissions nor exposes protection configuration. Tokens are scoped to the same installation, target repository, and operation permissions.

## Packaging and lifecycle

This repository is a Hermes directory plugin (`plugin.yaml`, root `__init__.py`) and a Python package. A future administrator installation must use the same dependency runtime as Hermes, enable `hermes-github-app`, and select `github_app` alongside the narrow surfaces above. Merely copying or reviewing this repository does not enable it.

Configuration and key contents are startup snapshots. Restart the plugin's Hermes process to change policy, approvers, or credentials. Files are still checked on every operation for presence/ownership/mode/isolation; removing or exposing them refuses calls. Restoring safe files does not change the loaded contents. Invalid startup omits this plugin's tool and leaves Hermes running. Diagnostics never echo raw credentials or rejected config values.

## Development verification

```sh
python -m pip install -e '.[test]'
python -m pytest -q
HERMES_GITHUB_APP_HERMES_SOURCE=/absolute/path/to/hermes-agent python -m pytest tests/test_plugin.py::test_native_hermes_dispatch -q
HERMES_GITHUB_APP_DOCKER_TEST=1 python -m pytest tests/test_isolation.py::test_real_docker_inspect_boundary -q
```

The native smoke uses real Hermes middleware/dispatch with a test live-agent binding and fake GitHub service. Docker smoke creates and removes a disposable Alpine container. Discord tests exercise actual `discord.py` views/callbacks with mocked network delivery; no live approvals, GitHub operations, production secrets, or installed profile changes are performed.
