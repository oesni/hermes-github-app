# Hermes GitHub App

Native, policy-bound GitHub tools for Hermes agents. App keys and repository-scoped installation tokens remain on the host. This repository implements the [configuration contract](docs/spec/github-app-configuration.md); it does not configure a live GitHub App or install itself.

## Configuration

Copy [allowlist.yaml](examples/allowlist.yaml), [all-except.yaml](examples/all-except.yaml), [issue-labels.yaml](examples/issue-labels.yaml), or the opt-in [inline-review.yaml](examples/inline-review.yaml) to a protected host directory. Replace App/installation IDs and the absolute private-key path. Select it with the host environment variable `HERMES_GITHUB_APP_CONFIG`. YAML is strict: unknown/duplicate fields, tags, aliases, interpolation, nulls, and legacy JSON-schema fields are rejected.

```yaml
version: 1
auth:
  app_id: 12345
  installation_id: 67890
  private_key_path: /secure/github-app/private-key.pem
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

`read` is a baseline, not a ceiling: inherited/global allowances still apply. An empty repository rule inherits; it does not deny. Action lists default to empty; unknown actions and wildcards are errors. Configuration version 1 recognizes twenty-two actions, including `pr_review_comment`, which requires an explicit `allow_actions` entry. The read and write profile expansions remain unchanged; upgrading does not grant inline comments, label mutations, PR body updates, source comment reads or reactions automatically.

| Profile | Configuration actions (public tools add `github_`) |
| --- | --- |
| read | `repo_get`, `contents_read`, `issue_list`, `issue_get`, `issue_comments_list`, `pr_list`, `pr_get`, `pr_comments_list` |
| write | All read actions plus `issue_create`, `issue_comment`, `pr_create`, `pr_comment`, `branch_create` |
| explicit allowance only | `pr_merge`, `pr_review_comment`, `issue_labels_add`, `issue_label_remove`, `pr_update_body`, `issue_comment_get`, `pr_review_comment_get`, `issue_comment_reaction`, `pr_review_comment_reaction` |

Each operation is a separate native tool named `github_<action>`; configuration actions remain unprefixed. For example, action `issue_comment` is exposed as `github_issue_comment`, and `pr_merge` as `github_pr_merge`. Arguments are flat: `github_issue_comment` takes `{repo, number, body}` and `github_pr_merge` takes `{repo, number, expected_head_sha, merge_method}`. Prefixed action names in configuration are rejected. There is no generic action dispatcher or legacy operation alias. The tool schema describes each operation's closed argument set; the specification defines bounds and refusal behavior. There is no raw REST/GraphQL, credential export, file write, git push/clone, review submission or diff-reading API, general PR edits beyond the explicit body action, PR deletion, auto-merge, or merge queue. PR creation/merge supports same-repository branches. Branch creation is pinned to a verified source SHA and never overwrites existing refs. `contents_read` uses named branches/tags and limits regular files to 1 MiB, returning base64 bytes.

## Inline PR comments

`github_pr_comment` writes a conversation comment. To comment on a line of a PR diff, keep configuration `version: 1` and explicitly allow `pr_review_comment` globally or for the selected repository. The read/write profiles do not include this new action. [inline-review.yaml](examples/inline-review.yaml) shows a read baseline with a repository-specific allowance and a global merge denial.

```json
{"repo":"acme/demo","number":42,"body":"Could this handle an empty input?","commit_id":"0123456789abcdef0123456789abcdef01234567","path":"src/parser.py","line":27,"side":"RIGHT"}
```

All seven fields are required. `line` is a JSON integer from 1 through 2147483647; `side` is exactly `LEFT` (old diff side) or `RIGHT` (new diff side). A multiline comment also supplies both `start_line` and `start_side`, on the same side with `start_line < line`. The path is a nonempty relative file path of at most 4096 Unicode code points without backslashes, empty/dot/parent segments, or control characters. `commit_id` is a full 40- or 64-character hexadecimal commit ID, normalized to lowercase. The body follows the same nonblank 65536-code-point limit as conversation comments.

The host confirms that the target is an open PR in the selected repository (fork-head PRs are permitted) and that its head matches `commit_id` before sending one request with `pull_requests:write` permission. GitHub validates that the requested path and line form a valid diff location. The head can change after the host check; the submitted comment remains bound to the supplied commit, so this is not an atomic current-head guarantee. A successfully created comment may return `uncertain_outcome` if a concurrent head advance changes the returned commit or line fields after the POST; it is never retried automatically. Success returns only available `id`, `html_url`, `pull_request_url`, `commit_id`, `path`, `line`, `side`, `start_line`, `start_side`, and `created_at` metadata, excluding raw diff content, body text, and user objects. Replies, batched reviews, file-level comments, review-comment editing/deletion, and diff reads are outside this creation tool. Read one inline review comment by ID with the separately allowed `github_pr_review_comment_get` tool. See the [inline-comment contract](docs/spec/pr-inline-review-comments.md).

## Host boundary

The plugin registers twenty-two tools through Hermes's public `register(ctx)` and `ctx.register_tool` API. Enable the `github_app` toolset in Hermes to expose them.

```yaml
toolsets: [github_app]
```

Enable `github_app` in the Hermes profiles that need these tools. Tool availability is selected by the host; repository and action permissions remain enforced by this plugin.

Every call rechecks the configuration and private-key files. The plugin enforces repository and action policy through its own tools and provides no credential export or arbitrary host-file access. Administrators must keep those files inaccessible to agents; the plugin does not isolate arbitrary programs running under the same operating-system account.

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

Optional native tests register and dispatch tools through Hermes's public plugin API. Mock HTTP transports verify operation payloads, scoped permissions, strict input validation and sanitized results without live GitHub mutations or real credentials.

### Issue classification

`github_issue_labels_add(repo, number, labels)` adds existing repository labels to an issue. `github_issue_label_remove(repo, number, label)` removes one label. Both preserve unrelated labels and reject pull request numbers. Names retain Unicode and punctuation, with plugin limits of 50 characters per name and 1–100 distinct additions per call. There is no explicit label creation, full replacement, or remove-all tool. Existence checks are not atomic with addition: a concurrent deletion or rename leaves GitHub authoritative for the add request, and the plugin cannot guarantee that the server never creates or recreates a label. Each action needs an explicit unprefixed `allow_actions` entry; the write profile stays unchanged. See [the contract](docs/spec/issue-label-actions.md) and [issue-labels.yaml](examples/issue-labels.yaml). An uncertain write is never retried automatically.

## PR body and comment operations

`github_pr_update_body(repo, number, body)` replaces only an existing PR body, including an empty body, with `pull_requests:write`. Open, closed and merged PRs are accepted. Concurrent body edits are not protected by a compare-and-swap operation. Success returns only the number and canonical PR URL.

`github_issue_comment_get(repo, comment_id)` and `github_pr_review_comment_get(repo, comment_id)` read one conversation or inline review comment. Results include only ID, body, actor ID/login/type, a validated comment HTML URL, and the parent API URL. They omit raw diff hunks and unrelated response fields. The shared issue-comment endpoint supports both issue and PR conversation comments using Issues read permission; inline review comments use Pull requests read permission.

`github_issue_comment_reaction(repo, comment_id)` and `github_pr_review_comment_reaction(repo, comment_id)` add one `eyes` reaction using Issues write or Pull requests write respectively. They accept no reaction-content selector. Success returns reaction ID, fixed content, actor metadata and `created` (`false` for an already-present reaction). An uncertain write is not retried automatically.

All five operations require explicit unprefixed policy allowances and are model-callable wherever the `github_app` toolset is enabled. Action policy applies to repository and operation, not to individual callers. The [PR body and comment operations contract](docs/spec/pr-body-and-comment-operations.md) defines strict arguments, URL checks, response fields and error behavior.
