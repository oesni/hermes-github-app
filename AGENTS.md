# Hermes GitHub App plugin

## Contract and implementation

- Native tool names and configuration action names are the same unprefixed snake_case identifiers (for example, `pr_merge` and `issue_comment`). Reject legacy dotted names; do not add aliases or a generic dispatcher tool.
- Read `docs/spec/github-app-configuration.md` before changing behavior. It defines the version-1 configuration and runtime contract. This unreleased implementation recognizes fifteen actions, including the user-requested `pr_review_comment` through explicit action allowance. The read profile retains eight actions and write retains thirteen; neither includes inline review comments or merge. The user explicitly requested no package or configuration version bump for this addition.
- Keep GitHub App keys, JWTs, installation tokens, configuration, and authorization decisions on the trusted host. Never expose credentials through agent arguments, results, errors, logs, forwarded environments, or sandbox mounts.
- Enforce repository selection, exclusions, action policy, argument validation, canonical target checks, and operation prerequisites on the host before mutation. Explicit denials win over grants. Merge uses the same explicit action policy and GitHub protection checks; do not add an unsolicited approval adapter or platform-specific authorization workflow.
- Register GitHub tools through Hermes's public `register(ctx)` and `ctx.register_tool` API. Do not pin a Hermes source revision, and do not restrict the host's other tools, hooks, delegation, or Docker container reuse. Keep credentials and repository policy inside this plugin, and recheck the protected configuration and key files before every operation.
- Preserve the complete startup snapshot and per-call isolation rechecks. Do not add implicit hot reload or credential fallback.

## Development and verification

- Use a purpose-specific Git worktree for code, debugging, tests, and branch work; do not edit the default checkout.
- Run focused tests for changed behavior and the integrated suite before publication. Use fake transports and test-only credentials; ordinary tests must not contact live GitHub or require a real App secret.
- Installation, activation, deployment, and live mutations require explicit user authorization. Tests or documentation do not provide that authorization.
- Keep documentation and examples consistent with the validated schema and supported runtime. Report unsupported behavior and unverified live behavior accurately.

## Git and review

- Use Conventional Commits for commit messages and PR titles.
- Publish feature changes through reviewable pull requests. Never push to `main`; the initial license-only bootstrap exception has already been used.
- Never merge, enable auto-merge, or enqueue a merge without the user's explicit instruction authorizing that specific PR. Implementation, review, or publication requests do not authorize a merge.
- When a particular PR merge is explicitly authorized, use squash merge only. Do not bypass repository protections or rewrite published history.
