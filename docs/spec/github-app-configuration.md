# GitHub App configuration interface

## Summary

A YAML policy configures one GitHub App installation, permitted repositories and closed operation names. Credentials remain in the host process.

## Behavior

1. Configuration requires `version`, `auth` and `policy`. The accepted version is determined by this revision's strict parser. Authentication contains App ID, installation ID and an absolute protected private-key path. No credential values or request-header overrides are accepted as tool arguments.
2. Repository mode is `allowlist` or `all`. Exact repository names and owner selectors determine eligibility; exclusions take precedence. Installation scope remains an independent ceiling.
3. An eligible repository's action set is its read/write baseline plus global and repository allowances, minus all denials. Unknown actions and unsupported fields are rejected. Rules do not add repositories outside the selected scope.
4. The model-facing tool names add `github_` to configuration action identifiers.
5. The exact read profile is `contents_read`, `issue_comments_list`, `issue_get`, `issue_list`, `pr_comments_list`, `pr_get`, `pr_list`, `repo_get`. The exact write profile is `branch_create`, `contents_read`, `issue_comment`, `issue_comments_list`, `issue_create`, `issue_get`, `issue_list`, `pr_comment`, `pr_comments_list`, `pr_create`, `pr_get`, `pr_list`, `repo_get`. Other catalog actions require explicit allowance.
6. This revision recognizes exactly these configuration actions: `repo_get`, `contents_read`, `issue_list`, `issue_get`, `issue_comments_list`, `issue_create`, `issue_comment`, `pr_list`, `pr_get`, `pr_comments_list`, `pr_create`, `pr_comment`, `pr_review_comment`, `branch_create`, `pr_merge`.
7. Merge uses explicit action authorization and GitHub prerequisites. No action grant bypasses GitHub repository protections.
8. Protected configuration and key metadata are checked before operations. File ownership, permissions, path safety and the administrator's control of agent access remain required. Changing configuration requires a new configuration snapshot; no implicit permissive fallback is selected.
9. Requests use fixed GitHub endpoints and validated arguments. Canonical target identity and minimal token permissions are verified. Failures are sanitized, credentials are not returned, and ambiguous writes are not automatically repeated.
10. Public operation schemas and tests packaged with this revision define the argument bounds, target prerequisites and result fields for its catalog. This document does not add operations or broaden existing profiles.

    ```yaml
    version: 1
    auth:
      app_id: 12345
      installation_id: 67890
      private_key_path: /secure/github-app/private-key.pem
    policy:
      repositories:
        mode: allowlist
        allow: [acme/*]
        exclude: [acme/payroll]
      default_access: read
      allow_actions: [issue_comment]
      deny_actions: [pr_merge]
      repository_rules:
        acme/support:
          access: write
          allow_actions: [pr_merge]
        acme/archive:
          access: read
          deny_actions: [issue_comment]
        acme/inherits: {}
    ```

    ```yaml
    version: 1
    auth:
      app_id: 12345
      installation_id: 67890
      private_key_path: /secure/github-app/private-key.pem
    policy:
      repositories:
        mode: all
        exclude: [acme/payroll, secret-org/*, acme/frozen]
      default_access: write
      allow_actions: []
      deny_actions: [pr_merge]
      repository_rules:
        acme/archive:
          access: read
        acme/support:
          deny_actions: [branch_create]
        acme/inherits: {}
    ```
