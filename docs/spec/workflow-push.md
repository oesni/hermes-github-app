# Workflow-file publication

## Summary

Operators may explicitly authorize Git publication with permission to update GitHub Actions workflow files. Ordinary publication retains its existing permission scope.

## Behavior

1. `github_git_push` accepts the optional boolean `workflow_write`, defaulting to false. Invalid types are rejected before GitHub authentication.
2. `workflow_write: true` requires both the existing `git_push` grant and the separate `git_push_workflows` policy grant for the target repository. This grant is not itself a callable tool and is excluded from the default read and write profiles. Global and repository denials take precedence.
3. Without the caller's explicit true value, publication requests only the existing Contents permission, even when the policy grants workflow access. With it, publication requests Contents write and Workflows write, scoped to the target repository. The GitHub App installation must already have granted these permissions; the plugin does not change installation permissions.
4. Both grants and isolation are checked before publication, including against the canonical repository returned by GitHub and immediately before the remote write. Denial fails closed. An absent or rejected installation permission fails without falling back to a broader token or retrying.
5. This option permits workflow changes; it does not require them or independently limit the paths in the push. Other publication rules, limits, branch protections, lease checks, and uncertain-outcome handling remain unchanged. An uncertain push is never retried automatically.
6. Workflow permissions can allow published changes to affect GitHub Actions. Operators should grant them only for repositories and callers they trust, and remain responsible for GitHub protections and downstream automation.
