# Hermes GitHub App

Policy-controlled GitHub App tools for Hermes. Credentials stay in the host process; tools expose only authorized operations.

## Configuration

Use the configuration schema and examples packaged with this revision. Supply App and installation IDs and a protected absolute key path, such as `/secure/github-app/private-key.pem`, through `HERMES_GITHUB_APP_CONFIG`. Repository selection and explicit action permissions are enforced before GitHub operations. Exclusions and action denials take precedence; policy cannot enlarge the App installation scope.

## Operations

The model-facing tool names add `github_` to configuration action identifiers.

Configuration actions in this revision:

`repo_get`, `contents_read`, `issue_list`, `issue_get`, `issue_comments_list`, `issue_create`, `issue_comment`, `pr_list`, `pr_get`, `pr_comments_list`, `pr_create`, `pr_comment`, `pr_review_comment`, `branch_create`, `pr_merge`.

The read profile contains 8 actions and the write profile contains 13. Operations outside those profiles require explicit allowances.

## Credentials and errors

Administrators keep configuration and key files inaccessible to agents. Tools validate repository identity and operation arguments and use installation tokens restricted to the repository and required permissions. The interface does not export credentials or provide arbitrary HTTP requests. An uncertain mutation is not automatically retried.

## Development

Run the tests packaged with this revision using its declared Python dependencies. Tests use synthetic data and mock GitHub responses.
