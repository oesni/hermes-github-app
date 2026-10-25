# Repository label creation

An explicitly authorized agent can create a repository label before assigning it to issues. This operation does not attach the label to any issue or pull request.

## Contract

- Native tool: `github_label_create(repo, name, color, description?)`; policy action: `label_create`. Both version-1 profiles remain unchanged (read eight, write thirteen); creation requires its own explicit allowance. Denials and repository exclusions win. Package version remains `0.1.0`, configuration version `1`, catalog twenty-four actions.
- Require GitHub App Issues write permission. Validate policy, protected files, inputs, and the canonical repository before sending a mutation. Refuse redirects or repository identity changes.
- `name` uses the existing label-name rules: 1–50 Unicode characters, nonblank, no control characters or surrogates, and neither `.` nor `..`. Reject leading or trailing whitespace; preserve accepted spelling and punctuation without normalization.
- `color` is exactly six ASCII hexadecimal digits without a leading `#`, normalized to lowercase. `description` is optional, defaults to the empty string, and accepts at most 100 Unicode characters with no control characters or surrogates. Unknown arguments are refused.
- Send one `POST /repos/{owner}/{repo}/labels`. Existing names are subject to GitHub validation failure; do not update an existing label, fabricate success, or perform an automatic conflict retry.
- Require a `201` response with a positive label ID and matching name, color and description. When the requested description is empty, accept an explicit upstream `null` and normalize it to the empty string; a missing description field remains unverifiable. Return only `id`, `name`, `color` and `description`. Never expose raw upstream objects or credential material. A transport failure, server error, or malformed/unverifiable success after the mutation is an uncertain outcome; never retry automatically. This plugin has no repository-label lookup tool; inspect the repository labels in GitHub before deciding whether to retry.
- Label assignment, rename and deletion are separate capabilities. Creation does not grant any of them.

## Verification

Use fake transports to verify explicit policy grants and denials, frozen profiles, native registration and argument forwarding, input boundaries, canonical repository refusal, request payload, sanitized success, duplicate-name rejection and uncertain outcomes without retries. The full suite must continue to pass without contacting live GitHub.

GitHub endpoint: [Create a label](https://docs.github.com/en/rest/issues/labels#create-a-label).
