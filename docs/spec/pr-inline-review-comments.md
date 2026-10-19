# Inline PR review comments

## Behavior

`pr_review_comment` creates one comment attached to a line or range of lines in a pull-request diff. `pr_comment` continues to create conversation comments, and `pr_comments_list` continues to exclude inline review comments. This feature does not expose arbitrary GitHub requests, pending/batched review submission, replies to existing review comments, file-level comments, editing/deletion, or diff/review-comment reads.

The tool and policy action share the exact unprefixed snake_case name `pr_review_comment`. Configuration version 1 recognizes the fifteen-action catalog, including this operation. Package and configuration versions remain unchanged. The eight-action `read` and thirteen-action `write` profiles remain unchanged. Administrators must explicitly allow the new action and restart the plugin to load the new snapshot. Merely upgrading the package or selecting `write` does not grant it. Existing repository selection, exclusions, global/local denial precedence, installation ceiling, protected-file rechecks, and credential non-disclosure rules apply unchanged.

## Closed arguments

| Field | Required | Meaning |
| --- | --- | --- |
| `repo` | Yes | Selected canonical `owner/repo`, following the existing repository-name rules |
| `number` | Yes | PR number, JSON integer 1 through 2147483647; boolean and string integers rejected |
| `body` | Yes | Nonblank string of at most 65536 Unicode code points; NUL forbidden, line breaks and tabs permitted |
| `commit_id` | Yes | Full 40- or 64-character hexadecimal commit ID, normalized to lowercase; no revision expression or abbreviation |
| `path` | Yes | Nonempty repository-relative file path of at most 4096 Unicode code points; no absolute path, backslash, empty segment, `.`/`..` segment, or control character |
| `line` | Yes | JSON integer 1 through 2147483647 identifying the final diff line on `side`; boolean and string integers rejected |
| `side` | Yes | Exact `LEFT` for the old diff side or `RIGHT` for the new diff side |
| `start_line` | No | JSON integer 1 through 2147483647 strictly less than `line`; requires `start_side` |
| `start_side` | No | Requires `start_line`, and must equal `side` |

All other fields are rejected, including `position`, `in_reply_to`, `subject_type`, review IDs, and arbitrary endpoint fields. Omitting both start fields selects a single-line comment. A multiline comment supplies both fields; cross-side ranges are refused.

## Dispatch and result

The host checks policy and protected files before obtaining a repository-restricted installation token with `pull_requests:write` and unavoidable metadata access. It confirms the PR exists in the selected repository (fork-head PRs are permitted), is open, and has a current head SHA equal to `commit_id`. An issue number is an invalid target. The host submits exactly one `POST /repos/{owner}/{repo}/pulls/{number}/comments` request with the validated fields, using the [GitHub create-review-comment contract](https://docs.github.com/en/rest/pulls/comments#create-a-review-comment-for-a-pull-request). It never retries an uncertain mutation automatically.

GitHub validates the path, line, side, and range against the diff; the plugin does not fetch or independently reconstruct the diff. A SHA mismatch before submission returns a target-changed refusal. GitHub provides no atomic current-PR-head precondition for this endpoint: the PR can advance after the host check, and the submitted comment remains attached to the explicit commit. Do not claim atomic head binding or that a successful comment is necessarily on the newest head. Existing host checks and error classifications apply: invalid arguments or target, policy denial, protected-file refusal, GitHub denial/unavailability, and uncertain post-dispatch outcome. Success returns only these comment metadata fields when present: `id`, `html_url`, `pull_request_url`, `commit_id`, `path`, `line`, `side`, `start_line`, `start_side`, and `created_at`. It does not return raw diff content (`diff_hunk`), body text, or user objects. A successfully created comment may still return `uncertain_outcome` if a concurrent head advance changes the returned commit or line fields after the POST; the plugin never retries it automatically.

## Verification criteria

Tests cover configuration-version validation and unchanged profile membership; global/local grants and deny precedence; valid single/multiline requests; malformed SHA, path, line, side, and range rejection; PR versus issue and closed-target refusal; changed-head refusal without a POST; one request with minimal token permissions; GitHub invalid-location refusal; uncertain-outcome handling without retry; credential non-disclosure; manifest/catalog agreement; and public Hermes tool registration/dispatch. Test transports provide GitHub responses rather than posting comments to live repositories.
