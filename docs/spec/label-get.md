# Repository label lookup

An authorized agent can read a known repository label before creation or inspect current state after an uncertain creation. No listing or pagination tool is added.

## Contract

- Native tool `github_label_get(repo, name)` uses the explicit-only action `label_get` and GitHub App Issues read permission. Creation and lookup grants are independent. Both version-1 profiles stay unchanged (read eight, write thirteen), package version remains `0.1.0`, and configuration version remains `1`. The catalog contains twenty-five actions.
- Apply protected-file checks, repository selection, action policy and input validation before authentication. Authenticate with the narrowly scoped installation token and verify token permissions, installation repository scope and canonical repository identity before querying a label. Denials and exclusions continue to win.
- Accept only `repo` and `name`. Names use existing label validation: 1–50 Unicode characters, nonblank, no control characters or surrogates, neither `.` nor `..`. Unlike creation, lookup accepts literal leading/trailing whitespace to support existing labels. Do not trim or normalize names; encode the entire name as one URL path segment, including slashes, percent signs, query and fragment characters.
- Send one `GET /repos/{owner}/{repo}/labels/{name}` after the prerequisite reads. Only a 404 from this label endpoint becomes `{ok: true, data: {exists: false}}`. A 404 while obtaining a token, verifying installation scope or checking repository identity is an error, not label absence. Redirects, permission/rate-limit failures, timeouts and malformed successes remain errors. Never follow redirects or fall back to anonymous requests.
- A valid 200 returns `{ok: true, data: {exists: true, id, name, color, description}}`. Validate the positive integer ID, returned label name matching the requested name case-insensitively, six-digit hexadecimal color and string-or-null description. Normalize a null description to an empty string. Reject missing required fields or conflicting explicit repository identity. Return only the named fields with existing secret redaction; do not expose raw upstream bodies or URLs.
- A successful response describes current observed state only. Existence does not establish who created the label or whether a previous creation failed because of a duplicate, missing permission, or another cause. Absence does not prove a previous uncertain creation has finished or cannot still succeed. Neither lookup nor creation automatically retries a mutation. If an existing label has different metadata, do not overwrite it automatically.
- A label-endpoint 404 is an observation under the verified session, not an atomic guarantee of continued repository access or label absence. Concurrent access changes, creations and deletions can occur after prerequisite checks or after the response.

## Verification

Use fake HTTP transports and test-only credentials. Cover explicit grants, frozen profiles, global/local denies, repository exclusions, YAML configuration and native registration/forwarding. Verify Unicode and encoded path characters, valid/null descriptions, minimal redacted results, malformed 200 including null bodies, label 404 versus authentication/installation/repository 404, mismatches, redirects, 403/429/5xx and transport failures. After a simulated uncertain creation, lookup may return present or absent but must never issue a second creation or an update. Run the integrated suite; no live mutation is required.

GitHub contracts: [Get a label](https://docs.github.com/en/rest/issues/labels#get-a-label), [404 and authentication](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api#404-not-found-for-an-existing-resource).
