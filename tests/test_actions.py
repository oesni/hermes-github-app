import unittest
from hermes_github_app.actions import ACTIONS, ActionError, build_request, validate_params, valid_ref, valid_sha


SHA = "a" * 40
FIXTURES = {"repo_get": {}, "contents_read": {"path": "README.md"}, "issue_list": {}, "issue_get": {"number": 1}, "issue_comments_list": {"number": 1}, "issue_create": {"title": "Report"}, "issue_comment": {"number": 1, "body": "Hello"}, "pr_list": {}, "pr_get": {"number": 2}, "pr_comments_list": {"number": 2}, "pr_create": {"title": "Change", "head": "feature/a", "base": "main"}, "pr_comment": {"number": 2, "body": "Review"}, "branch_create": {"branch": "new", "source_commit_sha": SHA}, "pr_merge": {"number": 1, "expected_head_sha": SHA, "merge_method": "squash"}}


FIXTURES["pr_review_comment"] = {"number": 2, "body": "Review", "commit_id": SHA, "path": "src/main.py", "line": 10, "side": "RIGHT"}


class ActionsTests(unittest.TestCase):
    def test_closed_catalog_and_transport_overrides(self):
        self.assertEqual(set(FIXTURES), set(ACTIONS))
        for action, params in FIXTURES.items():
            r = build_request(action, "Acme/Repo", params)
            self.assertTrue(r.path.startswith("/repos/acme/repo"))
            self.assertIn(r.method, {"GET", "POST", "PUT"})
            for override in ["url", "headers", "method", "token", "permissions", "installation_id", "approved", "force"]:
                with self.subTest(action=action, override=override), self.assertRaises(ActionError):
                    build_request(action, "acme/repo", dict(params, **{override: "override"}))

    def test_defaults_and_comment_routes(self):
        self.assertEqual(validate_params("issue_list", {}), {"state": "open", "page": 1, "per_page": 30})
        self.assertEqual(validate_params("issue_create", {"title": "a"}), {"title": "a", "body": ""})
        self.assertFalse(validate_params("pr_create", FIXTURES["pr_create"])["draft"])
        for action in ["issue_comments_list", "pr_comments_list"]:
            r = build_request(action, "acme/repo", {"number": 2})
            self.assertEqual(r.path, "/repos/acme/repo/issues/2/comments")
            self.assertEqual(r.query, {"page": 1, "per_page": 30})
        r = build_request("pr_comment", "acme/repo", {"number": 2, "body": "a\nb\tc"})
        self.assertEqual(r.body, {"body": "a\nb\tc"})

    def test_contents_safe_path_and_no_revision_expressions(self):
        r = build_request("contents_read", "acme/repo", {"path": "dir/a?#%.txt", "ref": "feature/x"})
        self.assertEqual(r.path, "/repos/acme/repo/contents/dir/a%3F%23%25.txt")
        self.assertEqual(r.query, {"ref": "feature/x"})
        self.assertEqual(build_request("contents_read", "acme/repo", {"path": ""}).path, "/repos/acme/repo/contents")
        for path in ["/etc/passwd", "../secret", "a/../b", "a//b", "a/./b", "a\\b", "a\nheader", chr(0xD800)]:
            with self.subTest(path=path), self.assertRaises(ActionError):
                build_request("contents_read", "acme/repo", {"path": path})
        r = build_request("contents_read", "acme/repo", {"path": "%2e%2e/%2fsecret"})
        self.assertEqual(r.path, "/repos/acme/repo/contents/%252e%252e/%252fsecret")

    def test_git_branch_and_ref_names(self):
        for name in ["main", "feature/a", "é" * 127, "v1.2", "release-1"]:
            self.assertEqual(valid_ref(name, branch=True), name)
        for name in ["HEAD", "refs/heads/main", SHA, "a" * 64, "main~1", "main^", "a..b", "a b", "a:b", "http://host/x", "a\\b", "a?b", "a*b", "a[b", ".a", "a/.b", "a.lock", "a/b.lock", "a/", "a//b", "@", "a@{1}", "a.", "é" * 128, "-branch"]:
            with self.subTest(name=name), self.assertRaises(ActionError):
                valid_ref(name, branch=True)
        for name in ["main~1", SHA, "a" * 64, "a:b"]:
            with self.assertRaises(ActionError):
                build_request("contents_read", "acme/repo", {"path": "", "ref": name})
        for field in ["head", "base"]:
            with self.assertRaises(ActionError):
                build_request("pr_create", "acme/repo", dict(FIXTURES["pr_create"], **{field: "owner:branch"}))

    def test_branch_source_forms_and_sha_normalization(self):
        for length in [40, 64]:
            self.assertEqual(valid_sha("A" * length), "a" * length)
        for value in ["a" * 39, "a" * 41, "g" * 40, "main", True, None]:
            with self.assertRaises(ActionError):
                valid_sha(value)
        r = build_request("branch_create", "acme/repo", {"branch": "new", "source_branch": "main", "expected_source_sha": SHA.upper()})
        self.assertEqual(r.body, {"ref": "refs/heads/new", "sha": SHA})
        for params in [{"branch": "new"}, {"branch": "new", "source_branch": "main"}, {"branch": "new", "expected_source_sha": SHA}, {"branch": "new", "source_commit_sha": SHA, "source_branch": "main"}, {"branch": "new", "source_commit_sha": SHA, "expected_source_sha": SHA}]:
            with self.subTest(params=params), self.assertRaises(ActionError):
                validate_params("branch_create", params)

    def test_merge_has_explicit_method_and_head(self):
        r = build_request("pr_merge", "acme/repo", FIXTURES["pr_merge"])
        self.assertEqual((r.method, r.path), ("PUT", "/repos/acme/repo/pulls/1/merge"))
        self.assertEqual(r.body, {"sha": SHA, "merge_method": "squash"})
        self.assertEqual(ACTIONS["pr_merge"].permissions, {"contents": "write", "pull_requests": "read"})
        for method in [None, "", "auto", "SQUASH", []]:
            with self.assertRaises(ActionError):
                validate_params("pr_merge", dict(FIXTURES["pr_merge"], merge_method=method))
        with self.assertRaises(ActionError):
            validate_params("pr_merge", {"number": 1, "expected_head_sha": SHA})

    def test_text_numbers_types_and_bounds(self):
        for params in [None, [], "", {1: "x"}]:
            with self.assertRaises(ActionError):
                build_request("repo_get", "acme/repo", params)
        for action, params in [("issue_get", {"number": "1/comments"}), ("issue_get", {"number": True}), ("issue_get", {"number": 0}), ("issue_get", {"number": 2**31}), ("issue_list", {"per_page": 101}), ("issue_list", {"page": 10001}), ("issue_list", {"state": []}), ("issue_create", {"title": " \t"}), ("issue_create", {"title": "a" * 257}), ("issue_create", {"title": "a\x85b"}), ("issue_comment", {"number": 1, "body": "\n\t"}), ("issue_comment", {"number": 1, "body": "a" * 65537}), ("issue_comment", {"number": 1, "body": "x\0"}), ("pr_create", dict(FIXTURES["pr_create"], draft=1))]:
            with self.subTest(action=action, params=params), self.assertRaises(ActionError):
                build_request(action, "acme/repo", params)
        self.assertEqual(validate_params("issue_get", {"number": 2**31 - 1})["number"], 2**31 - 1)
        validate_params("issue_create", {"title": "a" * 256, "body": "b" * 65536})
        for repo in ["acme/repo/../other", "https://evil", "acme/repo?x=1", "acme/repo#frag", "acme/%2e%2e", "acme/.."]:
            with self.assertRaises(ActionError):
                build_request("repo_get", repo, {})

    def test_legacy_dotted_actions_are_not_aliases(self):
        old_names = ["repo.get", "contents.read", "issues.list", "issues.get", "issues.comments.list", "issues.create", "issues.comment", "pulls.list", "pulls.get", "pulls.comments.list", "pulls.create", "pulls.comment", "branches.create", "pulls.merge"]
        for action in old_names + ["github_app_action", "github_pr_merge", "github_issue_comment"]:
            with self.subTest(action=action), self.assertRaises(ActionError):
                build_request(action, "acme/repo", {})

    def test_renamed_actions_preserve_plural_github_paths(self):
        expected = {
            "repo_get": ("GET", "/repos/acme/repo"),
            "contents_read": ("GET", "/repos/acme/repo/contents/README.md"),
            "issue_list": ("GET", "/repos/acme/repo/issues"),
            "issue_get": ("GET", "/repos/acme/repo/issues/1"),
            "issue_comments_list": ("GET", "/repos/acme/repo/issues/1/comments"),
            "issue_create": ("POST", "/repos/acme/repo/issues"),
            "issue_comment": ("POST", "/repos/acme/repo/issues/1/comments"),
            "pr_list": ("GET", "/repos/acme/repo/pulls"),
            "pr_get": ("GET", "/repos/acme/repo/pulls/2"),
            "pr_comments_list": ("GET", "/repos/acme/repo/issues/2/comments"),
            "pr_create": ("POST", "/repos/acme/repo/pulls"),
            "pr_comment": ("POST", "/repos/acme/repo/issues/2/comments"),
            "branch_create": ("POST", "/repos/acme/repo/git/refs"),
            "pr_review_comment": ("POST", "/repos/acme/repo/pulls/2/comments"),
            "pr_merge": ("PUT", "/repos/acme/repo/pulls/1/merge"),
        }
        self.assertEqual(set(expected), set(ACTIONS))
        for action, target in expected.items():
            with self.subTest(action=action):
                request = build_request(action, "acme/repo", FIXTURES[action])
                self.assertEqual((request.method, request.path), target)


class InlineReviewTests(unittest.TestCase):
    def test_single_and_multiline_request(self):
        for side in ["LEFT", "RIGHT"]:
            for extra in [{}, {"start_line": 2, "start_side": side}]:
                params = dict(FIXTURES["pr_review_comment"], side=side, commit_id=SHA.upper(), **extra)
                request = build_request("pr_review_comment", "acme/repo", params)
                self.assertEqual(request.path, "/repos/acme/repo/pulls/2/comments")
                self.assertEqual(request.body, {k: (SHA if k == "commit_id" else v) for k, v in params.items() if k != "number"})
                self.assertEqual(request.query, {})
        self.assertEqual(ACTIONS["pr_review_comment"].permissions, {"pull_requests": "write"})

    def test_invalid_coordinates_and_unsupported_forms(self):
        cases = [{"line": x} for x in [True, 0, -1, "10", 2**31, None]]
        cases += [{"path": x} for x in ["", " ", "/a", "../a", "a/../b", "a//b", "a/./b", "a\\b", "a\n", "a\0", "a" * 4097]]
        cases += [{"side": x} for x in ["left", "BOTH", [], None]]
        cases += [{"start_line": 2}, {"start_side": "RIGHT"}, {"start_line": 10, "start_side": "RIGHT"}, {"start_line": 11, "start_side": "RIGHT"}, {"start_line": True, "start_side": "RIGHT"}, {"start_line": 2, "start_side": "LEFT"}, {"in_reply_to": 3}, {"subject_type": "file"}, {"position": 4}, {"commit_id": "main"}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ActionError):
                validate_params("pr_review_comment", dict(FIXTURES["pr_review_comment"], **change))
        self.assertEqual(validate_params("pr_review_comment", dict(FIXTURES["pr_review_comment"], line=2**31-1))["line"], 2**31-1)
