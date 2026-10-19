import unittest
from hermes_github_app.actions import ACTIONS, ActionError, build_request, validate_params, valid_ref, valid_sha


SHA = "a" * 40
FIXTURES = {"repo.get": {}, "contents.read": {"path": "README.md"}, "issues.list": {}, "issues.get": {"number": 1}, "issues.comments.list": {"number": 1}, "issues.create": {"title": "Report"}, "issues.comment": {"number": 1, "body": "Hello"}, "pulls.list": {}, "pulls.get": {"number": 2}, "pulls.comments.list": {"number": 2}, "pulls.create": {"title": "Change", "head": "feature/a", "base": "main"}, "pulls.comment": {"number": 2, "body": "Review"}, "branches.create": {"branch": "new", "source_commit_sha": SHA}, "pulls.merge": {"number": 1, "expected_head_sha": SHA, "merge_method": "squash"}}


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
        self.assertEqual(validate_params("issues.list", {}), {"state": "open", "page": 1, "per_page": 30})
        self.assertEqual(validate_params("issues.create", {"title": "a"}), {"title": "a", "body": ""})
        self.assertFalse(validate_params("pulls.create", FIXTURES["pulls.create"])["draft"])
        for action in ["issues.comments.list", "pulls.comments.list"]:
            r = build_request(action, "acme/repo", {"number": 2})
            self.assertEqual(r.path, "/repos/acme/repo/issues/2/comments")
            self.assertEqual(r.query, {"page": 1, "per_page": 30})
        r = build_request("pulls.comment", "acme/repo", {"number": 2, "body": "a\nb\tc"})
        self.assertEqual(r.body, {"body": "a\nb\tc"})

    def test_contents_safe_path_and_no_revision_expressions(self):
        r = build_request("contents.read", "acme/repo", {"path": "dir/a?#%.txt", "ref": "feature/x"})
        self.assertEqual(r.path, "/repos/acme/repo/contents/dir/a%3F%23%25.txt")
        self.assertEqual(r.query, {"ref": "feature/x"})
        self.assertEqual(build_request("contents.read", "acme/repo", {"path": ""}).path, "/repos/acme/repo/contents")
        for path in ["/etc/passwd", "../secret", "a/../b", "a//b", "a/./b", "a\\b", "a\nheader", chr(0xD800)]:
            with self.subTest(path=path), self.assertRaises(ActionError):
                build_request("contents.read", "acme/repo", {"path": path})
        r = build_request("contents.read", "acme/repo", {"path": "%2e%2e/%2fsecret"})
        self.assertEqual(r.path, "/repos/acme/repo/contents/%252e%252e/%252fsecret")

    def test_git_branch_and_ref_names(self):
        for name in ["main", "feature/a", "é" * 127, "v1.2", "release-1"]:
            self.assertEqual(valid_ref(name, branch=True), name)
        for name in ["HEAD", "refs/heads/main", SHA, "a" * 64, "main~1", "main^", "a..b", "a b", "a:b", "http://host/x", "a\\b", "a?b", "a*b", "a[b", ".a", "a/.b", "a.lock", "a/b.lock", "a/", "a//b", "@", "a@{1}", "a.", "é" * 128, "-branch"]:
            with self.subTest(name=name), self.assertRaises(ActionError):
                valid_ref(name, branch=True)
        for name in ["main~1", SHA, "a" * 64, "a:b"]:
            with self.assertRaises(ActionError):
                build_request("contents.read", "acme/repo", {"path": "", "ref": name})
        for field in ["head", "base"]:
            with self.assertRaises(ActionError):
                build_request("pulls.create", "acme/repo", dict(FIXTURES["pulls.create"], **{field: "owner:branch"}))

    def test_branch_source_forms_and_sha_normalization(self):
        for length in [40, 64]:
            self.assertEqual(valid_sha("A" * length), "a" * length)
        for value in ["a" * 39, "a" * 41, "g" * 40, "main", True, None]:
            with self.assertRaises(ActionError):
                valid_sha(value)
        r = build_request("branches.create", "acme/repo", {"branch": "new", "source_branch": "main", "expected_source_sha": SHA.upper()})
        self.assertEqual(r.body, {"ref": "refs/heads/new", "sha": SHA})
        for params in [{"branch": "new"}, {"branch": "new", "source_branch": "main"}, {"branch": "new", "expected_source_sha": SHA}, {"branch": "new", "source_commit_sha": SHA, "source_branch": "main"}, {"branch": "new", "source_commit_sha": SHA, "expected_source_sha": SHA}]:
            with self.subTest(params=params), self.assertRaises(ActionError):
                validate_params("branches.create", params)

    def test_merge_has_explicit_method_and_head(self):
        r = build_request("pulls.merge", "acme/repo", FIXTURES["pulls.merge"])
        self.assertEqual((r.method, r.path), ("PUT", "/repos/acme/repo/pulls/1/merge"))
        self.assertEqual(r.body, {"sha": SHA, "merge_method": "squash"})
        self.assertEqual(ACTIONS["pulls.merge"].permissions, {"contents": "write", "pull_requests": "read"})
        for method in [None, "", "auto", "SQUASH", []]:
            with self.assertRaises(ActionError):
                validate_params("pulls.merge", dict(FIXTURES["pulls.merge"], merge_method=method))
        with self.assertRaises(ActionError):
            validate_params("pulls.merge", {"number": 1, "expected_head_sha": SHA})

    def test_text_numbers_types_and_bounds(self):
        for params in [None, [], "", {1: "x"}]:
            with self.assertRaises(ActionError):
                build_request("repo.get", "acme/repo", params)
        for action, params in [("issues.get", {"number": "1/comments"}), ("issues.get", {"number": True}), ("issues.get", {"number": 0}), ("issues.get", {"number": 2**31}), ("issues.list", {"per_page": 101}), ("issues.list", {"page": 10001}), ("issues.list", {"state": []}), ("issues.create", {"title": " \t"}), ("issues.create", {"title": "a" * 257}), ("issues.create", {"title": "a\x85b"}), ("issues.comment", {"number": 1, "body": "\n\t"}), ("issues.comment", {"number": 1, "body": "a" * 65537}), ("issues.comment", {"number": 1, "body": "x\0"}), ("pulls.create", dict(FIXTURES["pulls.create"], draft=1))]:
            with self.subTest(action=action, params=params), self.assertRaises(ActionError):
                build_request(action, "acme/repo", params)
        self.assertEqual(validate_params("issues.get", {"number": 2**31 - 1})["number"], 2**31 - 1)
        validate_params("issues.create", {"title": "a" * 256, "body": "b" * 65536})
        for repo in ["acme/repo/../other", "https://evil", "acme/repo?x=1", "acme/repo#frag", "acme/%2e%2e", "acme/.."]:
            with self.assertRaises(ActionError):
                build_request("repo.get", repo, {})
