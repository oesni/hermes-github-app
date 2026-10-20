import unittest
from hermes_github_app.actions import ACTIONS, ActionError, build_request, validate_params, valid_ref, valid_sha


SHA = "a" * 40
FIXTURES = {"repo_get": {}, "contents_read": {"path": "README.md"}, "issue_list": {}, "issue_get": {"number": 1}, "issue_comments_list": {"number": 1}, "issue_create": {"title": "Report"}, "issue_comment": {"number": 1, "body": "Hello"}, "pr_list": {}, "pr_get": {"number": 2}, "pr_comments_list": {"number": 2}, "pr_create": {"title": "Change", "head": "feature/a", "base": "main"}, "pr_comment": {"number": 2, "body": "Review"}, "branch_create": {"branch": "new", "source_commit_sha": SHA}, "pr_merge": {"number": 1, "expected_head_sha": SHA, "merge_method": "squash"}}


FIXTURES["pr_update_body"] = {"number": 2, "body": "Updated"}
for action in ("issue_comment_get", "issue_comment_reaction", "pr_review_comment_get", "pr_review_comment_reaction"):
    FIXTURES[action] = {"comment_id": 3}
FIXTURES["issue_labels_add"] = {"number": 1, "labels": ["bug"]}
FIXTURES["issue_label_remove"] = {"number": 1, "label": "bug"}
FIXTURES["pr_review_comment"] = {"number": 2, "body": "Review", "commit_id": SHA, "path": "src/main.py", "line": 10, "side": "RIGHT"}


class ActionsTests(unittest.TestCase):
    def test_closed_catalog_and_transport_overrides(self):
        self.assertEqual(set(FIXTURES), set(ACTIONS) - {"git_push"})
        for action, params in FIXTURES.items():
            r = build_request(action, "Acme/Repo", params)
            self.assertTrue(r.path.startswith("/repos/acme/repo"))
            self.assertIn(r.method, {"GET", "POST", "PUT", "DELETE", "PATCH"})
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
            "pr_update_body": ("PATCH", "/repos/acme/repo/pulls/2"),
            "issue_comment_get": ("GET", "/repos/acme/repo/issues/comments/3"),
            "issue_comment_reaction": ("POST", "/repos/acme/repo/issues/comments/3/reactions"),
            "pr_review_comment_get": ("GET", "/repos/acme/repo/pulls/comments/3"),
            "pr_review_comment_reaction": ("POST", "/repos/acme/repo/pulls/comments/3/reactions"),
            "issue_labels_add": ("POST", "/repos/acme/repo/issues/1/labels"),
            "issue_label_remove": ("DELETE", "/repos/acme/repo/issues/1/labels/bug"),
            "pr_review_comment": ("POST", "/repos/acme/repo/pulls/2/comments"),
            "pr_merge": ("PUT", "/repos/acme/repo/pulls/1/merge"),
        }
        self.assertEqual(set(expected), set(ACTIONS) - {"git_push"})
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


class LabelActionTests(unittest.TestCase):
    def test_label_routes_and_literal_encoding(self):
        label = '분류 /a?#%2E'
        add = build_request('issue_labels_add', 'Acme/Repo', {'number': 3, 'labels': [label]})
        self.assertEqual(add.body, {'labels': [label]})
        remove = build_request('issue_label_remove', 'acme/repo', {'number': 3, 'label': label})
        self.assertEqual(remove.method, 'DELETE')
        self.assertEqual(remove.path, '/repos/acme/repo/issues/3/labels/%EB%B6%84%EB%A5%98%20%2Fa%3F%23%252E')
        self.assertIsNone(remove.body)
        for action in ('issue_labels_add', 'issue_label_remove'):
            self.assertEqual(ACTIONS[action].permissions, {'issues': 'write'})

    def test_invalid_names_and_collections(self):
        invalid = ['', ' ', '.', '..', 'x'*51, '\x00', '\n', '\ud800', None, 12, True]
        for label in invalid:
            for action, field in [('issue_labels_add', 'labels'), ('issue_label_remove', 'label')]:
                with self.subTest(action=action, label=repr(label)), self.assertRaises(ActionError):
                    validate_params(action, {'number': 1, field: [label] if field == 'labels' else label})
        for labels in [[], ['a']*101, ['Bug','bug'], 'bug', {'bug':True}, None, ['ß','ss']]:
            with self.subTest(labels=labels), self.assertRaises(ActionError):
                validate_params('issue_labels_add', {'number':1,'labels':labels})
        self.assertEqual(validate_params('issue_labels_add', {'number':1,'labels':['x'*50,'표시 😀']})['labels'], ['x'*50,'표시 😀'])
        for number in (True, '1', 0, -1, 2**31):
            with self.assertRaises(ActionError):
                validate_params('issue_label_remove', {'number':number,'label':'bug'})


class PrBodyActionTests(unittest.TestCase):
    def test_closed_body_only_schema_and_bounds(self):
        self.assertEqual(ACTIONS['pr_update_body'].permissions, {'pull_requests':'write'})
        for body in ('',' \t\n','text','😀'*65536):
            request=build_request('pr_update_body','Acme/Repo',{'number':1,'body':body})
            self.assertEqual((request.method,request.path),('PATCH','/repos/acme/repo/pulls/1'))
            self.assertEqual(request.body,{'body':body})
        for change in ({'body':None},{'body':False},{'body':1},{'body':'x'*65537},
                       {'body':'x\x00'},{'body':'\ud800'},{'title':'x'},{'state':'closed'},
                       {'base':'main'},{'maintainer_can_modify':True},{'number':True},{'number':'1'}):
            with self.subTest(change=repr(change)), self.assertRaises(ActionError):
                validate_params('pr_update_body', {'number':1,'body':'edited',**change})
