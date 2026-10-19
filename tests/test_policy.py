import unittest
from hermes_github_app.actions import ACTIONS, ACTIONS_BY_VERSION, READ_ACTIONS, WRITE_ACTIONS
from hermes_github_app.policy import Policy, PolicyError


class PolicyTests(unittest.TestCase):
    def policy(self, **changes):
        config = {"repositories": {"mode": "allowlist", "allow": ["Acme/*"], "exclude": ["acme/secret"]}, "default_access": "read"}
        config.update(changes)
        return Policy.from_dict(config)

    def denied(self, policy, repo, action):
        with self.assertRaises(PolicyError):
            policy.authorize(repo, action)

    def test_frozen_profiles_and_explicit_merge(self):
        self.assertEqual(len(ACTIONS_BY_VERSION[1]), 14)
        self.assertEqual(len(ACTIONS_BY_VERSION[2]), 15)
        self.assertEqual(len(READ_ACTIONS), 8)
        self.assertEqual(len(WRITE_ACTIONS), 13)
        for access, expected in [("read", READ_ACTIONS), ("write", WRITE_ACTIONS)]:
            p = self.policy(default_access=access)
            for action in ACTIONS:
                if action in expected:
                    self.assertEqual(p.authorize("Acme/Repo", action), "acme/repo")
                else:
                    self.denied(p, "acme/repo", action)
        self.assertEqual(self.policy(allow_actions=["pr_merge"]).authorize("acme/repo", "pr_merge"), "acme/repo")

    def test_spec_allowlist_example(self):
        p = self.policy(allow_actions=["issue_comment"], deny_actions=["pr_merge"], repository_rules={"acme/support": {"access": "write", "allow_actions": ["pr_merge"]}, "acme/archive": {"access": "read", "deny_actions": ["issue_comment"]}, "acme/inherits": {}})
        for repo, action in [("Acme/Website", "contents_read"), ("acme/website", "issue_comment"), ("ACME/SUPPORT", "branch_create"), ("acme/inherits", "issue_comment")]:
            self.assertEqual(p.authorize(repo, action), repo.lower())
        for repo, action in [("other/demo", "repo_get"), ("acme/secret", "issue_comment"), ("acme/website", "issue_create"), ("acme/support", "pr_merge"), ("acme/archive", "issue_comment")]:
            self.denied(p, repo, action)

    def test_all_except_and_local_baseline(self):
        p = self.policy(repositories={"mode": "all", "exclude": ["secret-org/*", "acme/frozen"]}, default_access="write", repository_rules={"acme/archive": {"access": "read"}, "acme/support": {"deny_actions": ["branch_create"]}})
        p.authorize("other/demo", "issue_create")
        for repo, action in [("acme/archive", "issue_create"), ("acme/support", "branch_create"), ("acme/frozen", "repo_get"), ("secret-org/demo", "issue_get")]:
            self.denied(p, repo, action)

    def test_read_is_not_ceiling_and_global_denial_wins(self):
        p = self.policy(default_access="write", allow_actions=["issue_comment"], deny_actions=["pr_merge"], repository_rules={"acme/a": {"access": "read", "allow_actions": ["issue_create", "pr_merge"]}})
        p.authorize("acme/a", "issue_comment")
        p.authorize("acme/a", "issue_create")
        self.denied(p, "acme/a", "branch_create")
        self.denied(p, "acme/a", "pr_merge")
        p = self.policy(allow_actions=["issue_comment"], deny_actions=["issue_comment"])
        self.denied(p, "acme/a", "issue_comment")

    def test_inert_rule_cannot_grant_repository_access(self):
        p = self.policy(repository_rules={"other/repo": {"access": "write"}, "acme/secret": {"access": "write"}})
        for repo in ["other/repo", "acme/secret", "acmeevil/repo"]:
            self.denied(p, repo, "repo_get")
        for allow in [[], ["ACME/*"]]:
            p = self.policy(repositories={"mode": "allowlist", "allow": allow, "exclude": ["Acme/*"]}, repository_rules={"acme/a": {"access": "write"}})
            self.denied(p, "ACME/A", "repo_get")
        self.denied(self.policy(repositories={"mode": "allowlist", "exclude": []}), "acme/a", "repo_get")

    def test_invalid_schema_and_types(self):
        for config in [None, {}, {"repositories": {"mode": "all", "exclude": []}}, {"repositories": {"mode": "all"}, "default_access": "read"}]:
            with self.subTest(config=config), self.assertRaises(PolicyError):
                Policy.from_dict(config)
        cases = [("default_actions", []), ("denied_actions", []), ("default_access", None), ("default_access", "none"), ("allow_actions", ["read"]), ("allow_actions", ["contents_write"]), ("deny_actions", ["repo_get", "repo_get"]), ("repository_rules", {"acme/a": []}), ("repository_rules", {"acme/a": {"unknown": []}}), ("repository_rules", {"acme/*": {}}), ("repository_rules", {"Acme/a": {}, "acme/a": {}})]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(PolicyError):
                self.policy(**{key: value})
        for repos in [{"mode": "all", "allow": ["acme/*"], "exclude": []}, {"mode": "allowlist", "allow": ["acme/*", "ACME/*"], "exclude": []}, {"mode": "all", "exclude": None}, {"mode": [], "exclude": []}]:
            with self.subTest(repos=repos), self.assertRaises(PolicyError):
                self.policy(repositories=repos)
        for selector in ["*", "*/*", "owner/repo-*", "acme/repo?x", "acme/..", "-acme/*", "acme-/*", "acme_user/*"]:
            with self.subTest(selector=selector), self.assertRaises(PolicyError):
                self.policy(repositories={"mode": "allowlist", "allow": [selector], "exclude": []})

    def test_snapshot_immutable_and_literal_git_suffix(self):
        config = {"repositories": {"mode": "allowlist", "allow": ["acme/repo.git"], "exclude": []}, "default_access": "read", "repository_rules": {"acme/repo.git": {"deny_actions": ["repo_get"]}}}
        p = Policy.from_dict(config)
        config["repository_rules"]["acme/repo.git"]["deny_actions"].clear()
        self.denied(p, "acme/repo.git", "repo_get")
        self.denied(p, "acme/repo", "contents_read")
        p.authorize("acme/repo.git", "contents_read")
        with self.assertRaises(TypeError):
            p.repository_rules["acme/repo.git"] = None


class CatalogVersionTests(unittest.TestCase):
    def test_versioned_explicit_allow_and_deny(self):
        base = {"repositories": {"mode": "all", "exclude": ["acme/private"]}, "default_access": "write"}
        for version in [1, 2]:
            with self.assertRaises(PolicyError):
                Policy.from_dict(base, version=version).authorize("acme/repo", "pr_review_comment")
        for field in ["allow_actions", "deny_actions"]:
            with self.assertRaises(PolicyError):
                Policy.from_dict(dict(base, **{field: ["pr_review_comment"]}))
            with self.assertRaises(PolicyError):
                Policy.from_dict(dict(base, repository_rules={"acme/repo": {field: ["pr_review_comment"]}}))
        granted = dict(base, allow_actions=["pr_review_comment"])
        self.assertEqual(Policy.from_dict(granted, version=2).authorize("acme/repo", "pr_review_comment"), "acme/repo")
        local = dict(base, repository_rules={"acme/repo": {"access": "read", "allow_actions": ["pr_review_comment"]}})
        Policy.from_dict(local, version=2).authorize("acme/repo", "pr_review_comment")
        for cfg, repo in [(dict(granted, deny_actions=["pr_review_comment"]), "acme/repo"), (dict(granted, repository_rules={"acme/repo": {"deny_actions": ["pr_review_comment"]}}), "acme/repo"), (granted, "acme/private")]:
            with self.assertRaises(PolicyError):
                Policy.from_dict(cfg, version=2).authorize(repo, "pr_review_comment")

    def test_invalid_versions_and_constructed_v1_policy(self):
        from dataclasses import replace
        cfg = {"repositories": {"mode": "all", "exclude": []}, "default_access": "read", "allow_actions": ["pr_review_comment"]}
        valid = Policy.from_dict(cfg, version=2)
        for version in [1, True, False, 0, 3, "2", None, []]:
            with self.assertRaises(PolicyError):
                replace(valid, version=version).authorize("acme/repo", "pr_review_comment")
        for version in [True, False, 0, 3, "2", None, []]:
            with self.assertRaises(PolicyError):
                Policy.from_dict(cfg, version=version)
