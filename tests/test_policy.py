import unittest
from hermes_github_app.actions import ACTIONS, READ_ACTIONS, WRITE_ACTIONS
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
        self.assertEqual(len(ACTIONS), 14)
        self.assertEqual(len(READ_ACTIONS), 8)
        self.assertEqual(len(WRITE_ACTIONS), 13)
        for access, expected in [("read", READ_ACTIONS), ("write", WRITE_ACTIONS)]:
            p = self.policy(default_access=access)
            for action in ACTIONS:
                if action in expected:
                    self.assertEqual(p.authorize("Acme/Repo", action), "acme/repo")
                else:
                    self.denied(p, "acme/repo", action)
        self.assertEqual(self.policy(allow_actions=["pulls.merge"]).authorize("acme/repo", "pulls.merge"), "acme/repo")

    def test_spec_allowlist_example(self):
        p = self.policy(allow_actions=["issues.comment"], deny_actions=["pulls.merge"], repository_rules={"acme/support": {"access": "write", "allow_actions": ["pulls.merge"]}, "acme/archive": {"access": "read", "deny_actions": ["issues.comment"]}, "acme/inherits": {}})
        for repo, action in [("Acme/Website", "contents.read"), ("acme/website", "issues.comment"), ("ACME/SUPPORT", "branches.create"), ("acme/inherits", "issues.comment")]:
            self.assertEqual(p.authorize(repo, action), repo.lower())
        for repo, action in [("other/demo", "repo.get"), ("acme/secret", "issues.comment"), ("acme/website", "issues.create"), ("acme/support", "pulls.merge"), ("acme/archive", "issues.comment")]:
            self.denied(p, repo, action)

    def test_all_except_and_local_baseline(self):
        p = self.policy(repositories={"mode": "all", "exclude": ["secret-org/*", "acme/frozen"]}, default_access="write", repository_rules={"acme/archive": {"access": "read"}, "acme/support": {"deny_actions": ["branches.create"]}})
        p.authorize("other/demo", "issues.create")
        for repo, action in [("acme/archive", "issues.create"), ("acme/support", "branches.create"), ("acme/frozen", "repo.get"), ("secret-org/demo", "issues.get")]:
            self.denied(p, repo, action)

    def test_read_is_not_ceiling_and_global_denial_wins(self):
        p = self.policy(default_access="write", allow_actions=["issues.comment"], deny_actions=["pulls.merge"], repository_rules={"acme/a": {"access": "read", "allow_actions": ["issues.create", "pulls.merge"]}})
        p.authorize("acme/a", "issues.comment")
        p.authorize("acme/a", "issues.create")
        self.denied(p, "acme/a", "branches.create")
        self.denied(p, "acme/a", "pulls.merge")
        p = self.policy(allow_actions=["issues.comment"], deny_actions=["issues.comment"])
        self.denied(p, "acme/a", "issues.comment")

    def test_inert_rule_cannot_grant_repository_access(self):
        p = self.policy(repository_rules={"other/repo": {"access": "write"}, "acme/secret": {"access": "write"}})
        for repo in ["other/repo", "acme/secret", "acmeevil/repo"]:
            self.denied(p, repo, "repo.get")
        for allow in [[], ["ACME/*"]]:
            p = self.policy(repositories={"mode": "allowlist", "allow": allow, "exclude": ["Acme/*"]}, repository_rules={"acme/a": {"access": "write"}})
            self.denied(p, "ACME/A", "repo.get")
        self.denied(self.policy(repositories={"mode": "allowlist", "exclude": []}), "acme/a", "repo.get")

    def test_invalid_schema_and_types(self):
        for config in [None, {}, {"repositories": {"mode": "all", "exclude": []}}, {"repositories": {"mode": "all"}, "default_access": "read"}]:
            with self.subTest(config=config), self.assertRaises(PolicyError):
                Policy.from_dict(config)
        cases = [("default_actions", []), ("denied_actions", []), ("default_access", None), ("default_access", "none"), ("allow_actions", ["read"]), ("allow_actions", ["contents.write"]), ("deny_actions", ["repo.get", "repo.get"]), ("repository_rules", {"acme/a": []}), ("repository_rules", {"acme/a": {"unknown": []}}), ("repository_rules", {"acme/*": {}}), ("repository_rules", {"Acme/a": {}, "acme/a": {}})]
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
        config = {"repositories": {"mode": "allowlist", "allow": ["acme/repo.git"], "exclude": []}, "default_access": "read", "repository_rules": {"acme/repo.git": {"deny_actions": ["repo.get"]}}}
        p = Policy.from_dict(config)
        config["repository_rules"]["acme/repo.git"]["deny_actions"].clear()
        self.denied(p, "acme/repo.git", "repo.get")
        self.denied(p, "acme/repo", "contents.read")
        p.authorize("acme/repo.git", "contents.read")
        with self.assertRaises(TypeError):
            p.repository_rules["acme/repo.git"] = None
