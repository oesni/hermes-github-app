import unittest
from pathlib import Path
import re
from hermes_github_app.policy import PolicyError
from hermes_github_app.config import parse_config, ConfigError


BASE = '''version: 1
auth:
  app_id: 12345
  installation_id: 67890
  private_key_path: /secure/github-app/private-key.pem
policy:
  repositories:
    mode: all
    exclude: []
  default_access: read
'''


class ConfigTests(unittest.TestCase):
    def test_valid_snapshot_and_defaults(self):
        cfg = parse_config(BASE.encode())
        self.assertEqual(cfg.version, 1)
        self.assertEqual(cfg.auth.app_id, 12345)
        self.assertEqual(cfg.policy.authorize("acme/a", "repo_get"), "acme/a")
        explicit = parse_config(BASE + "  allow_actions: []\n  deny_actions: []\n  repository_rules: {}\n")
        self.assertEqual(cfg, explicit)

    def test_yaml_12_strings_not_yaml_11_booleans(self):
        cfg = parse_config(BASE.replace("/secure/github-app/private-key.pem", "/yes/on") + "  repository_rules: {yes/on: {}}\n")
        self.assertIn("yes/on", cfg.policy.repository_rules)
        parse_config("%YAML 1.2\n---\n" + BASE)
        with self.assertRaises(ConfigError):
            parse_config("%YAML 1.1\n---\n" + BASE)

    def test_lexically_strict_integer_fields(self):
        for value in ['"1"', "true", "false", "null", "0", "01", "+1", "-1", "1_0", "0x10", "0o10", "1.0", "1e2", str(2**63)]:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_config(BASE.replace("app_id: 12345", "app_id: " + value))
        cfg = parse_config(BASE.replace("app_id: 12345", "app_id: " + str(2**63 - 1)))
        self.assertEqual(cfg.auth.app_id, 2**63 - 1)
        for value in ['"1"', "true", "3"]:
            with self.assertRaises(ConfigError):
                parse_config(BASE.replace("version: 1", "version: " + value))

    def test_reject_ambiguous_or_executable_yaml(self):
        cases = ["", "[]", "null", BASE + "---\n" + BASE, BASE + "version: 1\n", BASE.replace("  app_id: 12345", "  app_id: 12345\n  app_id: 12345"), BASE.replace("version: 1", "version: &v 1"), BASE.replace("version: 1", "version: *v"), BASE.replace("version: 1", "version: !!int 1"), BASE + '<<: {}\n', BASE + '"<<": {}\n', BASE + '? [complex, key]\n: value\n', BASE + '1: value\n', BASE + 'true: value\n', BASE + 'extra: null\n', BASE + 'extra: !!python/object:secret {}\n']
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ConfigError):
                parse_config(case)

    def test_invalid_paths_and_no_interpolation(self):
        for path in ["relative/key", "~/key", "''", '"/secret\\0key"']:
            with self.subTest(path=path), self.assertRaises(ConfigError):
                parse_config(BASE.replace("/secure/github-app/private-key.pem", path))
        cfg = parse_config(BASE.replace("/secure/github-app/private-key.pem", "/$HOME/$(command)/key"))
        self.assertEqual(cfg.auth.private_key_path, "/$HOME/$(command)/key")
        with self.assertRaises(ConfigError):
            parse_config(b"\xff")

    def test_removed_approval_configuration_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config(BASE + 'merge_approval: {approvers: []}\n')

    def test_no_secret_value_in_diagnostics(self):
        for case in [BASE + 'secret: "sensitive-secret"\n', BASE.replace("app_id: 12345", 'app_id: "sensitive-secret"'), BASE + 'bad: ["sensitive-secret"\n']:
            with self.assertRaises(ConfigError) as caught:
                parse_config(case)
            self.assertNotIn("sensitive-secret", str(caught.exception))

    def test_unknown_nested_keys_null_and_old_schema_rejected(self):
        cases = [BASE + 'merge_approval: {wrong: []}\n', BASE.replace("  app_id: 12345", "  app_id: 12345\n  token: forbidden"), BASE.replace("  default_access: read", "  default_actions: [repo_get]"), BASE + '  repository_rules: {acme/a: {access: null}}\n', BASE.replace("    exclude: []", "    exclude: []\n    typo: []")]
        for case in cases:
            with self.assertRaises(ConfigError):
                parse_config(case)

    def test_documented_examples_and_policy_decision_table(self):
        spec = (Path(__file__).resolve().parents[1] / "docs/spec/github-app-configuration.md").read_text()
        blocks = re.findall(r"    ```yaml\n(.*?)    ```", spec, flags=re.S)
        configs = [parse_config("\n".join(line[4:] for line in block.splitlines())) for block in blocks[:2]]
        decisions = [
            (0, "Acme/Website", "contents_read", True),
            (0, "other/demo", "repo_get", False),
            (0, "acme/payroll", "issue_comment", False),
            (0, "acme/website", "issue_comment", True),
            (0, "acme/website", "issue_create", False),
            (0, "ACME/SUPPORT", "branch_create", True),
            (0, "acme/support", "pr_merge", False),
            (0, "acme/archive", "issue_comment", False),
            (0, "acme/inherits", "issue_comment", True),
            (1, "other/demo", "issue_create", True),
            (1, "acme/archive", "issue_create", False),
            (1, "acme/support", "branch_create", False),
            (1, "acme/frozen", "repo_get", False),
            (1, "secret-org/demo", "issue_get", False),
        ]
        for example, repo, action, expected in decisions:
            with self.subTest(example=example, repo=repo, action=action):
                if expected:
                    self.assertEqual(configs[example].policy.authorize(repo, action), repo.lower())
                else:
                    with self.assertRaises(PolicyError):
                        configs[example].policy.authorize(repo, action)
        # Decision 15 reaches the client: the policy grants the action, and the
        # client's issue/PR distinction must refuse an issue action on a PR.
        for cfg in configs:
            cfg.policy.authorize("acme/support", "issue_comment")
        # Decision 16 grants merge through the same action policy.
        cfg = parse_config(BASE + "  repository_rules: {acme/support: {allow_actions: [pr_merge]}}\n")
        cfg.policy.authorize("acme/support", "pr_merge")

    def test_public_tool_names_and_unknown_actions_are_not_config_actions(self):
        from hermes_github_app.actions import ACTIONS
        for action in [*('github_' + name for name in ACTIONS), 'unknown_action']:
            for field in ['allow_actions', 'deny_actions']:
                for block in [f'  {field}: [{action}]\n', f'  repository_rules: {{acme/a: {{{field}: [{action}]}}}}\n']:
                    with self.subTest(action=action, field=field, block=block), self.assertRaises(ConfigError):
                        parse_config(BASE + block)

    def test_legacy_dotted_actions_rejected_in_every_exception_list(self):
        old_names = ["repo.get", "contents.read", "issues.list", "issues.get", "issues.comments.list", "issues.create", "issues.comment", "pulls.list", "pulls.get", "pulls.comments.list", "pulls.create", "pulls.comment", "branches.create", "pulls.merge"]
        for action in old_names:
            for field in ["allow_actions", "deny_actions"]:
                for block in [f"  {field}: [{action}]\n", f"  repository_rules: {{acme/a: {{{field}: [{action}]}}}}\n"]:
                    with self.subTest(action=action, field=field, block=block), self.assertRaises(ConfigError):
                        parse_config(BASE + block)


class InlineCommentConfigTests(unittest.TestCase):
    def test_version_one_inline_comment_requires_explicit_allow(self):
        parsed = parse_config(BASE + "  allow_actions: [pr_review_comment]\n")
        self.assertEqual(parsed.version, 1)
        parsed.policy.authorize("acme/repo", "pr_review_comment")
        with self.assertRaises(PolicyError):
            parse_config(BASE).policy.authorize("acme/repo", "pr_review_comment")
        for version in ["2", "3", "true", '\"1\"']:
            with self.subTest(version=version), self.assertRaises(ConfigError):
                parse_config(BASE.replace("version: 1", "version: " + version))

    def test_inline_review_example_is_scoped_and_cannot_merge(self):
        path = Path(__file__).resolve().parents[1] / "examples/inline-review.yaml"
        config = parse_config(path.read_bytes())
        self.assertEqual(config.version, 1)
        self.assertEqual(config.policy.authorize("Acme/Demo", "pr_review_comment"), "acme/demo")
        for repo, action in [("acme/other", "pr_review_comment"), ("acme/demo", "pr_merge"), ("acme/demo", "issue_create")]:
            with self.subTest(repo=repo, action=action), self.assertRaises(PolicyError):
                config.policy.authorize(repo, action)


class LabelConfigTests(unittest.TestCase):
    def test_explicit_label_example_and_frozen_profiles(self):
        config=parse_config((Path(__file__).resolve().parents[1]/'examples/issue-labels.yaml').read_bytes())
        self.assertEqual(config.version,1)
        for action in ('issue_labels_add','issue_label_remove'):
            self.assertEqual(config.policy.authorize('Acme/Support',action),'acme/support')
            for repo in ('acme/other','other/support'):
                with self.assertRaises(PolicyError):config.policy.authorize(repo,action)
            with self.assertRaises(PolicyError):parse_config(BASE).policy.authorize('acme/repo',action)
        for action in ('pr_merge','issue_create'):
            with self.assertRaises(PolicyError):config.policy.authorize('acme/support',action)
