import unittest
from pathlib import Path
import re
from hermes_github_app.policy import PolicyError
from hermes_github_app.config import parse_config, ConfigError


BASE = '''version: 1
auth:
  app_id: 12345
  installation_id: 67890
  private_key_path: /srv/hermes-private/github-app.pem
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
        self.assertEqual(cfg.merge_approval.approvers, ())
        self.assertEqual(cfg.policy.authorize("acme/a", "repo.get"), "acme/a")
        explicit = parse_config(BASE + "  allow_actions: []\n  deny_actions: []\n  repository_rules: {}\nmerge_approval: {approvers: []}\n")
        self.assertEqual(cfg, explicit)

    def test_yaml_12_strings_not_yaml_11_booleans(self):
        cfg = parse_config(BASE.replace("/srv/hermes-private/github-app.pem", "/yes/on") + "  repository_rules: {yes/on: {}}\n")
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
        for value in ['"1"', "true", "2"]:
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
                parse_config(BASE.replace("/srv/hermes-private/github-app.pem", path))
        cfg = parse_config(BASE.replace("/srv/hermes-private/github-app.pem", "/$HOME/$(command)/key"))
        self.assertEqual(cfg.auth.private_key_path, "/$HOME/$(command)/key")
        with self.assertRaises(ConfigError):
            parse_config(b"\xff")

    def test_approver_bounds_types_and_duplicates(self):
        prefix = BASE + "merge_approval:\n  approvers:\n"
        for value in ['"1"', '"18446744073709551615"']:
            cfg = parse_config(prefix + f"    - {{platform: discord, user_id: {value}}}\n")
            self.assertEqual(cfg.merge_approval.approvers[0].platform, "discord")
        for value in ['1', '"0"', '"01"', '"+1"', '"name"', '"18446744073709551616"', 'null']:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_config(prefix + f"    - {{platform: discord, user_id: {value}}}\n")
        for block in ['    - {platform: local, user_id: "1"}\n', '    - {platform: discord, user_id: "1", bot: false}\n', '    - {platform: discord}\n', '    - {platform: discord, user_id: "1"}\n    - {platform: discord, user_id: "1"}\n']:
            with self.assertRaises(ConfigError):
                parse_config(prefix + block)

    def test_no_secret_value_in_diagnostics(self):
        for case in [BASE + 'secret: "sensitive-secret"\n', BASE.replace("app_id: 12345", 'app_id: "sensitive-secret"'), BASE + 'bad: ["sensitive-secret"\n']:
            with self.assertRaises(ConfigError) as caught:
                parse_config(case)
            self.assertNotIn("sensitive-secret", str(caught.exception))

    def test_unknown_nested_keys_null_and_old_schema_rejected(self):
        cases = [BASE + 'merge_approval: {wrong: []}\n', BASE.replace("  app_id: 12345", "  app_id: 12345\n  token: forbidden"), BASE.replace("  default_access: read", "  default_actions: [repo.get]"), BASE + '  repository_rules: {acme/a: {access: null}}\n', BASE.replace("    exclude: []", "    exclude: []\n    typo: []")]
        for case in cases:
            with self.assertRaises(ConfigError):
                parse_config(case)

    def test_documented_examples_and_policy_decision_table(self):
        spec = (Path(__file__).resolve().parents[1] / "docs/spec/github-app-configuration.md").read_text()
        blocks = re.findall(r"    ```yaml\n(.*?)    ```", spec, flags=re.S)
        configs = [parse_config("\n".join(line[4:] for line in block.splitlines())) for block in blocks[:2]]
        decisions = [
            (0, "Acme/Website", "contents.read", True),
            (0, "other/demo", "repo.get", False),
            (0, "acme/payroll", "issues.comment", False),
            (0, "acme/website", "issues.comment", True),
            (0, "acme/website", "issues.create", False),
            (0, "ACME/SUPPORT", "branches.create", True),
            (0, "acme/support", "pulls.merge", False),
            (0, "acme/archive", "issues.comment", False),
            (0, "acme/inherits", "issues.comment", True),
            (1, "other/demo", "issues.create", True),
            (1, "acme/archive", "issues.create", False),
            (1, "acme/support", "branches.create", False),
            (1, "acme/frozen", "repo.get", False),
            (1, "secret-org/demo", "issues.get", False),
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
            cfg.policy.authorize("acme/support", "issues.comment")
        # Decision 16 grants merge capability, but has no authorized approvers.
        cfg = parse_config(BASE + "  repository_rules: {acme/support: {allow_actions: [pulls.merge]}}\n")
        cfg.policy.authorize("acme/support", "pulls.merge")
        self.assertEqual(cfg.merge_approval.approvers, ())
