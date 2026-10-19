"""Repository selection, access profiles, repository selection and deny-wins exceptions."""
from dataclasses import dataclass
from types import MappingProxyType
from .actions import ACTIONS, READ_ACTIONS, WRITE_ACTIONS, ActionError, canonical_repo


class PolicyError(ValueError):
    pass


def _object(value, allowed, required=frozenset()):
    if not isinstance(value, dict) or value.keys() - allowed or not required <= value.keys():
        raise PolicyError("invalid policy object or unknown fields")
    return value


def _actions(value):
    if not isinstance(value, list) or any(not isinstance(a, str) or a not in ACTIONS for a in value):
        raise PolicyError("actions must be a list of known action names")
    if len(set(value)) != len(value):
        raise PolicyError("duplicate action")
    return frozenset(value)


def _access(value):
    if not isinstance(value, str) or value not in {"read", "write"}:
        raise PolicyError("access must be read or write")
    return value


def _patterns(value):
    if not isinstance(value, list):
        raise PolicyError("repository patterns must be a list")
    result = []
    for pattern in value:
        if not isinstance(pattern, str):
            raise PolicyError("invalid repository pattern")
        try:
            normalized = canonical_repo(pattern[:-1] + "placeholder").split("/")[0] + "/*" if pattern.endswith("/*") else canonical_repo(pattern)
        except ActionError as exc:
            raise PolicyError("invalid repository pattern") from exc
        if normalized in result:
            raise PolicyError("duplicate repository pattern")
        result.append(normalized)
    return tuple(result)


def _matches(repo, patterns):
    return any(repo == p or (p.endswith("/*") and repo.split("/")[0] == p[:-2]) for p in patterns)


@dataclass(frozen=True)
class RepositoryRule:
    access: str
    allow_actions: frozenset
    deny_actions: frozenset


@dataclass(frozen=True)
class Policy:
    mode: str
    allow: tuple
    exclude: tuple
    default_access: str
    allow_actions: frozenset
    deny_actions: frozenset
    repository_rules: object

    @classmethod
    def from_dict(cls, config):
        config = _object(config, {"repositories", "default_access", "allow_actions", "deny_actions", "repository_rules"}, {"repositories", "default_access"})
        repos = _object(config["repositories"], {"mode", "allow", "exclude"}, {"mode", "exclude"})
        mode = repos["mode"]
        if not isinstance(mode, str) or mode not in {"allowlist", "all"}:
            raise PolicyError("repository mode must be allowlist or all")
        allow, exclude = _patterns(repos.get("allow", [])), _patterns(repos["exclude"])
        if mode == "all" and allow:
            raise PolicyError("all mode cannot include allow patterns")
        default_access = _access(config["default_access"])
        raw_rules = config.get("repository_rules", {})
        if not isinstance(raw_rules, dict):
            raise PolicyError("repository_rules must be an object")
        rules = {}
        for repo, rule in raw_rules.items():
            try:
                normalized = canonical_repo(repo)
            except ActionError as exc:
                raise PolicyError("repository_rules require exact repositories") from exc
            if normalized in rules:
                raise PolicyError("duplicate normalized repository rule")
            rule = _object(rule, {"access", "allow_actions", "deny_actions"})
            rules[normalized] = RepositoryRule(_access(rule.get("access", default_access)), _actions(rule.get("allow_actions", [])), _actions(rule.get("deny_actions", [])))
        return cls(mode, allow, exclude, default_access, _actions(config.get("allow_actions", [])), _actions(config.get("deny_actions", [])), MappingProxyType(rules))

    def authorize(self, repo, action):
        try:
            repo = canonical_repo(repo)
        except ActionError as exc:
            raise PolicyError("invalid repository") from exc
        if not isinstance(action, str) or action not in ACTIONS:
            raise PolicyError("unknown action")
        if _matches(repo, self.exclude) or (self.mode == "allowlist" and not _matches(repo, self.allow)):
            raise PolicyError("repository access denied")
        rule = self.repository_rules.get(repo, RepositoryRule(self.default_access, frozenset(), frozenset()))
        baseline = READ_ACTIONS if rule.access == "read" else WRITE_ACTIONS
        effective = (baseline | self.allow_actions | rule.allow_actions) - self.deny_actions - rule.deny_actions
        if action not in effective:
            raise PolicyError("action access denied")
        return repo
