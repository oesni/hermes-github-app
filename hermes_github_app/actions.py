"""Frozen version-one action catalog and strict, credential-free arguments."""
from dataclasses import dataclass
from types import MappingProxyType
import re
import unicodedata
from urllib.parse import quote


class ActionError(ValueError):
    pass


@dataclass(frozen=True)
class ActionSpec:
    permission: str
    access: str
    extra_permissions: tuple = ()

    @property
    def permissions(self):
        return {self.permission: self.access, **dict(self.extra_permissions)}


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: dict
    body: dict | None


ACTIONS = {
    "repo_get": ActionSpec("metadata", "read"),
    "contents_read": ActionSpec("contents", "read"),
    "issue_list": ActionSpec("issues", "read"),
    "issue_get": ActionSpec("issues", "read"),
    "issue_comments_list": ActionSpec("issues", "read"),
    "issue_create": ActionSpec("issues", "write"),
    "issue_comment": ActionSpec("issues", "write"),
    "pr_list": ActionSpec("pull_requests", "read"),
    "pr_get": ActionSpec("pull_requests", "read"),
    "pr_comments_list": ActionSpec("pull_requests", "read"),
    "pr_create": ActionSpec("pull_requests", "write", (("contents", "read"),)),
    "pr_comment": ActionSpec("pull_requests", "write"),
    "branch_create": ActionSpec("contents", "write"),
    "pr_merge": ActionSpec("contents", "write", (("pull_requests", "read"),)),
}
READ_ACTIONS = frozenset({"repo_get", "contents_read", "issue_list", "issue_get", "issue_comments_list", "pr_list", "pr_get", "pr_comments_list"})
WRITE_ACTIONS = READ_ACTIONS | {"issue_create", "issue_comment", "pr_create", "pr_comment", "branch_create"}


def canonical_repo(repo: str) -> str:
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repo):
        raise ActionError("repository must be an explicit owner/repo")
    owner, name = repo.split("/")
    if owner.endswith("-") or name in {".", ".."}:
        raise ActionError("invalid repository name")
    return repo.lower()


def _text(value, name, maximum=65536, blank=False, controls=False):
    if not isinstance(value, str) or (not blank and not value.strip()) or len(value) > maximum:
        raise ActionError(f"invalid {name}")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value) or "\x00" in value:
        raise ActionError(f"invalid {name}")
    if not controls and any(unicodedata.category(c) == "Cc" for c in value):
        raise ActionError(f"invalid {name}")
    return value


def _integer(value, name, maximum=2**31 - 1):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ActionError(f"invalid {name}")
    return value


def valid_sha(value, name="sha"):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
        raise ActionError(f"invalid {name}")
    return value.lower()


def valid_ref(value, name="ref", branch=False):
    value = _text(value, name, maximum=255)
    if len(value.encode("utf-8")) > 255 or value == "HEAD" or value.startswith("refs/"):
        raise ActionError(f"invalid {name}")
    if re.fullmatch(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
        raise ActionError(f"invalid {name}")
    # Git check-ref-format constraints, with short branch/tag names only.
    if value == "@" or ".." in value or "@{" in value or value.endswith(".") or any(c in value for c in " ~^:?*[\\"):
        raise ActionError(f"invalid {name}")
    if branch and value.startswith("-"):
        raise ActionError(f"invalid {name}")
    if any(not part or part.startswith(".") or part.endswith(".lock") for part in value.split("/")):
        raise ActionError(f"invalid {name}")
    return value


_SCHEMAS = {
    "repo_get": (set(), set()),
    "contents_read": ({"path"}, {"ref"}),
    "issue_list": (set(), {"state", "page", "per_page"}),
    "issue_get": ({"number"}, set()),
    "issue_comments_list": ({"number"}, {"page", "per_page"}),
    "issue_create": ({"title"}, {"body"}),
    "issue_comment": ({"number", "body"}, set()),
    "pr_list": (set(), {"state", "page", "per_page"}),
    "pr_get": ({"number"}, set()),
    "pr_comments_list": ({"number"}, {"page", "per_page"}),
    "pr_create": ({"title", "head", "base"}, {"body", "draft"}),
    "pr_comment": ({"number", "body"}, set()),
    "branch_create": ({"branch"}, {"source_branch", "expected_source_sha", "source_commit_sha"}),
    "pr_merge": ({"number", "expected_head_sha", "merge_method"}, set()),
}


PARAMETER_FIELDS = MappingProxyType({
    action: (frozenset(required), frozenset(optional))
    for action, (required, optional) in _SCHEMAS.items()
})

def validate_params(action, params):
    """Return normalized parameters; network preconditions remain host-side."""
    if not isinstance(action, str) or action not in ACTIONS:
        raise ActionError("unknown action")
    if not isinstance(params, dict) or any(not isinstance(k, str) for k in params):
        raise ActionError("params must be an object")
    required, optional = _SCHEMAS[action]
    if not required <= params.keys() or params.keys() - required - optional:
        raise ActionError("missing or unsupported action parameters")
    result = dict(params)
    if "number" in result:
        result["number"] = _integer(result["number"], "number")
    if action.endswith("_list"):
        result["page"] = _integer(result.get("page", 1), "page", 10000)
        result["per_page"] = _integer(result.get("per_page", 30), "per_page", 100)
        if action in {"issue_list", "pr_list"}:
            state = result.get("state", "open")
            if not isinstance(state, str) or state not in {"open", "closed", "all"}:
                raise ActionError("invalid state")
            result["state"] = state
    if action == "contents_read":
        path = _text(result["path"], "path", maximum=2**31, blank=True)
        if path and (path.startswith("/") or "\\" in path or any(p in {"", ".", ".."} for p in path.split("/"))):
            raise ActionError("invalid content path")
        if "ref" in result:
            result["ref"] = valid_ref(result["ref"])
    if action in {"issue_create", "pr_create"}:
        result["title"] = _text(result["title"], "title", maximum=256)
        result["body"] = _text(result.get("body", ""), "body", blank=True, controls=True)
    if action in {"issue_comment", "pr_comment"}:
        result["body"] = _text(result["body"], "body", controls=True)
    if action == "pr_create":
        for name in ("head", "base"):
            result[name] = valid_ref(result[name], name, branch=True)
        draft = result.get("draft", False)
        if type(draft) is not bool:
            raise ActionError("draft must be a boolean")
        result["draft"] = draft
    if action == "branch_create":
        result["branch"] = valid_ref(result["branch"], "branch", branch=True)
        if "source_commit_sha" in result:
            if "source_branch" in result or "expected_source_sha" in result:
                raise ActionError("exactly one branch source form is required")
            result["source_commit_sha"] = valid_sha(result["source_commit_sha"], "source_commit_sha")
        else:
            if not {"source_branch", "expected_source_sha"} <= result.keys():
                raise ActionError("exactly one branch source form is required")
            result["source_branch"] = valid_ref(result["source_branch"], "source_branch", branch=True)
            result["expected_source_sha"] = valid_sha(result["expected_source_sha"], "expected_source_sha")
    if action == "pr_merge":
        result["expected_head_sha"] = valid_sha(result["expected_head_sha"], "expected_head_sha")
        if not isinstance(result["merge_method"], str) or result["merge_method"] not in {"merge", "squash", "rebase"}:
            raise ActionError("invalid merge_method")
    return result


def build_request(action: str, repo: str, params: dict) -> Request:
    repo = canonical_repo(repo)
    p = validate_params(action, params)
    prefix = f"/repos/{repo}"
    if action == "repo_get":
        return Request("GET", prefix, {}, None)
    if action == "contents_read":
        return Request("GET", prefix + "/contents" + ("/" + quote(p["path"], safe="/") if p["path"] else ""), {"ref": p["ref"]} if "ref" in p else {}, None)
    if action == "branch_create":
        return Request("POST", prefix + "/git/refs", {}, {"ref": "refs/heads/" + p["branch"], "sha": p.get("source_commit_sha", p.get("expected_source_sha"))})
    if action == "pr_merge":
        return Request("PUT", prefix + f"/pulls/{p['number']}/merge", {}, {"sha": p["expected_head_sha"], "merge_method": p["merge_method"]})
    resource, operation = action.split("_", 1)
    endpoint = prefix + "/" + {"issue": "issues", "pr": "pulls"}[resource]
    if operation == "list":
        return Request("GET", endpoint, {k: p[k] for k in ("state", "page", "per_page")}, None)
    if operation == "get":
        return Request("GET", endpoint + f"/{p['number']}", {}, None)
    if operation in {"comment", "comments_list"}:
        endpoint = prefix + f"/issues/{p['number']}/comments"
        if operation == "comments_list":
            return Request("GET", endpoint, {k: p[k] for k in ("page", "per_page")}, None)
        return Request("POST", endpoint, {}, {"body": p["body"]})
    return Request("POST", endpoint, {}, p)
