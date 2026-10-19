"""Frozen version-one action catalog and strict, credential-free arguments."""
from dataclasses import dataclass
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
    "repo.get": ActionSpec("metadata", "read"),
    "contents.read": ActionSpec("contents", "read"),
    "issues.list": ActionSpec("issues", "read"),
    "issues.get": ActionSpec("issues", "read"),
    "issues.comments.list": ActionSpec("issues", "read"),
    "issues.create": ActionSpec("issues", "write"),
    "issues.comment": ActionSpec("issues", "write"),
    "pulls.list": ActionSpec("pull_requests", "read"),
    "pulls.get": ActionSpec("pull_requests", "read"),
    "pulls.comments.list": ActionSpec("pull_requests", "read"),
    "pulls.create": ActionSpec("pull_requests", "write", (("contents", "read"),)),
    "pulls.comment": ActionSpec("pull_requests", "write"),
    "branches.create": ActionSpec("contents", "write"),
    "pulls.merge": ActionSpec("contents", "write", (("pull_requests", "read"),)),
}
READ_ACTIONS = frozenset({"repo.get", "contents.read", "issues.list", "issues.get", "issues.comments.list", "pulls.list", "pulls.get", "pulls.comments.list"})
WRITE_ACTIONS = READ_ACTIONS | {"issues.create", "issues.comment", "pulls.create", "pulls.comment", "branches.create"}


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
    "repo.get": (set(), set()),
    "contents.read": ({"path"}, {"ref"}),
    "issues.list": (set(), {"state", "page", "per_page"}),
    "issues.get": ({"number"}, set()),
    "issues.comments.list": ({"number"}, {"page", "per_page"}),
    "issues.create": ({"title"}, {"body"}),
    "issues.comment": ({"number", "body"}, set()),
    "pulls.list": (set(), {"state", "page", "per_page"}),
    "pulls.get": ({"number"}, set()),
    "pulls.comments.list": ({"number"}, {"page", "per_page"}),
    "pulls.create": ({"title", "head", "base"}, {"body", "draft"}),
    "pulls.comment": ({"number", "body"}, set()),
    "branches.create": ({"branch"}, {"source_branch", "expected_source_sha", "source_commit_sha"}),
    "pulls.merge": ({"number", "expected_head_sha", "merge_method"}, set()),
}


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
    if action.endswith(".list"):
        result["page"] = _integer(result.get("page", 1), "page", 10000)
        result["per_page"] = _integer(result.get("per_page", 30), "per_page", 100)
        if action in {"issues.list", "pulls.list"}:
            state = result.get("state", "open")
            if not isinstance(state, str) or state not in {"open", "closed", "all"}:
                raise ActionError("invalid state")
            result["state"] = state
    if action == "contents.read":
        path = _text(result["path"], "path", maximum=2**31, blank=True)
        if path and (path.startswith("/") or "\\" in path or any(p in {"", ".", ".."} for p in path.split("/"))):
            raise ActionError("invalid content path")
        if "ref" in result:
            result["ref"] = valid_ref(result["ref"])
    if action in {"issues.create", "pulls.create"}:
        result["title"] = _text(result["title"], "title", maximum=256)
        result["body"] = _text(result.get("body", ""), "body", blank=True, controls=True)
    if action in {"issues.comment", "pulls.comment"}:
        result["body"] = _text(result["body"], "body", controls=True)
    if action == "pulls.create":
        for name in ("head", "base"):
            result[name] = valid_ref(result[name], name, branch=True)
        draft = result.get("draft", False)
        if type(draft) is not bool:
            raise ActionError("draft must be a boolean")
        result["draft"] = draft
    if action == "branches.create":
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
    if action == "pulls.merge":
        result["expected_head_sha"] = valid_sha(result["expected_head_sha"], "expected_head_sha")
        if not isinstance(result["merge_method"], str) or result["merge_method"] not in {"merge", "squash", "rebase"}:
            raise ActionError("invalid merge_method")
    return result


def build_request(action: str, repo: str, params: dict) -> Request:
    repo = canonical_repo(repo)
    p = validate_params(action, params)
    prefix = f"/repos/{repo}"
    if action == "repo.get":
        return Request("GET", prefix, {}, None)
    if action == "contents.read":
        return Request("GET", prefix + "/contents" + ("/" + quote(p["path"], safe="/") if p["path"] else ""), {"ref": p["ref"]} if "ref" in p else {}, None)
    if action == "branches.create":
        return Request("POST", prefix + "/git/refs", {}, {"ref": "refs/heads/" + p["branch"], "sha": p.get("source_commit_sha", p.get("expected_source_sha"))})
    if action == "pulls.merge":
        return Request("PUT", prefix + f"/pulls/{p['number']}/merge", {}, {"sha": p["expected_head_sha"], "merge_method": p["merge_method"]})
    resource, operation = action.split(".", 1)
    endpoint = prefix + "/" + resource
    if operation == "list":
        return Request("GET", endpoint, {k: p[k] for k in ("state", "page", "per_page")}, None)
    if operation == "get":
        return Request("GET", endpoint + f"/{p['number']}", {}, None)
    if operation in {"comment", "comments.list"}:
        endpoint = prefix + f"/issues/{p['number']}/comments"
        if operation == "comments.list":
            return Request("GET", endpoint, {k: p[k] for k in ("page", "per_page")}, None)
        return Request("POST", endpoint, {}, {"body": p["body"]})
    return Request("POST", endpoint, {}, p)
