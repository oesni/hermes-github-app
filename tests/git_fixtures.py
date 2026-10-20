"""Real, offline Git repositories used by publication integration tests."""
import base64
import os
from pathlib import Path
import subprocess


def git(repo, *args, input=None):
    env = {"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "Test Author",
           "GIT_AUTHOR_EMAIL": "author@example.invalid", "GIT_COMMITTER_NAME": "Test Committer",
           "GIT_COMMITTER_EMAIL": "committer@example.invalid", "LC_ALL": "C"}
    result = subprocess.run(["git", "-C", str(repo), *args], env=env,
                            input=input, capture_output=True, check=True)
    return result.stdout


class Repository:
    def __init__(self, root):
        self.work = root / "source"
        self.work.mkdir()
        git(self.work, "init", "-b", "main")
        self.remote = root / "remote.git"
        self.remote.mkdir()
        git(self.remote, "init", "--bare")
        self.initial = self.commit("initial.txt", b"base\n", "Initial commit")
        git(self.work, "push", str(self.remote), "HEAD:refs/heads/main")
        self.head = self.commit("binary.bin", b"\x00\xff\x80\n", "Add binary")
        self.head = self.commit("initial.txt", b"changed\n", "Update file")

    def commit(self, path, content, message):
        (self.work / path).write_bytes(content)
        git(self.work, "add", "--", path)
        git(self.work, "commit", "-m", message)
        return git(self.work, "rev-parse", "HEAD").decode().strip()

    def bundle(self, branch="feature", *, incremental=False):
        path = self.work.parent / "publication.bundle"
        git(self.work, "update-ref", "refs/heads/" + branch, "HEAD")
        revisions = ["refs/heads/" + branch]
        if incremental:
            revisions.append("^" + self.initial)
        git(self.work, "bundle", "create", str(path), *revisions)
        return base64.b64encode(path.read_bytes()).decode("ascii")

    def remote_head(self, branch):
        return git(self.remote, "rev-parse", "refs/heads/" + branch).decode().strip()
