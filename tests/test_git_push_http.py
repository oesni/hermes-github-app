"""Exercise real Git HTTP authentication without any external service or secret."""
import base64
import sys
import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import subprocess
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

from git_fixtures import Repository, git
from hermes_github_app import git_push


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux Git worker")
@pytest.mark.parametrize("incremental", [False, True])
def test_http_askpass_publishes_with_host_only_token(tmp_path, monkeypatch, incremental):
    repositories = Repository(tmp_path)
    git(repositories.remote, 'config', 'http.receivepack', 'true')
    token = 'fake-installation-token-for-local-test'
    expected = 'Basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode()
    authenticated = []
    rejected = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_git(self):
            if self.headers.get('Authorization') != expected:
                rejected.append(True)
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="git-test"')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            authenticated.append(True)
            parsed = urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            env = {**os.environ, 'GIT_PROJECT_ROOT': str(repositories.remote.parent),
                   'GIT_HTTP_EXPORT_ALL': '1', 'REQUEST_METHOD': self.command,
                   'PATH_INFO': parsed.path, 'QUERY_STRING': parsed.query,
                   'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                   'CONTENT_LENGTH': str(len(body)), 'REMOTE_USER': 'test-user',
                   'SERVER_PROTOCOL': 'HTTP/1.1'}
            response = subprocess.run(['git', 'http-backend'], input=body, capture_output=True,
                                      env=env, check=True).stdout
            headers, payload = response.split(b'\r\n\r\n', 1)
            values = [line.decode().split(': ', 1) for line in headers.split(b'\r\n')]
            status = next((int(v.split()[0]) for k, v in values if k.lower() == 'status'), 200)
            self.send_response(status)
            for name, value in values:
                if name.lower() != 'status':
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = handle_git
        do_POST = handle_git

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(git_push, '_remote', lambda repo: f'http://127.0.0.1:{server.server_port}/{repositories.remote.name}')
    original = git_push._run
    inputs = []

    def local_http(root, args, *positional, **keywords):
        inputs.append(list(args))
        assert token not in repr(args)
        askpass = root / 'askpass'
        if askpass.exists():
            assert token not in askpass.read_text()
        return original(root, ['-c', 'protocol.http.allow=always', *args], *positional, **keywords)

    monkeypatch.setattr(git_push, '_run', local_http)
    session = SimpleNamespace(repo='acme/demo', _token=token, deadline=time.monotonic() + 120)
    branch = 'main' if incremental else 'feature'
    params = {'branch': branch, 'commit_sha': repositories.head, 'expected_head_sha': repositories.initial if incremental else None,
              'bundle_base64': repositories.bundle(branch, incremental=incremental)}
    try:
        result = git_push.publish(session, params, lambda: None)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert authenticated and rejected
    assert token not in repr(result)
    assert repositories.remote_head(branch) == repositories.head
    assert any('push' in args for args in inputs)
