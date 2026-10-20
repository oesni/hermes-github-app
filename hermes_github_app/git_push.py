"""Bounded publication of untrusted Git bundles with host-only credentials."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from .client import ClientError

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_OBJECTS = 100000
MAX_OUTPUT_BYTES = 1024 * 1024


def decode_bundle(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_BUNDLE_BYTES + 2) // 3):
        raise ValueError()
    data = base64.b64decode(value, validate=True)
    if not data or len(data) > MAX_BUNDLE_BYTES or base64.b64encode(data).decode('ascii') != value:
        raise ValueError()
    return data


def _remote(repo):
    return 'https://github.com/' + repo + '.git'


def _run(repo_path, args, deadline, token=None, mutation=False):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ClientError('Git operation timed out.', 'git_unavailable')
    git = shutil.which('git', path='/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin')
    if git is None or os.name != 'posix':
        raise ClientError('A supported host Git executable is required.', 'git_unavailable')
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(repo_path), 'LANG': 'C', 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_ATTR_NOSYSTEM': '1', 'GIT_PROTOCOL_FROM_USER': '0'}
    if token is not None:
        env['GIT_ASKPASS'] = str(Path(repo_path) / 'askpass')
        env['HERMES_PUSH_TOKEN'] = token
    command = [sys.executable, '-I', str(Path(__file__).with_name('git_worker.py')), git,
               '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
               '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true',
               '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
               '-c', 'core.attributesFile=/dev/null', '-c', 'pack.threads=1',
               '-c', 'pack.windowMemory=16m', '-c', 'core.deltaBaseCacheLimit=16m', *args]
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command, cwd=repo_path, env=env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                process.wait(timeout=min(remaining, 60))
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
            if output.tell() > MAX_OUTPUT_BYTES:
                raise ValueError()
            output.seek(0)
            result = output.read(MAX_OUTPUT_BYTES + 1)
            return process.returncode, result
    except BaseException as exc:
        if mutation:
            raise ClientError('Git push outcome is uncertain.', 'uncertain_outcome') from None
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ClientError('Git operation failed.', 'git_unavailable') from None


def publish(session, params, recheck):
    data = decode_bundle(params['bundle_base64'])
    header, separator, pack = data.partition(b'\n\n')
    lines = header.split(b'\n')
    advertised = (params['commit_sha'] + ' refs/heads/' + params['branch']).encode()
    if (not separator or len(header) > 4096 or not pack.startswith(b'PACK')
            or lines[0] != b'# v2 git bundle' or lines[-1] != advertised):
        raise ClientError('Invalid Git bundle.', 'invalid_arguments')
    prerequisites = lines[1:-1]
    expected = params['expected_head_sha']
    if prerequisites:
        if (len(prerequisites) != 1 or expected is None
                or not prerequisites[0].startswith(('-' + expected + ' ').encode())):
            raise ClientError('Bundle prerequisite must match the expected head.', 'invalid_arguments')
    ref = 'refs/heads/' + params['branch']
    deadline = min(session.deadline, time.monotonic() + 120)
    with tempfile.TemporaryDirectory(prefix='hermes-git-push-') as directory:
        root = Path(directory)
        # This executable contains no credential; only the network child gets the token.
        askpass = root / 'askpass'
        askpass.write_text('#!/bin/sh\ncase "$1" in *Username*) printf "%s" x-access-token;; *Password*) printf "%s" "$HERMES_PUSH_TOKEN";; *) exit 1;; esac\n')
        askpass.chmod(0o700)
        bundle = root / 'upload.bundle'
        bundle.write_bytes(data)

        def run(args, *, network=False, mutation=False):
            return _run(root, args, deadline, session._token if network else None, mutation)

        def required(args, *, network=False):
            code, out = run(args, network=network)
            if code:
                raise ClientError('Git data could not be verified.', 'git_unavailable')
            return out

        required(['init', '--bare', '--template=', '--object-format=sha1', '.'])
        remote_head = required(['ls-remote', '--refs', _remote(session.repo), ref], network=True)
        rows = remote_head.splitlines()
        if expected is None:
            matches = not rows
        else:
            matches = rows == [(expected + '\t' + ref).encode()]
        if not matches:
            raise ClientError('Remote branch differs from the expected head.', 'target_changed')
        if prerequisites:
            required(['fetch', '--no-tags', '--no-recurse-submodules', '--depth=1',
                      _remote(session.repo), expected], network=True)
            if required(['rev-parse', '--verify', 'FETCH_HEAD']).strip() != expected.encode():
                raise ClientError('Git prerequisite changed.', 'target_changed')
            required(['update-ref', 'refs/heads/bundle-base', expected])
        required(['bundle', 'verify', str(bundle)])
        required(['bundle', 'unbundle', str(bundle)])
        required(['fsck', '--strict', '--no-reflogs'])
        kind = required(['cat-file', '-t', params['commit_sha']]).strip()
        if kind != b'commit':
            raise ClientError('Bundle target must be a commit.', 'invalid_arguments')
        listing = required(['cat-file', '--batch-all-objects', '--batch-check=%(objectsize)'])
        sizes = listing.splitlines()
        if len(sizes) > MAX_OBJECTS or sum(int(size) for size in sizes) > MAX_OBJECT_BYTES:
            raise ClientError('Git objects exceed the size limit.', 'size_limit')
        if expected is not None:
            code, _ = run(['merge-base', '--is-ancestor', expected, params['commit_sha']])
            if code:
                raise ClientError('Push must fast-forward the expected head.', 'target_changed')
        recheck()
        # The explicit lease is checked by receive-pack atomically. The ancestry
        # check above forbids the history rewrites that a lease alone would allow.
        code, out = run(['push', '--porcelain', '--no-verify', '--recurse-submodules=no',
                         '--force-with-lease=' + ref + ':' + (expected or ''),
                         _remote(session.repo), params['commit_sha'] + ':' + ref],
                        network=True, mutation=True)
        statuses = [line.split(b'\t') for line in out.splitlines() if b'\t' in line]
        expected_mapping = (params['commit_sha'] + ':' + ref).encode()
        matching = [row for row in statuses if len(row) >= 3 and row[1] == expected_mapping]
        allowed_statuses = {b' ', b'*'}
        if expected == params['commit_sha']:
            allowed_statuses.add(b'=')
        if code or len(matching) != 1 or matching[0][0] not in allowed_statuses:
            # A failed transport may have lost the server acknowledgement. Never
            # infer no side effects from a process exit code or arbitrary stderr.
            raise ClientError('Git push outcome is uncertain.', 'uncertain_outcome')
        return {'branch': params['branch'], 'sha': params['commit_sha'],
                'previous_sha': expected, 'created': expected is None}
