"""Read a bundle in the caller's terminal backend through public tool dispatch.

Terminal results are model-facing text: the host may redact, truncate or
otherwise rewrite them before dispatch returns. Chunks therefore travel as
lowercase hexadecimal, which secret-redaction patterns do not target, masked
with a fresh per-attempt keystream so any remaining content-dependent rewrite
does not repeat on a retry. Every chunk carries a digest bound to that attempt;
an altered chunk is read again a bounded number of times and never accepted.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import shlex
import time

CHUNK_BYTES = 16 * 1024
TRANSFER_SECONDS = 120
CHUNK_ATTEMPTS = 3
MAX_ALTERED_READS = 8
_NONCE_BYTES = 16
# Static, cause-specific errors. They never include terminal output or file data.
_EXIT_ERRORS = {
    2: 'Bundle file was not found in the active terminal task.',
    3: 'Bundle path is not a nonempty regular file within the bundle size limit.',
    4: 'Bundle changed while it was being read.',
}
# The program receives only data arguments and never executes repository code.
_READER = r'''
import errno, hashlib, json, os, stat, sys
def mask(data, nonce):
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream[:len(data)], "big")).to_bytes(len(data), "big")
try:
    path, offset, limit, maximum = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    nonce = bytes.fromhex(sys.argv[5])
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        sys.exit({errno.ENOENT: 2, errno.ELOOP: 3}.get(error.errno, 1))
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum or offset > before.st_size:
        os.close(fd)
        sys.exit(3)
    with os.fdopen(fd, "rb") as f:
        def identity(s):
            return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        f.seek(offset)
        data = f.read(min(limit, before.st_size - offset))
        digest = None
        if offset == 0 or offset + len(data) == before.st_size:
            f.seek(0)
            h = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = f.read(min(65536, remaining))
                if not block:
                    sys.exit(4)
                h.update(block)
                remaining -= len(block)
            if f.read(1):
                sys.exit(4)
            digest = hashlib.sha256(nonce + h.digest()).hexdigest()
        if identity(before) != identity(os.fstat(f.fileno())):
            sys.exit(4)
    print(json.dumps({"identity": identity(before), "offset": offset, "data": mask(data, nonce).hex(),
                      "chunk_sha256": hashlib.sha256(nonce + data).hexdigest(), "sha256": digest},
                     separators=(",", ":")))
except SystemExit:
    raise
except Exception:
    sys.exit(1)
'''


class BundleInputError(ValueError):
    """Static error only; no terminal output or caller file content is exposed."""


class _AlteredOutput(Exception):
    """A successful reader result whose payload did not survive the terminal channel."""


def _mask(data, nonce):
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(nonce + counter.to_bytes(8, 'big')).digest()
        counter += 1
    return (int.from_bytes(data, 'big')
            ^ int.from_bytes(stream[:len(data)], 'big')).to_bytes(len(data), 'big')


def _is_digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in '0123456789abcdef' for c in value))


def validate_bundle_path(path):
    if (not isinstance(path, str) or not path.startswith('/') or len(path) > 4096
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in path)):
        raise BundleInputError('Invalid sandbox bundle path.')
    return path


def _read_chunk(dispatcher, path, context, offset, max_bytes, deadline):
    """Return (identity, data, nonce, file_digest) for one verified chunk."""
    remaining = deadline - time.monotonic()
    if remaining < 1:
        raise BundleInputError('Bundle transfer deadline exceeded.')
    nonce = os.urandom(_NONCE_BYTES)
    command = shlex.join(['python3', '-I', '-c', _READER, path, str(offset),
                          str(CHUNK_BYTES), str(max_bytes), nonce.hex()])
    raw = dispatcher('terminal', {'command': command, 'timeout': min(30, int(remaining))}, **context)
    if time.monotonic() > deadline:
        raise BundleInputError('Bundle transfer deadline exceeded.')
    if not isinstance(raw, str) or len(raw) > 200000:
        raise BundleInputError('Terminal dispatch returned an unusable result.')
    response = json.loads(raw)
    if (not isinstance(response, dict) or type(response.get('exit_code')) is not int
            or response.get('error') or not isinstance(response.get('output'), str)):
        raise BundleInputError('Terminal dispatch returned an unusable result.')
    if response['exit_code'] != 0:
        raise BundleInputError(_EXIT_ERRORS.get(
            response['exit_code'], 'The bundle reader failed in the active terminal task; python3 is required.'))
    # From here the reader succeeded, so a malformed payload means the terminal
    # result was rewritten (for example redacted or truncated) after the reader.
    try:
        chunk = json.loads(response['output'])
    except ValueError:
        raise _AlteredOutput() from None
    if not isinstance(chunk, dict) or set(chunk) != {'identity', 'offset', 'data', 'chunk_sha256', 'sha256'}:
        raise _AlteredOutput()
    identity = chunk['identity']
    if (not isinstance(identity, list) or len(identity) != 5
            or any(type(v) is not int for v in identity)
            or type(chunk['offset']) is not int or chunk['offset'] != offset):
        raise _AlteredOutput()
    if not 0 < identity[2] <= max_bytes or offset >= identity[2]:
        raise BundleInputError('Bundle changed while it was being read.')
    expected_length = min(CHUNK_BYTES, identity[2] - offset)
    encoded = chunk['data']
    if (not isinstance(encoded, str) or len(encoded) != 2 * expected_length
            or any(c not in '0123456789abcdef' for c in encoded)
            or not _is_digest(chunk['chunk_sha256'])):
        raise _AlteredOutput()
    data = _mask(bytes.fromhex(encoded), nonce)
    if hashlib.sha256(nonce + data).hexdigest() != chunk['chunk_sha256']:
        raise _AlteredOutput()
    digest = chunk['sha256']
    needs_digest = offset == 0 or offset + expected_length == identity[2]
    if needs_digest != (digest is not None) or (digest is not None and not _is_digest(digest)):
        raise _AlteredOutput()
    return identity, data, nonce, digest


def resolve_bundle_path(dispatcher, path, context, max_bytes):
    """Return canonical base64, preserving the active terminal task context.

    A missing task identifier refuses the path form rather than falling back to
    a default terminal environment. The direct base64 form needs no dispatcher.
    """
    validate_bundle_path(path)
    if (not callable(dispatcher) or not isinstance(context, dict)
            or not isinstance(context.get('task_id'), str) or not context['task_id']):
        raise BundleInputError('Active terminal task context is required.')
    deadline = time.monotonic() + TRANSFER_SECONDS
    expected_identity = None
    whole_file_checks = []
    received = bytearray()
    altered_reads = 0
    try:
        for _ in range(math.ceil(max_bytes / CHUNK_BYTES)):
            for attempt in range(CHUNK_ATTEMPTS):
                try:
                    identity, data, nonce, digest = _read_chunk(
                        dispatcher, path, context, len(received), max_bytes, deadline)
                    break
                except _AlteredOutput:
                    altered_reads += 1
                    if attempt + 1 == CHUNK_ATTEMPTS or altered_reads >= MAX_ALTERED_READS:
                        raise BundleInputError(
                            'Terminal output altered or truncated the bundle data; '
                            'check terminal output limits and output filters.') from None
            if expected_identity is None:
                expected_identity = identity
            if identity != expected_identity:
                raise BundleInputError('Bundle changed while it was being read.')
            if digest is not None:
                whole_file_checks.append((nonce, digest))
            received.extend(data)
            if len(received) == identity[2]:
                final = hashlib.sha256(received).digest()
                if (len(whole_file_checks) not in {1, 2} or any(
                        hashlib.sha256(n + final).hexdigest() != d for n, d in whole_file_checks)):
                    raise BundleInputError('Bundle changed while it was being read.')
                return base64.b64encode(received).decode('ascii')
    except BundleInputError:
        raise
    except Exception:
        raise BundleInputError('Terminal dispatch returned an unusable result.') from None
    raise BundleInputError('Bundle transfer limit exceeded.')
