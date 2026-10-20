"""Read a bundle in the caller's terminal backend through public tool dispatch."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import shlex
import time

CHUNK_BYTES = 16 * 1024
TRANSFER_SECONDS = 120
# The program receives only data arguments and never executes repository code.
_READER = r'''
import base64, hashlib, json, os, stat, sys
try:
    path, offset, limit, maximum = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum or offset > before.st_size:
            raise ValueError()
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
                    raise ValueError()
                h.update(block)
                remaining -= len(block)
            if f.read(1):
                raise ValueError()
            digest = h.hexdigest()
        if identity(before) != identity(os.fstat(f.fileno())):
            raise ValueError()
    print(json.dumps({"identity": identity(before), "offset": offset, "data": base64.b64encode(data).decode("ascii"), "sha256": digest}, separators=(",", ":")))
except Exception:
    sys.exit(1)
'''


class BundleInputError(ValueError):
    """Static error only; no terminal output or caller file content is exposed."""


def validate_bundle_path(path):
    if (not isinstance(path, str) or not path.startswith('/') or len(path) > 4096
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in path)):
        raise BundleInputError('Invalid sandbox bundle path.')
    return path


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
    expected_identity = expected_digest = None
    received = bytearray()
    max_calls = math.ceil(max_bytes / CHUNK_BYTES)
    try:
        for _ in range(max_calls):
            remaining = deadline - time.monotonic()
            if remaining < 1:
                raise BundleInputError('Bundle transfer deadline exceeded.')
            command = shlex.join(['python3', '-I', '-c', _READER, path,
                                  str(len(received)), str(CHUNK_BYTES), str(max_bytes)])
            raw = dispatcher('terminal', {'command': command, 'timeout': min(30, int(remaining))}, **context)
            if time.monotonic() > deadline or not isinstance(raw, str) or len(raw) > 100000:
                raise BundleInputError('Bundle transfer failed.')
            response = json.loads(raw)
            if (not isinstance(response, dict) or type(response.get('exit_code')) is not int
                    or response['exit_code'] != 0 or response.get('error')
                    or not isinstance(response.get('output'), str)):
                raise BundleInputError('Bundle transfer failed.')
            chunk = json.loads(response['output'])
            if not isinstance(chunk, dict) or set(chunk) != {'identity', 'offset', 'data', 'sha256'}:
                raise BundleInputError('Bundle transfer failed.')
            identity = chunk['identity']
            if (not isinstance(identity, list) or len(identity) != 5
                    or any(type(v) is not int for v in identity)
                    or not 0 < identity[2] <= max_bytes
                    or type(chunk['offset']) is not int or chunk['offset'] != len(received)):
                raise BundleInputError('Bundle transfer failed.')
            digest = chunk['sha256']
            if expected_identity is None:
                expected_identity = identity
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise BundleInputError('Bundle transfer failed.')
                expected_digest = digest
            if identity != expected_identity:
                raise BundleInputError('Bundle changed during transfer.')
            if not isinstance(chunk['data'], str) or len(chunk['data']) > 4 * ((CHUNK_BYTES + 2) // 3):
                raise BundleInputError('Bundle transfer failed.')
            data = base64.b64decode(chunk['data'], validate=True)
            if base64.b64encode(data).decode('ascii') != chunk['data']:
                raise BundleInputError('Bundle transfer failed.')
            if len(data) != min(CHUNK_BYTES, identity[2] - len(received)) or not data:
                raise BundleInputError('Bundle transfer failed.')
            received.extend(data)
            if len(received) == identity[2]:
                if digest != expected_digest or hashlib.sha256(received).hexdigest() != expected_digest:
                    raise BundleInputError('Bundle changed during transfer.')
                return base64.b64encode(received).decode('ascii')
            if digest is not None and digest != expected_digest:
                raise BundleInputError('Bundle changed during transfer.')
    except BundleInputError:
        raise
    except Exception:
        raise BundleInputError('Bundle transfer failed.') from None
    raise BundleInputError('Bundle transfer limit exceeded.')
