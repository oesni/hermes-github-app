"""Race-resistant host file access. No paths or rejected values in errors."""
from __future__ import annotations
import os
from pathlib import PurePath
import stat


class SecureFileError(ValueError):
    pass


def _open_secure(path: str) -> int:
    fd = None
    try:
        if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
            raise ValueError()
        parts = path.split('/')[1:]
        if not parts or any(part in {'', '.', '..'} for part in parts):
            raise ValueError()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags | os.O_DIRECTORY)
        for part in parts[:-1]:
            info = os.fstat(fd)
            if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError()
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        parent = os.fstat(fd)
        if parent.st_uid not in {0, os.getuid()} or stat.S_IMODE(parent.st_mode) & 0o022:
            raise ValueError()
        child = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        os.close(fd)
        fd = child
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        own = info.st_uid == os.getuid() and mode in {0o400, 0o600}
        shared = info.st_uid == 0 and info.st_gid in {*os.getgroups(), os.getgid()} and mode in {0o440, 0o640}
        if not stat.S_ISREG(info.st_mode) or not (own or shared):
            raise ValueError()
        result, fd = fd, None
        return result
    except Exception:
        raise SecureFileError('Protected file ownership, mode, path, or parent check failed.') from None
    finally:
        if fd is not None:
            os.close(fd)


def check_secure_file(path: str) -> None:
    fd = _open_secure(path)
    os.close(fd)


def read_secure_file(path: str, max_bytes: int) -> bytes:
    fd = _open_secure(path)
    try:
        if os.fstat(fd).st_size > max_bytes:
            raise SecureFileError('Protected file exceeds the size limit.')
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise SecureFileError('Protected file exceeds the size limit.')
    finally:
        os.close(fd)
