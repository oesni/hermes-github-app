"""Race-resistant host file access. No paths or rejected values in errors."""
from __future__ import annotations
import errno
import os
import stat


class SecureFileError(ValueError):
    def __init__(self, message, *, category='permissions'):
        super().__init__(message)
        self.category = category


def _path_error():
    return SecureFileError('Protected file path is missing or invalid.', category='path')


def _permissions_error():
    return SecureFileError('Protected file ownership, mode, or parent permissions failed.', category='permissions')


def _open_secure(path: str) -> int:
    fd = None
    try:
        if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
            raise _path_error()
        parts = path.split('/')[1:]
        if not parts or any(part in {'', '.', '..'} for part in parts):
            raise _path_error()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags | os.O_DIRECTORY)
        for part in parts[:-1]:
            info = os.fstat(fd)
            if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
                raise _permissions_error()
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        parent = os.fstat(fd)
        if parent.st_uid not in {0, os.getuid()} or stat.S_IMODE(parent.st_mode) & 0o022:
            raise _permissions_error()
        child = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        os.close(fd)
        fd = child
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        own = info.st_uid == os.getuid() and mode in {0o400, 0o600}
        shared = info.st_uid == 0 and info.st_gid in {*os.getgroups(), os.getgid()} and mode in {0o440, 0o640}
        if not stat.S_ISREG(info.st_mode):
            raise _path_error()
        if not (own or shared):
            raise _permissions_error()
        result, fd = fd, None
        return result
    except SecureFileError:
        raise
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise _permissions_error() from None
        raise _path_error() from None
    except Exception:
        raise _path_error() from None
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
            raise SecureFileError('Protected file exceeds the size limit.', category='size')
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise SecureFileError('Protected file exceeds the size limit.', category='size')
    except OSError:
        raise SecureFileError('Protected file read failed.', category='read') from None
    finally:
        os.close(fd)
