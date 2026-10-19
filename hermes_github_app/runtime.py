"""Protected-file boundary for host-owned GitHub credentials.

This module uses the operating system's file checks only. It does not import
Hermes, inspect its tools or hooks, or change Docker settings.
"""
from __future__ import annotations

from .isolation import IsolationError
from .secure_files import check_secure_file


class HostBoundary:
    def __init__(self, config_path: str, key_path: str):
        self.config_path = config_path
        self.key_path = key_path
        self.closed = False

    def check(self):
        if self.closed:
            raise IsolationError('Plugin stopped')
        check_secure_file(self.config_path)
        check_secure_file(self.key_path)

    def close(self):
        self.closed = True
