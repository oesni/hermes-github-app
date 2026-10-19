"""Explicit live-context binding; never use Hermes's global last tool list."""
from __future__ import annotations
from contextvars import ContextVar
from dataclasses import dataclass
import importlib
import hashlib
from pathlib import Path
import json
import sys
import threading
from .isolation import IsolationError, _guard_isolation

_CURRENT_CALL = ContextVar('github_app_host_call', default=None)
SUPPORTED_TOOLS = {
    'terminal': ('tools.terminal_tool', '_handle_terminal'),
    'process': ('tools.process_registry', '_handle_process'),
    'read_file': ('tools.file_tools', '_handle_read_file'),
    'write_file': ('tools.file_tools', '_handle_write_file'),
    'patch': ('tools.file_tools', '_handle_patch'),
    'search_files': ('tools.file_tools', '_handle_search_files'),
}
SUPPORTED_TOOLSETS = frozenset({'terminal', 'file', 'github_app'})


@dataclass
class HostCall:
    runtime: object
    agent: object
    session_id: str
    task_id: str
    call_id: str
    identity: str

    def cancelled(self):
        try:
            return (self.runtime.closed or bool(self.agent._interrupt_requested)
                    or self.runtime.find_agent(self.session_id) is not self.agent)
        except Exception:
            return True


class HermesRuntime:
    def __init__(self, ctx, config_path, key_path):
        self.manager = ctx._manager
        self.config_path, self.key_path = config_path, key_path
        self.closed = False
        self.handler = None
        self._fingerprints = json.loads(Path(__file__).with_name('compatibility.json').read_text())

    def check_configuration(self):
        from tools import terminal_tool
        source_root = Path(terminal_tool.__file__).resolve().parent.parent
        for relative, expected in self._fingerprints.items():
            if hashlib.sha256((source_root / relative).read_bytes()).hexdigest() != expected:
                raise IsolationError('Unsupported Hermes runtime revision')
        from hermes_cli.config import load_config_readonly
        config = load_config_readonly()
        selections = [config.get('toolsets')]
        platforms = config.get('platform_toolsets', {})
        if not isinstance(platforms, dict):
            raise IsolationError('Unsupported platform toolset configuration')
        selections.extend(platforms.values())
        if any(not isinstance(v, list) or not set(v) <= SUPPORTED_TOOLSETS for v in selections):
            raise IsolationError('Only terminal, file, and github_app toolsets are supported')
        if config.get('hooks') or config.get('mcp_servers') or config.get('gateway', {}).get('multiplex_profiles'):
            raise IsolationError('Host hooks and MCP surfaces are unsupported')
        for callbacks in [*self.manager._hooks.values(), *self.manager._middleware.values()]:
            for callback in callbacks:
                if not getattr(callback, '__module__', '').startswith(__package__ + '.'):
                    raise IsolationError('Unlisted host hook or middleware')

    def find_agent(self, session_id):
        candidates = []
        cli = self.manager._cli_ref
        if cli is not None:
            candidates.append(getattr(cli, 'agent', None))
        module = sys.modules.get('gateway.run')
        if module is not None:
            runner = module._gateway_runner_ref()
            if runner is not None:
                candidates.extend(list(runner._running_agents.values()))
        matches = [a for a in candidates if a is not None and getattr(a, 'session_id', None) == session_id]
        if len({id(a) for a in matches}) != 1:
            raise IsolationError('Calling agent cannot be verified')
        return matches[0]

    def check_agent(self, agent):
        from tools.registry import registry
        names = agent.valid_tool_names
        if not isinstance(names, set) or not names or not names <= {*SUPPORTED_TOOLS, 'github_app_action'}:
            raise IsolationError('Calling context exposes unsupported tools')
        for name in names:
            entry = registry.get_entry(name)
            if entry is None:
                raise IsolationError('Cannot verify enabled tool')
            if name == 'github_app_action':
                if self.handler is not None and entry.handler is not self.handler:
                    raise IsolationError('GitHub tool handler was replaced')
            else:
                module, function = SUPPORTED_TOOLS[name]
                if entry.handler is not getattr(importlib.import_module(module), function):
                    raise IsolationError('Unsupported replacement tool handler')
        if not hasattr(agent, '_interrupt_requested'):
            raise IsolationError('Cancellation contract unavailable')

    def check(self, call=None):
        if self.closed:
            raise IsolationError('Plugin stopped')
        self.check_configuration()
        _guard_isolation(self.config_path, self.key_path, call.task_id if call else None)
        if call is not None:
            if call.cancelled():
                raise IsolationError('Calling context ended')
            self.check_agent(call.agent)

    def middleware(self, *, tool_name, args, next_call, session_id='', task_id='', tool_call_id='', **kwargs):
        if tool_name not in {*SUPPORTED_TOOLS, 'github_app_action'}:
            return json.dumps({'ok': False, 'error': 'isolation_refused'})
        try:
            if not all(isinstance(v, str) and v for v in (session_id, task_id, tool_call_id)):
                raise IsolationError('Host call identity unavailable')
            agent = self.find_agent(session_id)
            call = HostCall(self, agent, session_id, task_id, tool_call_id,
                            f'{id(self)}:{id(agent)}:{session_id}:{task_id}:{tool_call_id}')
            self.check(call)
            self.prepare_tool(tool_name, args, call)
            token = _CURRENT_CALL.set(call)
            try:
                return next_call(args)
            finally:
                _CURRENT_CALL.reset(token)
        except Exception:
            return json.dumps({'ok': False, 'error': 'isolation_refused'})

    def prepare_tool(self, name, args, call):
        if name in {'read_file', 'write_file', 'patch', 'search_files'}:
            # The supported Hermes revision omits persist_across_processes in
            # its file-first environment creator. Initialize through terminal's
            # correctly configured path before the file helper can create one.
            from tools import terminal_tool
            key = terminal_tool._resolve_container_task_id(call.task_id)
            with terminal_tool._env_lock:
                existing = terminal_tool._active_environments.get(key)
            if existing is None:
                terminal_tool.terminal_tool(command='true', task_id=call.task_id)
                with terminal_tool._env_lock:
                    existing = terminal_tool._active_environments.get(key)
                if existing is None:
                    raise IsolationError('Cannot initialize safe file environment')
                self.check(call)
        if name == 'process' and args.get('action', 'list') != 'list':
            from tools.process_registry import process_registry
            from tools.terminal_tool import _resolve_container_task_id
            with process_registry._lock:
                item = process_registry._running.get(str(args.get('session_id'))) or process_registry._finished.get(str(args.get('session_id')))
            if item is None or item.task_id not in {call.task_id, _resolve_container_task_id(call.task_id)}:
                raise IsolationError('Process does not belong to calling sandbox')

    def pre_tool(self, tool_name=None, args=None, **kwargs):
        # Hermes emits this before intercepted tools as well as registry tools.
        name = tool_name or kwargs.get('tool') or kwargs.get('name')
        if name not in {*SUPPORTED_TOOLS, 'github_app_action'}:
            return {'action': 'block', 'message': 'Unsupported tool surface for GitHub App isolation'}
        return None

    def current_call(self):
        call = _CURRENT_CALL.get()
        if call is None or call.runtime is not self:
            raise IsolationError('Trusted host dispatch required')
        self.check(call)
        return call

    def close(self):
        self.closed = True
