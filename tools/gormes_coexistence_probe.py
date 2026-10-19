"""Opt-in, VM-local coexistence probe; never activate a production plugin.

Run with the managed Hermes Python bootstrap in an isolated HERMES_HOME. The
caller supplies a fresh protected --state-dir and a staged checkout --source.
Only assertions, source hashes and version identifiers are exported. Installed
plugins and their production settings are never copied into this repository.
The allowlist candidate is an explicitly labelled in-memory addition, not a
production policy change. GitHub HTTP and the child lifecycle are deterministic.
"""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid


def add_candidate_actions(current, actions):
    """Add exact public operation names without removing existing permissions."""
    return frozenset(current) | frozenset(actions)


def load_directory(path, name):
    spec = importlib.util.spec_from_file_location(name, path / '__init__.py', submodule_search_locations=[str(path)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DeterministicLifecycle:
    """Only the child execution boundary is fake; Orpheus resolution/ledger run."""
    def __init__(self):
        self.requests = []
    def launch(self, request):
        self.requests.append(request)
        return {'model': request['model'], 'provider': request['provider'], 'capability': 'DUMMY-CHILD-HANDLE'}
    def status(self, handle):
        return {'state': 'SUCCEEDED', 'handle': handle}
    def result(self, handle):
        return {'ready': True, 'summary': 'OFFLINE_CHILD_OK', 'handle': handle, 'completed_at': time.time()}
    def cancel(self, handle, reason):
        return {'accepted': True}


class FixtureContext:
    """Delegate all actual registration to the installed public PluginContext."""
    def __init__(self, native, settings=None, lifecycle=None):
        self.native, self.settings = native, settings or {}
        self.subagent_lifecycle = lifecycle
        self.cleanups = []
    def get_config(self, key, default=None):
        return self.settings.get(key, default)
    def on_unload(self, callback):
        self.cleanups.append(callback)
    def __getattr__(self, name):
        return getattr(self.native, name)


def main(args):
    state = Path(args.state_dir).resolve()
    source = Path(args.source).resolve()
    installed = Path(args.installed_plugins).resolve()
    assert state.is_dir() and stat_mode(state) == 0o700
    assert Path(os.environ['HERMES_HOME']).resolve() == state / 'profile'
    sys.path.insert(0, str(source))
    import httpx
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from ruamel.yaml import YAML
    yaml = YAML(typ="safe")
    def dump_yaml(value):
        stream = io.StringIO(); yaml.dump(value, stream); return stream.getvalue()
    import model_tools
    from hermes_cli.plugins import PluginContext, PluginManifest, get_plugin_manager
    from tools.registry import registry
    from hermes_github_app.actions import ACTIONS
    directory_entry = load_directory(source, 'probe_github_entry')
    plugin = sys.modules['probe_github_entry.hermes_github_app.plugin']
    GitHubClient = plugin.GitHubClient
    assert set(yaml.load((source / 'plugin.yaml').read_text())['provides_tools']) == set(ACTIONS)

    report = {'schema': 1, 'production_changed': False, 'github_network': False,
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'product_hashes': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted([*(source / 'hermes_github_app').glob('*.py'), source / '__init__.py', source / 'plugin.yaml'])},
              'evidence_classification': {'production_changed': 'test_design_no_production_writes', 'github_network': 'test_design_mock_transport'},
              'child_execution': 'deterministic_lifecycle', 'stages': {}}
    manager = get_plugin_manager()
    contexts = []
    def context(name, **kwargs):
        ctx = FixtureContext(PluginContext(PluginManifest(name=name), manager), **kwargs)
        contexts.append(ctx)
        return ctx
    key_bytes = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    key = state / 'dummy.pem'
    key.write_bytes(key_bytes); key.chmod(0o600)
    config = state / 'github-app.yaml'
    config.write_text(dump_yaml({'version': 1, 'auth': {'app_id': 12, 'installation_id': 34, 'private_key_path': str(key)},
        'policy': {'repositories': {'mode': 'allowlist', 'allow': ['fixture/demo'], 'exclude': []}, 'default_access': 'read'}}))
    config.chmod(0o600)
    os.environ['HERMES_GITHUB_APP_CONFIG'] = str(config)
    calls = []
    dummy_token = secrets.token_urlsafe(32)
    def transport(request):
        calls.append((request.method, request.url.path))
        assert request.url.host == 'api.github.com'
        if request.url.path == '/app/installations/34/access_tokens':
            grant = json.loads(request.content)
            assert grant['repositories'] == ['demo']
            return httpx.Response(201, json={'token': dummy_token, 'permissions': grant['permissions']})
        if request.url.path == '/installation/repositories':
            return httpx.Response(200, json={'total_count': 1, 'repositories': [{'full_name': 'fixture/demo'}]})
        if request.url.path == '/repos/fixture/demo':
            return httpx.Response(200, json={'full_name': 'fixture/demo', 'description': dummy_token})
        return httpx.Response(404, json={})
    class OfflineClient(GitHubClient):
        def __init__(self, **kwargs):
            super().__init__(**kwargs, transport=httpx.MockTransport(transport))
    plugin.GitHubClient = OfflineClient

    try:
        security = load_directory(installed / 'gormes-sandbox-policy', 'probe_security')
        provenance = load_directory(installed / 'gormes-request-provenance', 'probe_provenance')
        security.register(context('gormes-sandbox-policy'))
        provenance.register(context('gormes-request-provenance', settings={'state_dir': str(state / 'provenance')}))
        hook_count = len(manager._hooks.get('pre_tool_call', []))
        assert hook_count >= 2
        assert security.integrity_ok(), 'installed-integrity-check'
        assert security.check(tool_name='terminal', args={'command': 'true'}) is None, 'fixture-docker-policy'
        original_allowed = frozenset(security.ALLOWED)
        report['installed_hashes'] = {name: hashlib.sha256((installed / name / '__init__.py').read_bytes()).hexdigest()
            for name in ['gormes-sandbox-policy', 'gormes-request-provenance', 'hermes-orpheus']}
        directory_entry.register(context('hermes-github-app'))
        report['stages']['directory_entrypoint'] = True
        assert len(manager._hooks.get('pre_tool_call', [])) == hook_count
        assert set(ACTIONS) <= set(registry._merged_tools()), 'registered-tools'
        def dispatch(name, params):
            result = model_tools.handle_function_call(name, params, task_id='coexist-probe', session_id='coexist-probe')
            return json.loads(result) if isinstance(result, str) else result
        before = len(calls)
        expected_block = security.check(tool_name='repo_get', args={'repo': 'fixture/demo'})
        assert expected_block is not None
        baseline = dispatch('repo_get', {'repo': 'fixture/demo'})
        assert len(calls) == before
        assert not baseline.get('ok', False)
        assert expected_block['message'] in json.dumps(baseline)
        report['stages']['unchanged_production_hook'] = {'new_tool_blocked': True, 'upstream_calls': 0}

        # Explicit candidate ONLY: extend this subprocess's module object. The
        # installed file and integrity manifest stay byte-for-byte unchanged.
        security.ALLOWED = add_candidate_actions(original_allowed, ACTIONS)
        assert original_allowed <= security.ALLOWED
        assert security.ALLOWED - original_allowed == set(ACTIONS) - original_allowed
        before = len(calls)
        denied = dispatch('repo_get', {'repo': 'unselected/demo'})
        assert denied.get('code') == 'policy_denied' and len(calls) == before
        allowed = dispatch('repo_get', {'repo': 'fixture/demo'})
        assert allowed.get('ok') is True and len(calls) > before
        encoded = json.dumps(allowed)
        assert dummy_token not in encoded and key_bytes.decode() not in encoded
        entry = registry._merged_tools()['gormes_create_pr']
        sentinel_calls = []
        def forbidden_handler(*args, **kwargs):
            sentinel_calls.append(True)
            raise AssertionError('legacy handler must never run')
        entry.handler = forbidden_handler
        assert 'gormes_create_pr' in security.ALLOWED
        blocked = dispatch('gormes_create_pr', {'repo': 'fixture/demo', 'head': 'a', 'base': 'b', 'title': 'offline', 'body': ''})
        assert not blocked.get('ok', False) and not sentinel_calls
        assert 'provenance' in json.dumps(blocked).lower()
        before = len(calls)
        assert security.check(tool_name='not_an_operator_approved_tool', args={}) is not None
        unknown = dispatch('not_an_operator_approved_tool', {})
        assert not unknown.get('ok', False) and len(calls) == before
        report['stages']['additive_policy_candidate'] = {'preserved_old_permissions': True, 'added_exact_tool_count': len(ACTIONS),
            'policy_denial_before_upstream': True, 'real_service_mock_http': True, 'secret_nonexposure': True,
            'provenance_gate_still_blocks': True, 'unknown_tool_still_blocked': True}

        report['stages']['orpheus'] = exercise_orpheus(installed, state, context, dispatch)
        if args.docker:
            report['stages']['docker'] = exercise_docker(state, dispatch)
        security.ALLOWED = original_allowed
        assert security.integrity_ok()
        report['stages']['hooks_preserved'] = True
    finally:
        for ctx in reversed(contexts):
            for close in reversed(ctx.cleanups):
                close()
    return report


def stat_mode(path):
    return path.stat().st_mode & 0o777


def exercise_orpheus(installed, state, context, dispatch):
    from ruamel.yaml import YAML
    yaml = YAML(typ="safe")
    def dump_yaml(value):
        stream = io.StringIO(); yaml.dump(value, stream); return stream.getvalue()
    lifecycle = DeterministicLifecycle()
    registry_config = {'schema_version': 1, 'inventory': {'models': {'offline': {'model': 'fixture', 'provider': 'offline'}}},
        'presets': [{'id': 'probe', 'fields': {'model': {'mode': 'fixed', 'value': 'offline'}, 'allowed_toolsets': {'mode': 'fixed', 'value': ['github_app', 'terminal', 'file']}}, 'compatible_settings': {'one': {}}}],
        'subagent_policy': 'probe', 'policies': {'probe': {'entrypoint': 'subagent',
            'input_schema': {'task.text': {'type': 'string', 'max_length': 100, 'required': True, 'trust': 'payload'}},
            'preset_selector': {'id': 'p', 'kind': 'parent'}, 'field_resolver': {'id': 'f', 'kind': 'fixed', 'settings': 'one'}}}}
    config = state / 'fixture-orpheus.yaml'; config.write_text(dump_yaml(registry_config))
    deployment = state / 'fixture-deployment.yaml'; deployment.write_text(dump_yaml({'subagent': {
        'fallback_disabled': True, 'allowed_toolsets': ['github_app', 'terminal', 'file'], 'verified_settings': [{'provider': 'offline', 'model': 'fixture'}]}}))
    entry = load_directory(installed / 'hermes-orpheus', 'probe_orpheus')
    entry.register(context('hermes-orpheus', settings={'config_path': str(config), 'deployment_path': str(deployment),
        'state_dir': str(state / 'orpheus')}, lifecycle=lifecycle))
    launched = dispatch('orpheus_spawn', {'task': 'Return the offline fixture marker.', 'preset_id': 'probe'})
    assert launched.get('state') == 'running', 'orpheus-launch'
    result = dispatch('orpheus_status', {'request_id': launched['request_id']})
    assert result.get('state') == 'SUCCEEDED', 'orpheus-completion'
    assert len(lifecycle.requests) == 1
    assert lifecycle.requests[0]['allowed_toolsets'] == ['github_app', 'terminal', 'file']
    assert result['result']['summary'] == 'OFFLINE_CHILD_OK'
    assert 'DUMMY-CHILD-HANDLE' not in json.dumps(result)
    return {'installed_resolver_adapter_ledger': True, 'child_provider': 'deterministic_fake', 'single_child': True, 'result_received': True}


def exercise_docker(state, dispatch):
    from tools import terminal_tool
    task = 'coexist-probe'
    key = terminal_tool._resolve_container_task_id(task)
    assert not terminal_tool._active_environments
    env = None
    try:
        first = dispatch('terminal', {'command': 'printf COEXIST_DOCKER_OK', 'timeout': 30})
        assert 'COEXIST_DOCKER_OK' in json.dumps(first)
        env = terminal_tool._active_environments[key]
        container_id = env._container_id
        second = dispatch('terminal', {'command': 'printf COEXIST_REUSE_OK', 'timeout': 30})
        assert 'COEXIST_REUSE_OK' in json.dumps(second)
        assert terminal_tool._active_environments[key]._container_id == container_id
        return {'real_terminal_docker': True, 'same_container_reused': True, 'cross_process_reuse_tested': False, 'profile_workspace_isolated': True}
    finally:
        if env is not None:
            env.cleanup(force_remove=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--installed-plugins', default='/home/hermes/.hermes/plugins')
    parser.add_argument('--docker', action='store_true')
    options = parser.parse_args()
    logging.disable(logging.CRITICAL)
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            receipt = main(options)
    except BaseException as exc:
        # Never export upstream exceptions, captured logs, or credentials.
        receipt = {'schema': 1, 'passed': False, 'failure_type': type(exc).__name__}
        import traceback
        own = [frame.lineno for frame in traceback.extract_tb(exc.__traceback__) if frame.filename == __file__]
        receipt['failure_line'] = own[-1] if own else None
        if isinstance(exc, ModuleNotFoundError):
            receipt['missing_module'] = exc.name
        if isinstance(exc, AssertionError) and exc.args and str(exc.args[0]) in {
            'installed-integrity-check', 'fixture-docker-policy', 'registered-tools', 'orpheus-launch', 'orpheus-completion'}:
            receipt['failure_stage'] = str(exc.args[0])
        print(json.dumps(receipt))
        raise SystemExit(1)
    receipt['passed'] = True
    print(json.dumps(receipt, sort_keys=True))
