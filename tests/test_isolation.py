"""Docker boundary checks with synthetic inspect data and an opt-in live smoke."""
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from hermes_github_app.isolation import IsolationError, _check_mount, _inspect_container


DockerEnvironment = type('DockerEnvironment', (), {'__module__': 'tools.environments.docker'})


def environment():
    env = DockerEnvironment()
    env._container_id = 'test-container'
    env._docker_exe = 'docker'
    env._env = {}
    env._forward_env = []
    env._init_env_args = []
    return env


@pytest.fixture
def inspect_data(tmp_path):
    return [{
        'State': {'Running': True, 'Paused': False, 'Restarting': False},
        'HostConfig': {
            'Privileged': False, 'PidMode': '', 'IpcMode': 'private',
            'NetworkMode': 'bridge', 'Devices': [], 'VolumesFrom': None,
            'CapDrop': ['ALL'], 'CapAdd': ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'],
            'SecurityOpt': ['no-new-privileges'],
        },
        'Mounts': [{'Type': 'bind', 'Source': str(tmp_path / 'sandbox'), 'Destination': '/workspace'}],
    }]


def inspect_with(monkeypatch, data, tmp_path, env=None):
    runner = Mock(return_value=SimpleNamespace(stdout=json.dumps(data)))
    monkeypatch.setattr('hermes_github_app.isolation.subprocess.run', runner)
    _inspect_container(env or environment(), [tmp_path / 'protected'], [(tmp_path / 'sandbox').resolve()])
    return runner


def test_hardened_container_accepts_only_inspect_command(monkeypatch, inspect_data, tmp_path):
    runner = inspect_with(monkeypatch, inspect_data, tmp_path)
    runner.assert_called_once_with(['docker', 'inspect', 'test-container'], capture_output=True, text=True, timeout=10, check=True)


@pytest.mark.parametrize(('field', 'value'), [
    ('Privileged', True), ('PidMode', 'host'), ('IpcMode', 'host'),
    ('NetworkMode', 'host'), ('NetworkMode', 'container:other'), ('NetworkMode', 'unknown'),
    ('Devices', [{'PathOnHost': '/dev/kvm'}]), ('VolumesFrom', ['other']),
    ('CapDrop', []), ('CapDrop', None), ('CapAdd', ['SYS_ADMIN']),
    ('CapAdd', ['NET_ADMIN']), ('SecurityOpt', []), ('SecurityOpt', ['seccomp=unconfined']),
])
def test_unsafe_docker_host_configuration_refused(monkeypatch, inspect_data, tmp_path, field, value):
    inspect_data[0]['HostConfig'][field] = value
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path)


@pytest.mark.parametrize('security_option', ['no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true'])
def test_supported_no_new_privileges_spellings(monkeypatch, inspect_data, tmp_path, security_option):
    inspect_data[0]['HostConfig']['SecurityOpt'] = [security_option]
    inspect_with(monkeypatch, inspect_data, tmp_path)


@pytest.mark.parametrize('field', ['_env', '_forward_env', '_init_env_args'])
def test_cached_environment_forwarding_refused_before_inspection(monkeypatch, inspect_data, tmp_path, field):
    env = environment()
    setattr(env, field, ['SECRET'])
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path, env)


@pytest.mark.parametrize('field', ['_container_id', '_docker_exe'])
def test_unverifiable_environment_refused(monkeypatch, inspect_data, tmp_path, field):
    env = environment()
    setattr(env, field, None)
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path, env)


def test_unknown_environment_type_refused(monkeypatch, inspect_data, tmp_path):
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path, SimpleNamespace(_container_id='id', _docker_exe='docker'))


@pytest.mark.parametrize('data', [[], [{}, {}], {}, None])
def test_unverifiable_inspect_count_refused(monkeypatch, tmp_path, data):
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, data, tmp_path)


@pytest.mark.parametrize('kind', ['volume', 'tmpfs', 'unknown'])
def test_nonbind_mount_refused(monkeypatch, inspect_data, tmp_path, kind):
    inspect_data[0]['Mounts'][0]['Type'] = kind
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path)


def test_protected_and_unapproved_mounts_refused(monkeypatch, inspect_data, tmp_path):
    for source in [tmp_path / 'protected', tmp_path / 'protected/key.pem', tmp_path, tmp_path / 'unapproved']:
        inspect_data[0]['Mounts'][0]['Source'] = str(source)
        with pytest.raises(IsolationError):
            inspect_with(monkeypatch, inspect_data, tmp_path)


def test_symlink_mount_cannot_hide_protected_file(tmp_path):
    protected = tmp_path / 'protected'
    protected.mkdir()
    symlink = tmp_path / 'sandbox-link'
    symlink.symlink_to(protected, target_is_directory=True)
    with pytest.raises(IsolationError):
        _check_mount(symlink, [protected / 'key.pem'])


def test_socket_mount_refused(tmp_path, monkeypatch):
    # Socket creation is forbidden by some CI sandboxes; model the filesystem
    # type result without opening an unrelated local IPC endpoint.
    path = (tmp_path / 'control.sock').resolve()
    monkeypatch.setattr(Path, 'is_socket', lambda self: self == path)
    with pytest.raises(IsolationError):
        _check_mount(path, [])


@pytest.mark.skipif(os.environ.get('HERMES_GITHUB_APP_DOCKER_TEST') != '1', reason='opt-in local Docker smoke')
def test_real_docker_inspect_boundary(tmp_path):
    docker = shutil.which('docker')
    if not docker:
        pytest.fail('Docker smoke explicitly enabled but docker is unavailable')
    sandbox = tmp_path / 'sandbox'
    sandbox.mkdir()
    protected = tmp_path / 'protected'
    protected.mkdir()
    (protected / 'test-key.pem').write_text('TEST-ONLY-NONCREDENTIAL')
    container = None
    try:
        # No credentials or GitHub calls. Only this returned container ID is removed.
        result = subprocess.run([
            docker, 'run', '-d', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={sandbox},dst=/workspace',
            'alpine:3.22', 'sleep', '120',
        ], check=True, capture_output=True, text=True, timeout=60)
        container = result.stdout.strip()
        env = environment()
        env._container_id, env._docker_exe = container, docker
        _inspect_container(env, [protected], [sandbox.resolve()])
        inaccessible = subprocess.run([docker, 'exec', container, 'test', '!', '-e', str(protected / 'test-key.pem')], capture_output=True, timeout=10)
        assert inaccessible.returncode == 0
        # The very same real mount is rejected when classified as protected.
        with pytest.raises(IsolationError):
            _inspect_container(env, [sandbox], [sandbox.resolve()])
    finally:
        if container:
            subprocess.run([docker, 'rm', '-f', container], check=False, capture_output=True, timeout=20)


@pytest.mark.parametrize('source', [None, '', 'relative/sandbox'])
def test_unverifiable_bind_source_refused(monkeypatch, inspect_data, tmp_path, source):
    inspect_data[0]['Mounts'][0]['Source'] = source
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path)


@pytest.mark.parametrize('state', [None, {}, {'Running': False, 'Paused': False, 'Restarting': False}, {'Running': True, 'Paused': True, 'Restarting': False}, {'Running': True, 'Paused': False, 'Restarting': True}])
def test_unverifiable_active_state_refused(monkeypatch, inspect_data, tmp_path, state):
    inspect_data[0]['State'] = state
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path)


@pytest.mark.parametrize('option', ['seccomp=unconfined', 'apparmor=unconfined', 'label=disable', 'no-new-privileges:false'])
def test_extra_security_options_not_hidden_by_hardening_flag(monkeypatch, inspect_data, tmp_path, option):
    inspect_data[0]['HostConfig']['SecurityOpt'] = ['no-new-privileges', option]
    with pytest.raises(IsolationError):
        inspect_with(monkeypatch, inspect_data, tmp_path)


@pytest.fixture
def guard_runtime(monkeypatch, tmp_path):
    import sys
    import threading
    from types import ModuleType
    from hermes_github_app import isolation
    modules = {name: ModuleType(name) for name in ['tools', 'tools.terminal_tool', 'tools.credential_files', 'tools.environments', 'tools.environments.base', 'tools.env_passthrough', 'tools.file_tools', 'tools.process_registry']}
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    terminal = modules['tools.terminal_tool']
    terminal.__file__ = str(tmp_path / 'hermes-source' / 'tools' / 'terminal_tool.py')
    config = {'env_type': 'docker'}
    terminal._get_env_config = lambda: config
    terminal.resolve_task_overrides = lambda task_id: {}
    terminal._task_env_overrides = {}
    terminal._env_lock = threading.Lock()
    terminal._active_environments = {}
    files = modules['tools.file_tools']
    files._file_ops_lock = threading.Lock()
    files._file_ops_cache = {}
    registry = SimpleNamespace(_lock=threading.Lock(), _running={}, _finished={})
    modules['tools.process_registry'].process_registry = registry
    credentials = modules['tools.credential_files']
    credentials.get_credential_file_mounts = lambda: []
    credentials.get_skills_directory_mount = lambda: []
    credentials.get_cache_directory_mounts = lambda: []
    modules['tools.env_passthrough'].get_all_passthrough = lambda: {}
    sandbox = tmp_path / 'sandbox'
    modules['tools.environments.base'].get_sandbox_dir = lambda: str(sandbox)
    secure = Mock()
    inspect = Mock()
    monkeypatch.setattr(isolation, 'check_secure_file', secure)
    monkeypatch.setattr(isolation, '_inspect_container', inspect)
    return SimpleNamespace(modules=modules, terminal=terminal, config=config, files=files, registry=registry, credentials=credentials, secure=secure, inspect=inspect, config_path=tmp_path / 'private/config.yaml', key_path=tmp_path / 'private/key.pem', sandbox=sandbox)


def run_guard(runtime):
    from hermes_github_app.isolation import _guard_isolation
    _guard_isolation(runtime.config_path, runtime.key_path, 'session-1')


def test_guard_checks_files_then_cached_surface_environments(guard_runtime):
    runtime = guard_runtime
    terminal_env, file_env, process_env = environment(), environment(), environment()
    runtime.terminal._active_environments['session-1'] = terminal_env
    runtime.files._file_ops_cache['session-1'] = SimpleNamespace(env=file_env)
    runtime.registry._finished['old'] = SimpleNamespace(pid_scope='sandbox', process=None, _pty=None, env_ref=process_env)
    run_guard(runtime)
    assert [call.args[0] for call in runtime.secure.call_args_list] == [str(runtime.config_path), str(runtime.key_path)]
    assert [call.args[0] for call in runtime.inspect.call_args_list] == [terminal_env, file_env, process_env]


@pytest.mark.parametrize(('field', 'value'), [
    ('env_type', 'local'), ('env_type', 'ssh'), ('env_type', None),
    ('docker_volumes', ['/host:/sandbox']), ('docker_env', {'TOKEN': 'secret'}),
    ('docker_forward_env', ['TOKEN']), ('docker_extra_args', ['--privileged']),
    ('docker_mount_cwd_to_workspace', True), ('docker_persist_across_processes', True),
])
def test_guard_refuses_backend_and_configuration_overrides(guard_runtime, field, value):
    guard_runtime.config[field] = value
    with pytest.raises(IsolationError):
        run_guard(guard_runtime)
    guard_runtime.inspect.assert_not_called()


@pytest.mark.parametrize('scope', ['current', 'other'])
def test_guard_refuses_current_or_other_task_override(guard_runtime, scope):
    if scope == 'current':
        guard_runtime.terminal.resolve_task_overrides = lambda task: {'env_type': 'local'}
    else:
        guard_runtime.terminal._task_env_overrides['other'] = {'env_type': 'local'}
    with pytest.raises(IsolationError):
        run_guard(guard_runtime)


@pytest.mark.parametrize('kind', ['credential', 'passthrough'])
def test_guard_refuses_automatic_credential_forwarding(guard_runtime, kind):
    if kind == 'credential':
        guard_runtime.credentials.get_credential_file_mounts = lambda: [{'host_path': '/secret'}]
    else:
        guard_runtime.modules['tools.env_passthrough'].get_all_passthrough = lambda: {'TOKEN': 'secret'}
    with pytest.raises(IsolationError):
        run_guard(guard_runtime)


@pytest.mark.parametrize('protected_kind', ['configuration', 'key', 'plugin', 'hermes', 'python'])
def test_guard_automatic_mount_cannot_expose_any_protected_source(guard_runtime, protected_kind):
    import sys
    from hermes_github_app import isolation
    paths = {'configuration': guard_runtime.config_path, 'key': guard_runtime.key_path, 'plugin': Path(isolation.__file__).parent, 'hermes': Path(guard_runtime.terminal.__file__).parent, 'python': Path(sys.prefix)}
    guard_runtime.credentials.get_skills_directory_mount = lambda: [{'host_path': str(paths[protected_kind])}]
    with pytest.raises(IsolationError):
        run_guard(guard_runtime)


@pytest.mark.parametrize(('field', 'value'), [('pid_scope', 'host'), ('process', object()), ('_pty', object()), ('env_ref', None)])
def test_guard_refuses_host_process_in_running_or_finished_registry(guard_runtime, field, value):
    for bucket in [guard_runtime.registry._running, guard_runtime.registry._finished]:
        fields = dict(pid_scope='sandbox', process=None, _pty=None, env_ref=environment())
        fields[field] = value
        bucket['reachable'] = SimpleNamespace(**fields)
        with pytest.raises(IsolationError):
            run_guard(guard_runtime)
        bucket.clear()
