"""Conservative Docker boundary checks for supported Hermes versions."""
import json
import os
from pathlib import Path
import subprocess
import sys
from .secure_files import check_secure_file

class IsolationError(ValueError):
    pass

def _overlaps(left, right):
    left, right = Path(left).resolve(), Path(right).resolve()
    return left == right or left in right.parents or right in left.parents


def _check_mount(source, protected):
    source = Path(source).resolve()
    if source.is_socket() or any(_overlaps(source, item) for item in protected):
        raise IsolationError('Unsafe Docker mount')


def _capabilities(value):
    if value is None:
        return set()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IsolationError('Cannot verify Docker capabilities')
    return {item.upper().removeprefix('CAP_') for item in value}


def _inspect_container(environment, protected, allowed_mounts):
    # Do not trust only current settings: a cached environment may have been
    # created with different mounts or namespace privileges earlier.
    if type(environment).__name__ != 'DockerEnvironment' or type(environment).__module__ != 'tools.environments.docker':
        raise IsolationError('Existing environment is not supported Docker')
    container_id = getattr(environment, '_container_id', None)
    executable = getattr(environment, '_docker_exe', None)
    if not container_id or not executable:
        raise IsolationError('Cannot verify existing Docker environment')
    if getattr(environment, '_env', None) or getattr(environment, '_forward_env', None) or getattr(environment, '_init_env_args', None):
        raise IsolationError('Existing Docker credential forwarding is not supported')
    result = subprocess.run([executable, 'inspect', container_id], capture_output=True, text=True, timeout=10, check=True)
    data = json.loads(result.stdout)
    if not isinstance(data, list) or len(data) != 1:
        raise IsolationError('Cannot verify existing Docker environment')
    state = data[0].get('State', {})
    if not isinstance(state, dict) or state.get('Running') is not True or state.get('Paused') is not False or state.get('Restarting') is not False:
        raise IsolationError('Docker container is not running safely')
    host = data[0]['HostConfig']
    if host.get('Privileged') or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host' or host.get('NetworkMode') not in {'bridge', 'default', 'none'} or host.get('Devices') or host.get('VolumesFrom'):
        raise IsolationError('Unsafe Docker privileges')
    if 'ALL' not in _capabilities(host.get('CapDrop')) or not set(host.get('SecurityOpt', [])) & {'no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true'}:
        raise IsolationError('Docker hardening unavailable')
    if set(host.get('SecurityOpt', [])) - {'no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true'}:
        raise IsolationError('Unsafe Docker security profile')
    if _capabilities(host.get('CapAdd')) - {'DAC_OVERRIDE', 'CHOWN', 'FOWNER', 'SETGID', 'SETUID'}:
        raise IsolationError('Unsafe Docker capabilities')
    for mount in data[0].get('Mounts', []):
        if mount.get('Type') != 'bind':
            raise IsolationError('Unapproved Docker volume type')
        source = mount.get('Source')
        if not isinstance(source, str) or not source or not Path(source).is_absolute():
            raise IsolationError('Cannot verify Docker mount source')
        _check_mount(source, protected)
        resolved = Path(source).resolve()
        if not any(resolved == root or root in resolved.parents for root in allowed_mounts):
            raise IsolationError('Existing Docker mount is not approved')


def _guard_isolation(config_path, key_path, task_id=None):
    # These runtime APIs are intentionally fail-closed if the installed Hermes
    # version changes. The file tool uses this same terminal configuration.
    check_secure_file(str(config_path))
    check_secure_file(str(key_path))
    from tools import terminal_tool
    from tools.credential_files import get_credential_file_mounts, get_skills_directory_mount, get_cache_directory_mounts
    from tools.environments.base import get_sandbox_dir
    from tools.env_passthrough import get_all_passthrough
    from hermes_constants import get_config_path, get_env_path

    config = terminal_tool._get_env_config()
    if config.get('env_type') != 'docker':
        raise IsolationError('Docker terminal backend required')
    for field in ('docker_volumes', 'docker_env', 'docker_forward_env', 'docker_extra_args', 'docker_mount_cwd_to_workspace', 'docker_persist_across_processes'):
        if config.get(field):
            raise IsolationError('Unsupported Docker configuration')
    if terminal_tool.resolve_task_overrides(task_id or 'default') or any(terminal_tool._task_env_overrides.values()):
        raise IsolationError('Task environment overrides are not supported')
    if get_all_passthrough() or get_credential_file_mounts():
        raise IsolationError('Credential forwarding is not supported')
    protected = [Path(config_path), Path(key_path), Path(__file__).resolve().parent.parent,
                 Path(terminal_tool.__file__).resolve().parent.parent, Path(sys.prefix),
                 Path(get_config_path()), Path(get_env_path())]
    sandbox = Path(get_sandbox_dir())
    if any(p.is_symlink() for p in [sandbox, *sandbox.parents]):
        raise IsolationError('Sandbox symlinks are unsupported')
    allowed_mounts = [sandbox.resolve()]
    _check_mount(get_sandbox_dir(), protected)
    for mount in get_skills_directory_mount() + get_cache_directory_mounts():
        _check_mount(mount['host_path'], protected)
        allowed_mounts.append(Path(mount['host_path']).resolve())
    # An older shared container must not bypass startup validation.
    with terminal_tool._env_lock:
        environments = list(terminal_tool._active_environments.values())
    from tools import file_tools
    with file_tools._file_ops_lock:
        file_environments = [ops.env for ops in file_tools._file_ops_cache.values()]
    from tools.process_registry import process_registry
    with process_registry._lock:
        processes = [*process_registry._running.values(), *process_registry._finished.values()]
    process_environments = []
    for process in processes:
        if process.pid_scope != 'sandbox' or process.process is not None or process._pty is not None or process.env_ref is None:
            raise IsolationError('Host process session is reachable')
        process_environments.append(process.env_ref)
    for environment in [*environments, *file_environments, *process_environments]:
        _inspect_container(environment, protected, allowed_mounts)
