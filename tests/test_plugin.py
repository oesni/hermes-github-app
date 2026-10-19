import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from hermes_github_app import plugin
from hermes_github_app.runtime import HermesRuntime, _CURRENT_CALL, HostCall
from hermes_github_app.secure_files import SecureFileError, read_secure_file, check_secure_file


@pytest.fixture
def configuration(tmp_path, monkeypatch):
    # pytest's macOS/Linux temp roots may be world-writable. Host-file tests
    # need the contract's protected parent chain, not a /tmp exemption.
    base = Path(__file__).resolve().parent.parent / '.test-private'
    base.mkdir(exist_ok=True, mode=0o700)
    import tempfile
    directory = Path(tempfile.mkdtemp(dir=base))
    path = directory / 'config.yaml'
    key = directory / 'key.pem'
    key.write_text('TEST-ONLY-PRIVATE-KEY')
    key.chmod(0o600)
    path.write_text(f'''version: 1
auth:
  app_id: 1
  installation_id: 2
  private_key_path: {key}
policy:
  repositories:
    mode: allowlist
    allow: [acme/demo]
    exclude: []
  default_access: read
''')
    path.chmod(0o600)
    monkeypatch.setenv('HERMES_GITHUB_APP_CONFIG', str(path))
    yield path
    import shutil
    shutil.rmtree(directory)
    try:
        base.rmdir()
    except OSError:
        pass


def test_protected_file_checks_and_snapshot(configuration):
    assert b'version: 1' in read_secure_file(str(configuration), 10000)
    configuration.chmod(0o644)
    with pytest.raises(SecureFileError):
        check_secure_file(str(configuration))
    configuration.chmod(0o600)
    linked = configuration.parent / 'link'
    linked.symlink_to(configuration)
    with pytest.raises(SecureFileError):
        check_secure_file(str(linked))
    linked.unlink()
    alias = configuration.parent / 'alias'
    alias.symlink_to(configuration.parent, target_is_directory=True)
    with pytest.raises(SecureFileError):
        check_secure_file(str(alias / configuration.name))
    alias.unlink()
    configuration.parent.chmod(0o777)
    try:
        with pytest.raises(SecureFileError):
            check_secure_file(str(configuration))
    finally:
        configuration.parent.chmod(0o700)


def test_invalid_startup_omits_tool_and_does_not_echo_secret(configuration, caplog):
    configuration.write_text('password: PRIVATE-SECRET')
    ctx = Mock()
    plugin.register(ctx)
    ctx.register_tool.assert_not_called()
    assert 'PRIVATE-SECRET' not in caplog.text


def test_direct_registry_bypass_refused_and_runtime_snapshot(configuration, monkeypatch):
    client = Mock()
    monkeypatch.setattr(plugin, 'GitHubClient', Mock(return_value=client))
    monkeypatch.setattr(HermesRuntime, 'check', lambda *args: None)
    ctx = Mock()
    plugin.register(ctx)
    handler = ctx.register_tool.call_args.kwargs['handler']
    assert json.loads(handler({'action':'repo.get','repo':'acme/demo','params':{}}))['error']=='isolation_refused'
    ctx.register_middleware.assert_called_once()


def test_context_cancelled_on_agent_interruption_or_session_replacement():
    agent = SimpleNamespace(_interrupt_requested=False)
    runtime = SimpleNamespace(closed=False, find_agent=lambda _: agent)
    context = HostCall(runtime, agent, 's', 't', 'c', 'id')
    assert not context.cancelled()
    agent._interrupt_requested = True
    assert context.cancelled()
    agent._interrupt_requested = False
    runtime.find_agent = lambda _: object()
    assert context.cancelled()


@pytest.mark.skipif(not os.getenv('HERMES_GITHUB_APP_HERMES_SOURCE'), reason='opt-in real Hermes dispatch')
def test_native_hermes_dispatch(configuration, tmp_path):
    source = os.environ['HERMES_GITHUB_APP_HERMES_SOURCE']
    profile = tmp_path / 'profile'
    profile.mkdir()
    (profile / 'config.yaml').write_text('toolsets: [github_app, terminal, file]\nplugins:\n  disabled: [raft-platform]\n')
    script = '''
import json,sys
from types import SimpleNamespace
from unittest.mock import Mock
sys.path.insert(0,sys.argv[1])
import model_tools
from hermes_cli.plugins import PluginContext,PluginManifest,get_plugin_manager
from tools.registry import registry
from hermes_github_app import plugin
manager=get_plugin_manager()

agent=SimpleNamespace(session_id="native-test",valid_tool_names={"github_app_action","terminal","read_file","write_file","patch","search_files"},_interrupt_requested=False)
manager._cli_ref=SimpleNamespace(agent=agent)
client=Mock()
# A fake GitHub service isolates this integration test from the separately tested transport.
service=Mock()
service.execute.return_value={"ok":True,"data":{"name":"demo"}}
plugin.GitHubClient=Mock(return_value=client)
plugin.GitHubService=Mock(return_value=service)
from hermes_github_app.runtime import HermesRuntime
import os
ctx=PluginContext(PluginManifest(name="hermes-github-app"),manager)
HermesRuntime(ctx,os.environ["HERMES_GITHUB_APP_CONFIG"],os.path.join(os.path.dirname(os.environ["HERMES_GITHUB_APP_CONFIG"]),"key.pem")).check()
plugin.register(ctx)
assert registry.get_entry("github_app_action") is not None
definitions=model_tools.get_tool_definitions(enabled_toolsets=["terminal","file","github_app"],skip_tool_search_assembly=True)
agent.valid_tool_names={d["function"]["name"] for d in definitions}
assert "process" in agent.valid_tool_names
assert {"terminal","read_file","write_file","search_files","patch","github_app_action"} <= agent.valid_tool_names
args={"action":"repo.get","repo":"acme/demo","params":{}}
result=model_tools.handle_function_call("github_app_action",args,task_id="default",session_id="native-test",tool_call_id="call-1",enabled_tools=["github_app_action"])
assert json.loads(result)["ok"],result
context=service.execute.call_args.kwargs["context"]
assert context.session_id=="native-test" and not context.cancelled()
assert json.loads(registry.dispatch("github_app_action",args))["error"]=="isolation_refused"
# Exercise the native file-first preparation contract without creating a second
# Docker test environment: only the environment constructor boundary is mocked.
from tools import terminal_tool
from unittest.mock import patch
from hermes_github_app.runtime import HermesRuntime
runtime=context.runtime
key=terminal_tool._resolve_container_task_id(context.task_id)
assert key not in terminal_tool._active_environments
marker=object()
def initialize(**kw):
    assert kw=={"command":"true","task_id":context.task_id}
    terminal_tool._active_environments[key]=marker
try:
    with patch.object(terminal_tool,"terminal_tool",side_effect=initialize) as creator, patch.object(runtime,"check") as check:
        runtime.prepare_tool("read_file",{"path":"/workspace/example"},context)
        creator.assert_called_once()
        check.assert_called_once_with(context)
        runtime.prepare_tool("read_file",{"path":"/workspace/example"},context)
        creator.assert_called_once()
finally:
    terminal_tool._active_environments.pop(key,None)
from hermes_cli.plugins import get_pre_tool_call_block_message
assert get_pre_tool_call_block_message("execute_code",{})
assert not get_pre_tool_call_block_message("terminal",{})
agent.valid_tool_names.add("execute_code")
result=model_tools.handle_function_call("github_app_action",args,task_id="default",session_id="native-test",tool_call_id="call-2",enabled_tools=list(agent.valid_tool_names))
assert json.loads(result)["error"]=="isolation_refused"
agent._interrupt_requested=True
assert context.cancelled()
print("Real native middleware/dispatch and context rejection passed")
'''
    env = {'HOME': os.environ['HOME'], 'PATH': os.environ.get('PATH', ''),
           'HERMES_HOME': str(profile), 'HERMES_GITHUB_APP_CONFIG': str(configuration),
           'TERMINAL_ENV': 'docker', 'TERMINAL_DOCKER_PERSIST_ACROSS_PROCESSES': 'false',
           'TERMINAL_SANDBOX_DIR': str(tmp_path / 'sandbox')}
    result = subprocess.run([sys.executable, '-c', script, source], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
