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
    monkeypatch.setattr(HermesRuntime, 'install_environment_guard', lambda *args: None)
    ctx = Mock()
    plugin.register(ctx)
    handler = ctx.register_tool.call_args.kwargs['handler']
    assert json.loads(handler({'repo':'acme/demo'}))['code']=='isolation_refusal'
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

agent=SimpleNamespace(session_id="native-test",valid_tool_names={"repo_get","terminal","read_file","write_file","patch","search_files"},_interrupt_requested=False)
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
assert registry.get_entry("repo_get") is not None
assert registry.get_entry("github_app_action") is None
definitions=model_tools.get_tool_definitions(enabled_toolsets=["terminal","file","github_app"],skip_tool_search_assembly=True)
agent.valid_tool_names={d["function"]["name"] for d in definitions}
from hermes_github_app.actions import ACTIONS
assert set(ACTIONS) <= agent.valid_tool_names
assert "process" in agent.valid_tool_names
assert {"terminal","read_file","write_file","search_files","patch","repo_get"} <= agent.valid_tool_names
args={"repo":"acme/demo"}
result=model_tools.handle_function_call("repo_get",args,task_id="default",session_id="native-test",tool_call_id="call-1",enabled_tools=["repo_get"])
assert json.loads(result)["ok"],result
context=service.execute.call_args.kwargs["context"]
assert context.session_id=="native-test" and not context.cancelled()
for tool,bad in [("issue_get",{"repo":"acme/demo","number":"42"}), ("pr_create",{"repo":"acme/demo","title":"t","base":"main","head":"feature","draft":"false"}), ("repo_get",{"repo":"acme/demo","action":"repo_get"})]:
    before=service.execute.call_count
    rejected=model_tools.handle_function_call(tool,bad,task_id="default",session_id="native-test",tool_call_id="bad-"+tool,enabled_tools=list(agent.valid_tool_names))
    assert json.loads(rejected)["code"]=="invalid_arguments",rejected
    assert service.execute.call_count==before
accepted=model_tools.handle_function_call("issue_get",{"repo":"acme/demo","number":42},task_id="default",session_id="native-test",tool_call_id="good-int",enabled_tools=list(agent.valid_tool_names))
assert json.loads(accepted)["ok"],accepted
assert service.execute.call_args.args==("issue_get","acme/demo",{"number":42})
assert json.loads(registry.dispatch("repo_get",args))["code"]=="isolation_refusal"
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
# Native resolver rejects extraction before the host extraction function runs,
# including a symlink whose requested name hides its document extension.
from pathlib import Path
from hermes_github_app.isolation import IsolationError
from tools import read_extract
probe=Path(os.environ["HERMES_HOME"])/"secret.docx"
probe.write_text("TEST-ONLY-NOT-A-DOCUMENT")
alias=probe.with_name("innocent.txt")
alias.symlink_to(probe)
for path in [str(probe),str(alias),runtime.config_path,runtime.key_path]:
    with patch.object(read_extract,"extract_document_text",side_effect=AssertionError("host extraction reached")):
        try:
            runtime.prepare_tool("read_file",{"path":path},context)
        except IsolationError:
            pass
        else:
            raise AssertionError("unsafe host read accepted")
# Read routing bypasses the host read helper even if a path changes after
# validation: all content and stat operations belong to ShellFileOperations.
from tools import file_tools
ops=Mock()
ops.read_file.return_value.to_dict.return_value={"content":"sandbox-only","file_size":12}
with patch.object(file_tools,"_get_file_ops",return_value=ops), patch.object(runtime,"check"), patch.object(file_tools,"read_file_tool",side_effect=AssertionError("host reader reached")):
    routed=json.loads(runtime.read_sandbox_file({"path":"/workspace/example","offset":2,"limit":3},context))
    assert routed["content"]=="sandbox-only"
    ops.read_file.assert_called_once_with("/workspace/example",offset=2,limit=3)
# A file-helper recreation must force reuse off even when the native caller
# omits the setting (the idle-reaper race); no container is created here.
from hermes_github_app.runtime import _CURRENT_CALL
original=runtime._original_creator
seen=[]
def constructor(env_type,image,cwd,timeout,ssh_config=None,container_config=None,local_config=None,task_id="default",host_cwd=None):
    seen.append(container_config)
    return object()
with patch.object(terminal_tool,"_create_environment",constructor):
    runtime.install_environment_guard()
    token=_CURRENT_CALL.set(context)
    try:
        terminal_tool._create_environment("docker","test","/workspace",10,container_config={})
        assert seen[-1]["docker_persist_across_processes"] is False
    finally:
        _CURRENT_CALL.reset(token)
        runtime.close()
runtime.closed=False
runtime._creator=terminal_tool._create_environment
runtime._original_creator=original
# Directory hooks are a separate surface from plugin hooks.
import types
fakegateway=types.ModuleType("gateway.run")
fakegateway._gateway_runner_ref=lambda: SimpleNamespace(hooks=SimpleNamespace(_handlers={"agent:start":[object()]},loaded_hooks=[]))
with patch.dict(sys.modules,{"gateway.run":fakegateway}):
    try:
        runtime.check_configuration()
    except IsolationError:
        pass
    else:
        raise AssertionError("gateway directory hooks accepted")
from hermes_cli.plugins import get_pre_tool_call_block_message
assert get_pre_tool_call_block_message("execute_code",{})
assert not get_pre_tool_call_block_message("terminal",{})
agent.valid_tool_names.add("execute_code")
result=model_tools.handle_function_call("repo_get",args,task_id="default",session_id="native-test",tool_call_id="call-2",enabled_tools=list(agent.valid_tool_names))
assert json.loads(result)["code"]=="isolation_refusal"
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


def test_fourteen_flat_tools_are_registered_with_distinct_handlers(configuration, monkeypatch):
    from hermes_github_app.actions import ACTIONS, PARAMETER_FIELDS
    monkeypatch.setattr(plugin, 'GitHubClient', Mock())
    monkeypatch.setattr(HermesRuntime, 'check', lambda *args: None)
    monkeypatch.setattr(HermesRuntime, 'install_environment_guard', lambda *args: None)
    ctx = Mock()
    plugin.register(ctx)
    registrations = {call.kwargs['name']: call.kwargs for call in ctx.register_tool.call_args_list}
    assert set(registrations) == set(ACTIONS)
    assert len({id(item['handler']) for item in registrations.values()}) == 14
    for action, item in registrations.items():
        schema = item['schema']['parameters']
        required, optional = PARAMETER_FIELDS[action]
        assert set(schema['properties']) == {'repo', *required, *optional}
        assert set(schema['required']) == {'repo', *required}
        assert schema['additionalProperties'] is False
        assert 'action' not in schema['properties'] and 'params' not in schema['properties']
    assert registrations['issue_get']['schema']['parameters']['properties']['number'] == {'anyOf': [{'type': 'integer', 'minimum': 1, 'maximum': 2**31-1}]}
    assert registrations['pr_create']['schema']['parameters']['properties']['draft'] == {'anyOf': [{'type': 'boolean'}]}


@pytest.mark.parametrize('failure, expected', [
    ('config_missing', 'config_path path'),
    ('config_mode', 'config_path permissions'),
    ('key_missing', 'private_key path'),
    ('key_mode', 'private_key permissions'),
    ('yaml', 'YAML'),
    ('field', 'field'),
])
def test_startup_diagnostic_categories(configuration, caplog, failure, expected):
    key = configuration.parent / 'key.pem'
    if failure == 'config_missing':
        configuration.unlink()
    elif failure == 'config_mode':
        configuration.chmod(0o644)
    elif failure == 'key_missing':
        key.unlink()
    elif failure == 'key_mode':
        key.chmod(0o644)
    elif failure == 'yaml':
        configuration.write_text('version: [unterminated')
    else:
        configuration.write_text('version: 1\nunknown: PRIVATE-SECRET')
    ctx = Mock()
    plugin.register(ctx)
    ctx.register_tool.assert_not_called()
    assert expected in caplog.text
    assert 'PRIVATE-SECRET' not in caplog.text
