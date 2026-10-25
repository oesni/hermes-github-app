import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock
import pytest
from hermes_github_app import plugin
from hermes_github_app.runtime import HostBoundary
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


def test_handler_rechecks_protected_files_and_ignores_other_host_surfaces(configuration, monkeypatch):
    client = Mock()
    service = Mock()
    service.execute.return_value = {'ok': True, 'data': {'name': 'demo'}}
    monkeypatch.setattr(plugin, 'GitHubClient', Mock(return_value=client))
    monkeypatch.setattr(plugin, 'GitHubService', Mock(return_value=service))
    ctx = Mock()
    plugin.register(ctx)
    ctx.register_middleware.assert_not_called()
    ctx.register_hook.assert_not_called()
    handlers = {call.kwargs['name']: call.kwargs['handler'] for call in ctx.register_tool.call_args_list}
    handler = handlers['github_repo_get']
    assert json.loads(handler({'repo': 'acme/demo'}, task_id='task', session_id='session'))['ok']
    assert service.execute.call_args.kwargs['recheck_isolation'].__func__ is HostBoundary.check
    configuration.chmod(0o644)
    try:
        before = service.execute.call_count
        refused = json.loads(handler({'repo': 'acme/demo'}))
        assert refused['code'] == 'isolation_refusal'
        assert 'key' not in refused['error'].lower()
        assert service.execute.call_count == before
    finally:
        configuration.chmod(0o600)


def test_missing_key_and_edited_config_do_not_reload_or_run(configuration, monkeypatch):
    calls = {'parse': 0}
    original = plugin.parse_config

    def counting(data):
        calls['parse'] += 1
        return original(data)

    service = Mock()
    service.execute.return_value = {'ok': True, 'data': {}}
    monkeypatch.setattr(plugin, 'parse_config', counting)
    monkeypatch.setattr(plugin, 'GitHubClient', Mock())
    monkeypatch.setattr(plugin, 'GitHubService', Mock(return_value=service))
    ctx = Mock()
    plugin.register(ctx)
    handler = {call.kwargs['name']: call.kwargs['handler'] for call in ctx.register_tool.call_args_list}['github_repo_get']
    assert calls['parse'] == 1
    configuration.write_text(configuration.read_text().replace('default_access: read', 'default_access: write'))
    assert json.loads(handler({'repo': 'acme/demo'}))['ok']
    assert calls['parse'] == 1
    key = configuration.parent / 'key.pem'
    key.unlink()
    assert json.loads(handler({'repo': 'acme/demo'}))['code'] == 'isolation_refusal'
    service.execute.assert_called_once()


def test_stopped_plugin_refuses_later_calls(configuration, monkeypatch):
    service = Mock()
    service.execute.return_value = {'ok': True, 'data': {}}
    monkeypatch.setattr(plugin, 'GitHubClient', Mock())
    monkeypatch.setattr(plugin, 'GitHubService', Mock(return_value=service))
    ctx = Mock()
    plugin.register(ctx)
    handler = ctx.register_tool.call_args.kwargs['handler']
    ctx.on_unload.call_args.args[0]()
    assert json.loads(handler({'repo': 'acme/demo'}))['code'] == 'isolation_refusal'
    service.execute.assert_not_called()


def test_package_does_not_bind_hermes_internals():
    root = Path(__file__).resolve().parents[1] / 'hermes_github_app'
    source = '\n'.join(path.read_text() for path in root.glob('*.py'))
    for token in (
        'compatibility.json', 'terminal_tool', 'docker_persist_across_processes',
        '_gateway_runner', 'valid_tool_names', 'register_middleware', 'pre_tool_call',
        '_create_environment', 'tools.file_tools', 'tools.environments',
    ):
        assert token not in source
    assert not (root / 'compatibility.json').exists()


@pytest.mark.skipif(not os.getenv('HERMES_GITHUB_APP_HERMES_SOURCE'), reason='opt-in real Hermes dispatch')
def test_native_plugin_api_dispatch(configuration, tmp_path):
    source = os.environ['HERMES_GITHUB_APP_HERMES_SOURCE']
    profile = tmp_path / 'profile'
    profile.mkdir()
    (profile / 'config.yaml').write_text(
        'toolsets: [github_app, terminal, file, delegation]\n'
        'terminal:\n  backend: docker\n  docker_persist_across_processes: true\n'
    )
    script = r'''
import json, sys
from unittest.mock import Mock
sys.path.insert(0, sys.argv[1])
import model_tools
from hermes_cli.plugins import PluginContext, PluginManifest, get_plugin_manager
from tools.registry import registry
from hermes_github_app import plugin

manager = get_plugin_manager()
blocked = set()
def security_hook(tool_name=None, **kwargs):
    if tool_name in blocked:
        return {"action": "block", "message": "existing security hook"}
    return None
manager._hooks.setdefault("pre_tool_call", []).append(security_hook)
service = Mock()
service.execute.return_value = {"ok": True, "data": {"name": "demo"}}
plugin.GitHubClient = Mock()
plugin.GitHubService = Mock(return_value=service)
ctx = PluginContext(PluginManifest(name="hermes-github-app"), manager)
plugin.register(ctx)
assert registry.get_entry("github_repo_get") is not None
assert registry.get_entry("github_app_action") is None
from hermes_github_app.actions import ACTIONS
assert len(ACTIONS) == 24
assert all(registry.get_entry("github_" + name) is not None for name in ACTIONS)
assert all(registry.get_entry(name) is None for name in ACTIONS)
inline = {"repo": "acme/demo", "number": 1, "body": "Review", "commit_id": "a" * 40,
          "path": "src.py", "line": 8, "side": "RIGHT", "start_line": 4, "start_side": "RIGHT"}
for field in ("line", "start_line"):
    for value in ("4", True):
        before = service.execute.call_count
        bad = dict(inline, **{field: value})
        rejected = model_tools.handle_function_call("github_pr_review_comment", bad, task_id="default", session_id="native-test", tool_call_id="bad-inline-" + field)
        assert json.loads(rejected)["code"] == "invalid_arguments", rejected
        assert service.execute.call_count == before
accepted = model_tools.handle_function_call("github_pr_review_comment", inline, task_id="default", session_id="native-test", tool_call_id="good-inline")
assert json.loads(accepted)["ok"], accepted
assert service.execute.call_args.args == ("pr_review_comment", "acme/demo", {k: v for k, v in inline.items() if k != "repo"})
for name, args in [("github_issue_labels_add", {"repo": "acme/demo", "number": 1, "labels": ["분류/bug"]}),
                   ("github_issue_label_remove", {"repo": "acme/demo", "number": 1, "label": "분류/bug"})]:
    accepted = model_tools.handle_function_call(name, args, task_id="default", session_id="native-test", tool_call_id=name)
    assert json.loads(accepted)["ok"], accepted
    assert service.execute.call_args.args[0] == name.removeprefix("github_")
    for field, value in (("number", "1"), ("number", True), ("labels", '["bug"]')) if "labels" in args else (("number", "1"), ("number", True)):
        before = service.execute.call_count
        rejected = model_tools.handle_function_call(name, dict(args, **{field: value}), task_id="default", session_id="native-test", tool_call_id="bad-label")
        assert json.loads(rejected)["code"] == "invalid_arguments", rejected
        assert service.execute.call_count == before
label_create = {"repo": "Acme/Demo", "name": "분류/bug", "color": "AABBCC", "description": ""}
accepted = model_tools.handle_function_call("github_label_create", label_create, task_id="default", session_id="native-test", tool_call_id="create-label")
assert json.loads(accepted)["ok"], accepted
assert service.execute.call_args.args == ("label_create", "acme/demo", {key: value for key, value in label_create.items() if key != "repo"})
for field, value in (("name", " bug"), ("color", "#aabbcc"), ("description", "x" * 101), ("url", "https://evil.invalid")):
    before = service.execute.call_count
    rejected = model_tools.handle_function_call("github_label_create", dict(label_create, **{field: value}), task_id="default", session_id="native-test", tool_call_id="bad-create-label")
    assert json.loads(rejected)["code"] == "invalid_arguments", rejected
    assert service.execute.call_count == before
new_operations = [("github_pr_update_body", {"repo":"acme/demo","number":1,"body":""})]
new_operations += [("github_" + name, {"repo":"acme/demo","comment_id":2**53 + 1}) for name in
                   ("issue_comment_get","issue_comment_reaction","pr_review_comment_get","pr_review_comment_reaction")]
for name, args in new_operations:
    accepted = model_tools.handle_function_call(name, args, task_id="default", session_id="native-test", tool_call_id=name)
    assert json.loads(accepted)["ok"], accepted
    assert service.execute.call_args.args == (name.removeprefix("github_"), "acme/demo", {key:value for key,value in args.items() if key != "repo"})
    before = service.execute.call_count
    rejected = model_tools.handle_function_call(name, dict(args, url="https://evil.invalid"), task_id="default", session_id="native-test", tool_call_id="invalid-new-override")
    assert json.loads(rejected)["code"] == "invalid_arguments", rejected
    assert service.execute.call_count == before
    integer_field = "comment_id" if "comment_id" in args else "number"
    for value in ("1", True):
        before = service.execute.call_count
        rejected = model_tools.handle_function_call(name, dict(args, **{integer_field:value}), task_id="default", session_id="native-test", tool_call_id="invalid-new-int")
        assert json.loads(rejected)["code"] == "invalid_arguments", rejected
        assert service.execute.call_count == before
blocked.add("execute_code")
denied = model_tools.handle_function_call("execute_code", {"code": "1"}, task_id="default", session_id="native-test", tool_call_id="blocked-code")
assert "existing security hook" in denied
args = {"repo": "acme/demo"}
result = json.loads(model_tools.handle_function_call("github_repo_get", args, task_id="default", session_id="native-test", tool_call_id="call-1"))
assert result["ok"], result
for tool, bad in [("github_issue_get", {"repo": "acme/demo", "number": "42"}), ("github_pr_create", {"repo": "acme/demo", "title": "t", "base": "main", "head": "feature", "draft": "false"}), ("github_repo_get", {"repo": "acme/demo", "action": "repo_get"})]:
    before = service.execute.call_count
    rejected = model_tools.handle_function_call(tool, bad, task_id="default", session_id="native-test", tool_call_id="bad-" + tool)
    assert json.loads(rejected)["code"] == "invalid_arguments", rejected
    assert service.execute.call_count == before
accepted = model_tools.handle_function_call("github_issue_get", {"repo": "acme/demo", "number": 42}, task_id="default", session_id="native-test", tool_call_id="good-int")
assert json.loads(accepted)["ok"], accepted
assert service.execute.call_args.args == ("issue_get", "acme/demo", {"number": 42})
blocked.add("github_repo_get")
before = service.execute.call_count
hooked = model_tools.handle_function_call("github_repo_get", args, task_id="default", session_id="native-test", tool_call_id="hook-block")
assert "existing security hook" in hooked
assert service.execute.call_count == before
# Exercise the real public nested dispatcher and native task context forwarding.
import base64, hashlib
terminal_contexts = []
def terminal_reader(args, **kwargs):
    terminal_contexts.append(kwargs)
    payload = b"test bundle transport"
    return json.dumps({"exit_code": 0, "output": json.dumps({"identity": [1,2,len(payload),4,5], "offset": 0, "data": base64.b64encode(payload).decode(), "sha256": hashlib.sha256(payload).hexdigest()})})
registry.register(name="terminal", toolset="terminal", schema={"name":"terminal", "parameters":{"type":"object","properties":{}}}, handler=terminal_reader, override=True)
path_args = {"repo":"acme/demo", "branch":"feature", "commit_sha":"a"*40, "expected_head_sha":None, "bundle_path":"/sandbox/upload.bundle"}
published = json.loads(model_tools.handle_function_call("github_git_push", path_args, task_id="native-push-task", session_id="native-push-session", tool_call_id="native-push"))
assert published["ok"], published
assert terminal_contexts and terminal_contexts[0]["task_id"] == "native-push-task", terminal_contexts
assert service.execute.call_args.args[2]["bundle_base64"] == base64.b64encode(b"test bundle transport").decode()
assert "bundle_path" not in service.execute.call_args.args[2]
print("Public registration kept strict arguments and an existing security hook")
'''
    env = {'HOME': os.environ['HOME'], 'PATH': os.environ.get('PATH', ''),
           'HERMES_HOME': str(profile), 'HERMES_GITHUB_APP_CONFIG': str(configuration)}
    result = subprocess.run([sys.executable, '-c', script, source], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout


def test_twenty_four_flat_tools_are_registered_with_distinct_handlers(configuration, monkeypatch):
    from hermes_github_app.actions import ACTIONS, PARAMETER_FIELDS
    monkeypatch.setattr(plugin, 'GitHubClient', Mock())
    ctx = Mock()
    plugin.register(ctx)
    registrations = {call.kwargs['name']: call.kwargs for call in ctx.register_tool.call_args_list}
    assert set(registrations) == {'github_' + action for action in ACTIONS}
    assert len({id(item['handler']) for item in registrations.values()}) == 24
    for action in ACTIONS:
        item = registrations['github_' + action]
        assert item['schema']['name'] == 'github_' + action
        assert item['toolset'] == 'github_app'
        schema = item['schema']['parameters']
        required, optional = PARAMETER_FIELDS[action]
        assert set(schema['properties']) == {'repo', *required, *optional}
        assert set(schema['required']) == {'repo', *required}
        assert schema['additionalProperties'] is False
        assert 'action' not in schema['properties'] and 'params' not in schema['properties']
    assert registrations['github_issue_get']['schema']['parameters']['properties']['number'] == {'anyOf': [{'type': 'integer', 'minimum': 1, 'maximum': 2**31-1}]}
    assert registrations['github_pr_create']['schema']['parameters']['properties']['draft'] == {'anyOf': [{'type': 'boolean'}]}


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


def test_version_one_registers_inline_tool_with_strict_flat_schema(configuration,monkeypatch):
    from hermes_github_app.actions import ACTIONS
    monkeypatch.setattr(plugin,'GitHubClient',Mock())
    service=Mock();monkeypatch.setattr(plugin,'GitHubService',Mock(return_value=service))
    ctx=Mock();plugin.register(ctx)
    registered={call.kwargs['name']:call.kwargs for call in ctx.register_tool.call_args_list}
    assert set(registered)=={'github_' + action for action in ACTIONS}
    item=registered['github_pr_review_comment'];schema=item['schema']['parameters']
    assert set(schema['required'])=={'repo','number','body','commit_id','path','line','side'}
    for name in ('line','start_line'):
        assert schema['properties'][name]=={'anyOf':[{'type':'integer','minimum':1,'maximum':2**31-1}]}
    for name in ('side','start_side'):
        assert schema['properties'][name]['enum']==['LEFT','RIGHT']
    assert schema['additionalProperties'] is False
    args={'repo':'acme/demo','number':1,'body':'Comment','commit_id':'a'*40,'path':'src.py','line':True,'side':'RIGHT'}
    result=json.loads(item['handler'](args))
    assert result['code']=='invalid_arguments'
    service.execute.assert_not_called()


def test_prefixed_handlers_apply_unprefixed_policy_before_client_access(configuration, monkeypatch):
    configuration.write_text(configuration.read_text() + '  allow_actions: [issue_comment]\n  deny_actions: [pr_merge]\n')
    client = Mock()
    session = client.session.return_value
    session.repo = 'acme/demo'
    session.execute.return_value = {'id': 7}
    monkeypatch.setattr(plugin, 'GitHubClient', Mock(return_value=client))
    ctx = Mock()
    plugin.register(ctx)
    handlers = {call.kwargs['name']: call.kwargs['handler'] for call in ctx.register_tool.call_args_list}
    assert json.loads(handlers['github_issue_comment']({'repo': 'acme/demo', 'number': 1, 'body': 'Comment'}))['ok']
    assert session.execute.call_args.args[0] == 'issue_comment'
    client.session.reset_mock()
    for tool, args in [
        ('github_issue_comment', {'repo': 'excluded/demo', 'number': 1, 'body': 'Comment'}),
        ('github_pr_merge', {'repo': 'acme/demo', 'number': 1, 'expected_head_sha': 'a' * 40, 'merge_method': 'squash'}),
    ]:
        assert json.loads(handlers[tool](args))['code'] == 'policy_denied'
    client.session.assert_not_called()


def test_label_schemas_and_handlers_preserve_strict_types(configuration, monkeypatch):
    service=Mock();service.execute.return_value={'ok':True,'data':{}}
    monkeypatch.setattr(plugin,'GitHubClient',Mock())
    monkeypatch.setattr(plugin,'GitHubService',Mock(return_value=service))
    ctx=Mock();plugin.register(ctx)
    registrations={call.kwargs['name']:call.kwargs for call in ctx.register_tool.call_args_list}
    for action,params in [('issue_labels_add',{'number':1,'labels':['분류 /?#%']}),
                          ('issue_label_remove',{'number':1,'label':'분류 /?#%'})]:
        entry=registrations['github_'+action]
        schema=entry['schema']['parameters']
        assert schema['additionalProperties'] is False
        assert schema['properties']['number']['anyOf'][0]['type']=='integer'
        if action.endswith('_add'):
            assert schema['properties']['labels']['anyOf'][0]=={'type':'array','minItems':1,'maxItems':100,
                'uniqueItems':True,'items':{'type':'string','minLength':1,'maxLength':50}}
        assert json.loads(entry['handler']({'repo':'Acme/Demo',**params}))['ok']
        assert service.execute.call_args.args==(action,'acme/demo',params)
        before=service.execute.call_count
        invalid={'labels':'["bug"]'} if action.endswith('_add') else {'label':False}
        assert json.loads(entry['handler']({'repo':'acme/demo',**params,**invalid}))['code']=='invalid_arguments'
        assert before==service.execute.call_count


@pytest.mark.parametrize('failure_stage',['isolation','client','service'])
def test_shared_startup_failure_closes_created_resources_and_sanitizes(configuration,monkeypatch,caplog,failure_stage):
    from hermes_github_app.isolation import IsolationError
    boundary=Mock()
    client=Mock()
    monkeypatch.setattr(plugin,'HostBoundary',Mock(return_value=boundary))
    monkeypatch.setattr(plugin,'GitHubClient',Mock(return_value=client))
    if failure_stage=='isolation':boundary.check.side_effect=IsolationError('private-host-detail')
    elif failure_stage=='client':plugin.GitHubClient.side_effect=RuntimeError('private-host-detail')
    else:monkeypatch.setattr(plugin,'GitHubService',Mock(side_effect=RuntimeError('private-host-detail')))
    assert plugin._open_host_service() is None
    boundary.close.assert_called_once_with()
    if failure_stage=='service':client.close.assert_called_once_with()
    else:client.close.assert_not_called()
    assert 'private-host-detail' not in caplog.text


def test_public_manifest_names_match_catalog():
    from ruamel.yaml import YAML
    from hermes_github_app.actions import ACTIONS
    manifest=YAML(typ='safe').load((Path(__file__).resolve().parents[1]/'plugin.yaml').read_text())
    assert set(manifest['provides_tools'])=={'github_'+action for action in ACTIONS}
    assert len(manifest['provides_tools'])==len(ACTIONS)


def test_label_create_registered_handler_forwards_arguments(configuration, monkeypatch):
    service = Mock()
    service.execute.return_value = {'ok': True, 'data': {}}
    monkeypatch.setattr(plugin, 'GitHubClient', Mock())
    monkeypatch.setattr(plugin, 'GitHubService', Mock(return_value=service))
    ctx = Mock()
    plugin.register(ctx)
    registrations = {call.kwargs['name']: call.kwargs for call in ctx.register_tool.call_args_list}
    entry = registrations['github_label_create']
    schema = entry['schema']['parameters']
    assert schema['additionalProperties'] is False
    assert set(schema['required']) == {'repo', 'name', 'color'}
    params = {'name': '분류 /?#%', 'color': 'AABBCC', 'description': ''}
    assert json.loads(entry['handler']({'repo': 'Acme/Demo', **params}))['ok']
    assert service.execute.call_args.args == ('label_create', 'acme/demo', params)
    for invalid in ({'name': False}, {'name': ' bug'}, {'color': 123456}, {'description': None}, {'number': 1}):
        before = service.execute.call_count
        assert json.loads(entry['handler']({'repo': 'acme/demo', **params, **invalid}))['code'] == 'invalid_arguments'
        assert service.execute.call_count == before
