"""Repository label creation uses closed, explicitly granted operations."""
import json
from unittest.mock import Mock

import httpx
import pytest

from hermes_github_app.actions import ActionError, build_request, validate_params
from hermes_github_app.client import ClientError
from hermes_github_app.plugin import _execute_host_operation, tool_schema
from hermes_github_app.policy import Policy
from hermes_github_app.service import GitHubService
from test_client import API, key_file

PARAMS = {'name': '분류 /?#%', 'color': 'aabbcc', 'description': 'A label'}
LABEL = {'id': 7, **PARAMS}


def policy(access='read', **extra):
    return Policy.from_dict({'repositories': {'mode': 'all', 'exclude': []},
                             'default_access': access, **extra})


def test_exact_creation_request_and_minimal_result(key_file):
    api = API(key_file, {('POST', '/labels'): httpx.Response(201, json={
        **LABEL, 'url': 'https://example.test/private', 'extra': 'hidden'})})
    result = api.run('label_create', {**PARAMS, 'color': 'AaBbCc'})
    assert result == LABEL
    assert json.loads(api.calls[0].content)['permissions'] == {'issues': 'write'}
    assert len(api.calls) == 4
    assert api.calls[-1].method == 'POST'
    assert api.calls[-1].url.path == '/repos/acme/demo/labels'
    assert json.loads(api.calls[-1].content) == PARAMS


def test_optional_description_is_empty_and_name_is_literal(key_file):
    params = {'name': ' X😀 ', 'color': 'FF0099'}
    expected = {'name': ' X😀 ', 'color': 'ff0099', 'description': ''}
    assert validate_params('label_create', params) == expected
    request = build_request('label_create', 'Acme/Demo', params)
    assert request.body == expected and request.path == '/repos/acme/demo/labels'
    api = API(key_file, {('POST', '/labels'): httpx.Response(201, json={'id': 1, **expected})})
    assert api.run('label_create', params) == {'id': 1, **expected}


@pytest.mark.parametrize('field,value', [
    ('name', ''), ('name', ' '), ('name', '.'), ('name', '..'), ('name', 'a'*51),
    ('name', 'a\n'), ('name', '\ud800'), ('name', True), ('name', None),
    ('color', '#aabbcc'), ('color', 'abc'), ('color', 'aabbccd'), ('color', 'gg0000'),
    ('color', 'aabbcc\n'), ('color', 123456), ('color', None),
    ('description', 'a'*101), ('description', 'a\n'), ('description', '\0'),
    ('description', '\udfff'), ('description', None), ('description', False),
    ('number', 1), ('repo', 'other/repo'), ('url', 'https://example.test'),
    ('permissions', {'issues': 'write'}), ('token', 'secret'), ('method', 'PATCH'),
])
def test_invalid_arguments_refuse_before_authentication(field, value):
    client = Mock()
    result = GitHubService(policy(allow_actions=['label_create']), client).execute(
        'label_create', 'acme/demo', {**PARAMS, field: value}, recheck_isolation=lambda: None)
    assert result['code'] == 'invalid_arguments'
    client.session.assert_not_called()


@pytest.mark.parametrize('field', ['name', 'color'])
def test_required_fields(field):
    params = dict(PARAMS)
    del params[field]
    with pytest.raises(ActionError):
        validate_params('label_create', params)


def test_boundary_lengths():
    params = {'name': '😀'*50, 'color': 'ABCDEF', 'description': '가'*100}
    assert validate_params('label_create', params) == {**params, 'color': 'abcdef'}


@pytest.mark.parametrize('access', ['read', 'write'])
def test_profiles_do_not_grant_creation(access):
    client = Mock()
    result = GitHubService(policy(access), client).execute(
        'label_create', 'acme/demo', PARAMS, recheck_isolation=lambda: None)
    assert result['code'] == 'policy_denied'
    client.session.assert_not_called()


@pytest.mark.parametrize('extra', [
    {'allow_actions': ['label_create'], 'deny_actions': ['label_create']},
    {'allow_actions': ['label_create'], 'repository_rules': {'acme/demo': {'deny_actions': ['label_create']}}},
    {'deny_actions': ['label_create'], 'repository_rules': {'acme/demo': {'allow_actions': ['label_create']}}},
    {'allow_actions': ['issue_labels_add', 'issue_label_remove']},
    {'allow_actions': ['label_create'], 'repositories': {'mode': 'all', 'exclude': ['acme/demo']}},
    {'allow_actions': ['label_create'], 'repositories': {'mode': 'allowlist', 'allow': ['other/repo'], 'exclude': []}},
])
def test_denials_and_repository_selection_win(extra):
    client = Mock()
    result = GitHubService(policy(**extra), client).execute(
        'label_create', 'acme/demo', PARAMS, recheck_isolation=lambda: None)
    assert result['code'] == 'policy_denied'
    client.session.assert_not_called()


def test_repository_local_allow_and_host_checks(key_file):
    api = API(key_file, {('POST', '/labels'): httpx.Response(201, json=LABEL)})
    p = policy(repository_rules={'acme/demo': {'allow_actions': ['label_create']}})
    runtime = Mock()
    result = _execute_host_operation(runtime, GitHubService(p, api.client),
                                     'label_create', {'repo': 'Acme/Demo', **PARAMS})
    assert result == {'ok': True, 'data': LABEL}
    assert runtime.check.call_count == 2


@pytest.mark.parametrize('metadata', [
    {'full_name': 'other/demo'}, {},
    httpx.Response(301, headers={'location': 'https://api.github.com/repos/other/demo'}),
])
def test_canonical_target_mismatch_never_mutates(key_file, metadata):
    api = API(key_file, {'': metadata})
    with pytest.raises(ClientError):
        api.run('label_create', PARAMS)
    assert len(api.calls) == 3
    assert not any(call.url.path.endswith('/labels') for call in api.calls)


@pytest.mark.parametrize('failure,code', [
    (httpx.Response(422, text='secret-token duplicate'), 'github_denied'),
    (httpx.Response(403, text='secret-token'), 'github_denied'),
    (httpx.Response(404), 'github_denied'),
    (httpx.Response(302, headers={'location': 'https://example.test'}), 'github_denied'),
    (httpx.Response(503), 'uncertain_outcome'),
    (httpx.ReadTimeout('secret-token'), 'uncertain_outcome'),
    (httpx.Response(201, text='secret-token invalid json'), 'uncertain_outcome'),
    (httpx.Response(200, json=LABEL), 'uncertain_outcome'),
    (httpx.Response(202, json=LABEL), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'id': True}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'id': 0}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'name': 'other'}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'color': 'ff0000'}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'color': None}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'description': None}), 'uncertain_outcome'),
    (httpx.Response(201, json={**LABEL, 'repository': {'full_name': 'other/demo'}}), 'uncertain_outcome'),
])
def test_denied_or_uncertain_creation_never_retries_or_updates(key_file, failure, code):
    api = API(key_file, {('POST', '/labels'): failure})
    with pytest.raises(ClientError) as caught:
        api.run('label_create', PARAMS)
    assert caught.value.code == code
    assert 'secret-token' not in str(caught.value)
    assert len(api.calls) == 4
    assert sum(call.url.path.endswith('/labels') for call in api.calls) == 1
    assert not any(call.method in {'PATCH', 'DELETE'} for call in api.calls)


def test_secret_redaction_on_allowed_fields(key_file):
    params = {**PARAMS, 'description': 'secret-token'}
    api = API(key_file, {('POST', '/labels'): httpx.Response(201, json={'id': 1, **params})})
    assert api.run('label_create', params)['description'] == '[REDACTED]'


def test_schema_exposes_only_creation_fields():
    schema = tool_schema('label_create')
    assert schema['name'] == 'github_label_create'
    params = schema['parameters']
    assert set(params['required']) == {'repo', 'name', 'color'}
    assert set(params['properties']) == {'repo', 'name', 'color', 'description'}
    assert params['additionalProperties'] is False
    assert params['properties']['name']['maxLength'] == 50
    assert params['properties']['color']['pattern'] == '^[a-fA-F0-9]{6}$'
    assert params['properties']['description']['maxLength'] == 100
