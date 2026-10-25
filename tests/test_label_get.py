"""Named label lookup observes current state without retrying mutations."""
import json
from unittest.mock import Mock
from urllib.parse import quote

import httpx
import pytest

from hermes_github_app.actions import build_request, validate_params
from hermes_github_app.client import ClientError
from hermes_github_app.policy import Policy
from hermes_github_app.service import GitHubService
from test_client import API, key_file

NAME = '분류 /?#%'
LABEL = {'id': 7, 'name': NAME, 'color': 'AaBbCc', 'description': None}


def policy(access='read', **extra):
    return Policy.from_dict({'repositories': {'mode': 'all', 'exclude': []},
                             'default_access': access, **extra})


def test_lookup_scoped_auth_encoding_and_minimal_result(key_file):
    api = API(key_file, {'/labels/' + NAME: {**LABEL, 'url': 'https://example.test', 'extra': 'hidden'}})
    result = api.run('label_get', {'name': NAME})
    assert result == {'exists': True, **LABEL, 'description': ''}
    assert json.loads(api.calls[0].content)['permissions'] == {'issues': 'read'}
    assert len(api.calls) == 4
    request = api.calls[-1]
    assert request.method == 'GET'
    assert request.url.raw_path == ('/repos/acme/demo/labels/' + quote(NAME, safe='')).encode()
    assert request.url.query == b'' and request.url.fragment == ''


def test_existing_label_whitespace_and_case_are_preserved(key_file):
    name = ' Bug '
    assert validate_params('label_get', {'name': name}) == {'name': name}
    request = build_request('label_get', 'Acme/Demo', {'name': name})
    assert request.path == '/repos/acme/demo/labels/%20Bug%20'
    label = {**LABEL, 'name': ' bug ', 'description': 'Existing description'}
    api = API(key_file, {'/labels/' + name: label})
    assert api.run('label_get', {'name': name}) == {'exists': True, **label}


def test_only_label_endpoint_404_is_absent(key_file):
    api = API(key_file)
    result = GitHubService(policy(allow_actions=['label_get']), api.client).execute(
        'label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert result == {'ok': True, 'data': {'exists': False}}
    assert len(api.calls) == 4


@pytest.mark.parametrize('stage', [
    '/app/installations/34/access_tokens', '/installation/repositories', '/repos/acme/demo',
])
def test_prerequisite_404_never_becomes_absent(key_file, stage):
    class FailingAPI(API):
        def handle(self, req):
            if req.url.path == stage:
                self.calls.append(req)
                return httpx.Response(404, text='secret-token')
            return super().handle(req)
    api = FailingAPI(key_file)
    result = GitHubService(policy(allow_actions=['label_get']), api.client).execute(
        'label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert result['ok'] is False and result['code'] == 'github_denied'
    assert 'exists' not in result and 'secret-token' not in str(result)
    assert not any('/labels/' in call.url.path for call in api.calls)


@pytest.mark.parametrize('metadata', [{'full_name': 'other/demo'}, {},
    httpx.Response(301, headers={'location': 'https://example.test'})])
def test_canonical_check_precedes_lookup(key_file, metadata):
    api = API(key_file, {'': metadata})
    with pytest.raises(ClientError):
        api.run('label_get', {'name': NAME})
    assert len(api.calls) == 3


@pytest.mark.parametrize('field,value', [
    ('name', ''), ('name', ' '), ('name', '.'), ('name', '..'), ('name', 'x'*51),
    ('name', 'x\n'), ('name', '\ud800'), ('name', False), ('name', None),
    ('color', 'aabbcc'), ('number', 1), ('url', 'https://example.test'), ('token', 'secret'),
])
def test_invalid_lookup_arguments_never_authenticate(field, value):
    client = Mock()
    result = GitHubService(policy(allow_actions=['label_get']), client).execute(
        'label_get', 'acme/demo', {'name': NAME, field: value}, recheck_isolation=lambda: None)
    assert result['code'] == 'invalid_arguments'
    client.session.assert_not_called()


@pytest.mark.parametrize('access', ['read', 'write'])
def test_profiles_do_not_grant_lookup(access):
    client = Mock()
    result = GitHubService(policy(access), client).execute(
        'label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert result['code'] == 'policy_denied'
    client.session.assert_not_called()


@pytest.mark.parametrize('extra', [
    {'allow_actions': ['label_create', 'issue_labels_add']},
    {'allow_actions': ['label_get'], 'deny_actions': ['label_get']},
    {'allow_actions': ['label_get'], 'repository_rules': {'acme/demo': {'deny_actions': ['label_get']}}},
    {'deny_actions': ['label_get'], 'repository_rules': {'acme/demo': {'allow_actions': ['label_get']}}},
    {'allow_actions': ['label_get'], 'repositories': {'mode': 'all', 'exclude': ['acme/demo']}},
])
def test_lookup_denials_precede_authentication(extra):
    client = Mock()
    result = GitHubService(policy(**extra), client).execute(
        'label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert result['code'] == 'policy_denied'
    client.session.assert_not_called()


@pytest.mark.parametrize('response', [
    httpx.Response(200, json=None), httpx.Response(200, json=[]), httpx.Response(204),
    httpx.Response(201, json=LABEL), httpx.Response(200, text='invalid-json secret-token'),
    httpx.Response(403, text='secret-token'), httpx.Response(429), httpx.Response(500),
    httpx.Response(302, headers={'location': 'https://example.test'}),
    httpx.ReadTimeout('secret-token'),
    *[httpx.Response(200, json={**LABEL, **change}) for change in [
        {'id': False}, {'id': 0}, {'name': 'other'}, {'name': None},
        {'color': '#aabbcc'}, {'color': 'aabbcc\n'}, {'description': False},
        {'repository': {'full_name': 'other/demo'}},
    ]],
    httpx.Response(200, json={key: value for key, value in LABEL.items() if key != 'description'}),
])
def test_lookup_failures_are_errors_not_absence_and_never_retry(key_file, response):
    api = API(key_file, {'/labels/' + NAME: response})
    result = GitHubService(policy(allow_actions=['label_get']), api.client).execute(
        'label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert result['ok'] is False and 'exists' not in result
    assert result['code'] != 'uncertain_outcome'
    assert 'secret-token' not in str(result)
    assert len(api.calls) == 4
    assert api.calls[-1].method == 'GET'


@pytest.mark.parametrize('present', [True, False])
def test_uncertain_create_then_lookup_never_repeats_creation(key_file, present):
    api = API(key_file, {('POST', '/labels'): httpx.ReadTimeout('timeout'),
                        '/labels/' + NAME: LABEL if present else httpx.Response(404)})
    service = GitHubService(policy(allow_actions=['label_create', 'label_get']), api.client)
    created = service.execute('label_create', 'acme/demo',
                              {'name': NAME, 'color': 'aabbcc'}, recheck_isolation=lambda: None)
    assert created['code'] == 'uncertain_outcome'
    observed = service.execute('label_get', 'acme/demo', {'name': NAME}, recheck_isolation=lambda: None)
    assert observed['ok'] is True and observed['data']['exists'] is present
    assert len(api.calls) == 8
    assert sum(call.method == 'POST' and call.url.path.endswith('/labels') for call in api.calls) == 1


def test_lookup_redacts_returned_metadata(key_file):
    api = API(key_file, {'/labels/' + NAME: {**LABEL, 'description': 'secret-token'}})
    assert api.run('label_get', {'name': NAME})['description'] == '[REDACTED]'


@pytest.mark.parametrize('permissions,scope,call_count', [
    ({'issues': 'write'}, None, 1),
    ({'metadata': 'read'}, None, 1),
    (None, {'total_count': 1, 'repositories': [{'full_name': 'other/demo'}]}, 2),
])
def test_lookup_scope_verification_precedes_label_request(key_file, permissions, scope, call_count):
    api = API(key_file, permissions=permissions, scope=scope)
    with pytest.raises(ClientError):
        api.run('label_get', {'name': NAME})
    assert len(api.calls) == call_count
    assert not any('/labels/' in call.url.path for call in api.calls)


def test_missing_response_preserves_status_and_existing_missing_ref_behavior(key_file):
    api = API(key_file)
    session = api.client.session('acme/demo', {'contents': 'read'})
    response = session.request('GET', '/git/ref/heads/missing', missing=True)
    assert response.status_code == 404 and response.data is None
    assert session.ref('heads', 'missing', missing=True) is None
    with pytest.raises(ClientError) as caught:
        session.ref('heads', 'missing')
    assert caught.value.code == 'github_denied'
