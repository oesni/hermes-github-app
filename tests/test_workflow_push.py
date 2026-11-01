"""Workflow token access requires both a caller opt-in and an operator grant."""
from unittest.mock import Mock

import pytest

from hermes_github_app import git_push
from hermes_github_app.client import ClientError
from hermes_github_app.plugin import _execute_host_operation, tool_schema
from hermes_github_app.policy import Policy, PolicyError
from hermes_github_app.service import GitHubService


def make_policy(allow, deny=()):
    return Policy.from_dict({'repositories': {'mode': 'all', 'exclude': []},
                             'default_access': 'write', 'allow_actions': list(allow),
                             'deny_actions': list(deny)})


def invoke(monkeypatch, policy, flag=None):
    monkeypatch.setattr(git_push, 'require_supported_host', lambda: None)
    publish = Mock(side_effect=lambda session, params, recheck: (recheck(), {'sha': params['commit_sha']})[1])
    monkeypatch.setattr(git_push, 'publish', publish)
    client = Mock()
    client.session.return_value.repo = 'acme/demo'
    params = {'branch': 'feature', 'commit_sha': 'a' * 40,
              'expected_head_sha': None, 'bundle_base64': 'YQ=='}
    if flag is not None:
        params['workflow_write'] = flag
    result = GitHubService(policy, client).execute('git_push', 'acme/demo', params,
                                                   recheck_isolation=lambda: None)
    return result, client, publish


@pytest.mark.parametrize('flag', [None, False])
def test_ordinary_push_never_requests_workflow_access(monkeypatch, flag):
    result, client, publish = invoke(monkeypatch, make_policy(['git_push', 'git_push_workflows']), flag)
    assert result['ok']
    client.session.assert_called_once_with('acme/demo', {'contents': 'write'})
    publish.assert_called_once()


def test_workflow_push_requires_separate_explicit_grant(monkeypatch):
    for policy in (make_policy(['git_push']),
                   make_policy(['git_push', 'git_push_workflows'], ['git_push_workflows']),
                   make_policy(['git_push_workflows'])):
        result, client, publish = invoke(monkeypatch, policy, True)
        assert result['code'] == 'policy_denied'
        client.session.assert_not_called()
        publish.assert_not_called()


def test_workflow_push_requests_only_required_extra_permission(monkeypatch):
    result, client, publish = invoke(monkeypatch, make_policy(['git_push', 'git_push_workflows']), True)
    assert result['ok']
    client.session.assert_called_once_with('acme/demo', {'contents': 'write', 'workflows': 'write'})
    publish.assert_called_once()


@pytest.mark.parametrize('bad', ['true', 1, [], {}])
def test_workflow_flag_must_be_boolean(monkeypatch, bad):
    result, client, publish = invoke(monkeypatch, make_policy(['git_push', 'git_push_workflows']), bad)
    assert result['code'] == 'invalid_arguments'
    client.session.assert_not_called()
    publish.assert_not_called()


def test_workflow_permission_checked_again_before_mutation(monkeypatch):
    base = make_policy(['git_push', 'git_push_workflows'])
    policy = Mock(wraps=base)
    def check(repo, action):
        if action == 'git_push_workflows' and policy.authorize.call_count > 4:
            raise PolicyError('revoked')
        return base.authorize(repo, action)
    policy.authorize.side_effect = check
    result, _, _ = invoke(monkeypatch, policy, True)
    assert result['code'] == 'policy_denied'


def test_workflow_capability_is_not_a_tool():
    from hermes_github_app.actions import ACTIONS
    assert 'git_push_workflows' not in ACTIONS
    assert tool_schema('git_push')['parameters']['properties']['workflow_write'] == {'anyOf': [{'type': 'boolean'}]}


def test_workflow_scope_is_checked_against_github_canonical_repository(monkeypatch):
    monkeypatch.setattr(git_push, 'require_supported_host', lambda: None)
    publish = Mock()
    monkeypatch.setattr(git_push, 'publish', publish)
    policy = Policy.from_dict({
        'repositories': {'mode': 'all', 'exclude': []}, 'default_access': 'write',
        'allow_actions': ['git_push'],
        'repository_rules': {'acme/demo': {'allow_actions': ['git_push_workflows']}},
    })
    client = Mock()
    client.session.return_value.repo = 'acme/other'
    params = {'branch': 'feature', 'commit_sha': 'a' * 40, 'expected_head_sha': None,
              'bundle_base64': 'YQ==', 'workflow_write': True}
    result = GitHubService(policy, client).execute('git_push', 'acme/demo', params,
                                                   recheck_isolation=lambda: None)
    assert result['code'] == 'policy_denied'
    publish.assert_not_called()


def test_repository_deny_wins_over_global_workflow_allowance(monkeypatch):
    policy = Policy.from_dict({
        'repositories': {'mode': 'all', 'exclude': []}, 'default_access': 'write',
        'allow_actions': ['git_push', 'git_push_workflows'],
        'repository_rules': {'acme/demo': {'deny_actions': ['git_push_workflows']}},
    })
    result, client, publish = invoke(monkeypatch, policy, True)
    assert result['code'] == 'policy_denied'
    client.session.assert_not_called()
    publish.assert_not_called()


def test_workflow_policy_denial_precedes_sandbox_bundle_read(monkeypatch):
    read = Mock()
    monkeypatch.setattr('hermes_github_app.plugin.resolve_bundle_path', read)
    service = Mock()
    service.policy = make_policy(['git_push'])
    result = _execute_host_operation(Mock(), service, 'git_push', {
        'repo': 'acme/demo', 'branch': 'feature', 'commit_sha': 'a' * 40,
        'expected_head_sha': None, 'bundle_path': '/workspace/push.bundle',
        'workflow_write': True,
    })
    assert result['code'] == 'policy_denied'
    read.assert_not_called()
    service.execute.assert_not_called()


def test_workflow_token_denial_never_falls_back_to_contents_only(monkeypatch):
    monkeypatch.setattr(git_push, 'require_supported_host', lambda: None)
    client = Mock()
    client.session.side_effect = ClientError('Denied.', 'github_denied')
    result = GitHubService(make_policy(['git_push', 'git_push_workflows']), client).execute(
        'git_push', 'acme/demo', {'branch': 'feature', 'commit_sha': 'a' * 40,
                                  'expected_head_sha': None, 'bundle_base64': 'YQ==',
                                  'workflow_write': True}, recheck_isolation=lambda: None)
    assert result['code'] == 'github_denied'
    client.session.assert_called_once_with('acme/demo', {'contents': 'write', 'workflows': 'write'})


def test_explicit_null_workflow_flag_is_rejected(monkeypatch):
    monkeypatch.setattr(git_push, 'require_supported_host', lambda: None)
    client = Mock()
    result = GitHubService(make_policy(['git_push', 'git_push_workflows']), client).execute(
        'git_push', 'acme/demo', {'branch': 'feature', 'commit_sha': 'a' * 40,
                                  'expected_head_sha': None, 'bundle_base64': 'YQ==',
                                  'workflow_write': None}, recheck_isolation=lambda: None)
    assert result['code'] == 'invalid_arguments'
    client.session.assert_not_called()
