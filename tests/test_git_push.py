"""Offline integration tests publish real Git objects to disposable bare remotes."""
import base64
import subprocess
import time
from unittest.mock import Mock

import pytest

from git_fixtures import Repository, git
from hermes_github_app.client import ClientError
from hermes_github_app.policy import Policy
from hermes_github_app.service import GitHubService


@pytest.fixture
def repositories(tmp_path):
    return Repository(tmp_path)


@pytest.fixture
def transport(monkeypatch, repositories):
    from hermes_github_app import git_push
    monkeypatch.setattr(git_push, '_remote', lambda repo: str(repositories.remote))
    original = git_push._run
    def local_transport(repo_path, args, *positional, **keywords):
        return original(repo_path, ['-c', 'protocol.file.allow=always', *args], *positional, **keywords)
    monkeypatch.setattr(git_push, '_run', local_transport)
    return git_push


def arguments(repositories, *, branch='feature', expected=None, incremental=False):
    return {'branch': branch, 'commit_sha': repositories.head, 'expected_head_sha': expected,
            'bundle_base64': repositories.bundle(branch, incremental=incremental)}


def session():
    return Mock(repo='acme/demo', token='test-only-installation-secret',
                _token='test-only-installation-secret', deadline=time.monotonic()+120,
                _deadline=time.monotonic()+120)


def test_publish_new_branch_preserves_commit_history_and_binary(transport, repositories):
    result = transport.publish(session(), arguments(repositories), lambda: None)
    assert result == {'branch': 'feature', 'sha': repositories.head,
                      'previous_sha': None, 'created': True}
    assert repositories.remote_head('feature') == repositories.head
    assert repositories.remote_head('main') == repositories.initial
    assert git(repositories.remote, 'show', 'feature:binary.bin') == b'\x00\xff\x80\n'
    assert git(repositories.remote, 'show', 'feature:initial.txt') == b'changed\n'
    assert git(repositories.remote, 'rev-list', 'feature') == git(repositories.work, 'rev-list', 'HEAD')
    assert git(repositories.remote, 'cat-file', 'commit', repositories.head) == git(repositories.work, 'cat-file', 'commit', repositories.head)


@pytest.mark.parametrize('incremental', [False, True])
def test_existing_branch_fast_forward(transport, repositories, incremental):
    params = arguments(repositories, branch='main', expected=repositories.initial, incremental=incremental)
    result = transport.publish(session(), params, lambda: None)
    assert result['created'] is False and result['previous_sha'] == repositories.initial
    assert repositories.remote_head('main') == repositories.head


def test_non_fast_forward_is_rejected(transport, repositories):
    git(repositories.remote, 'update-ref', 'refs/heads/main', repositories.initial)
    git(repositories.work, 'checkout', '--orphan', 'unrelated')
    repositories.head = repositories.commit('other.txt', b'other', 'Unrelated root')
    params = arguments(repositories, branch='main', expected=repositories.initial)
    with pytest.raises(ClientError):
        transport.publish(session(), params, lambda: None)
    assert repositories.remote_head('main') == repositories.initial


def test_stale_expected_head_does_not_overwrite(transport, repositories):
    params = arguments(repositories, branch='main', expected=repositories.initial)
    git(repositories.work, 'push', str(repositories.remote), 'HEAD:refs/heads/main')
    with pytest.raises(ClientError) as error:
        transport.publish(session(), params, lambda: None)
    assert error.value.code == 'target_changed'
    assert repositories.remote_head('main') == repositories.head


def test_creation_refuses_existing_branch(transport, repositories):
    with pytest.raises(ClientError) as error:
        transport.publish(session(), arguments(repositories, branch='main'), lambda: None)
    assert error.value.code == 'target_changed'
    assert repositories.remote_head('main') == repositories.initial


def test_missing_expected_branch_is_not_implicitly_created(transport, repositories):
    with pytest.raises(ClientError) as error:
        transport.publish(session(), arguments(repositories, expected=repositories.initial), lambda: None)
    assert error.value.code == 'target_changed'
    assert git(repositories.remote, 'for-each-ref', '--format=%(refname)') == b'refs/heads/main\n'


@pytest.mark.parametrize('change', [
    {'commit_sha': 'a'*40}, {'branch': 'other'}, {'bundle_base64': 'bm90IGEgYnVuZGxl'},
])
def test_invalid_bundle_cannot_mutate_remote(transport, repositories, change):
    params = dict(arguments(repositories), **change)
    with pytest.raises(ClientError):
        transport.publish(session(), params, lambda: None)
    assert git(repositories.remote, 'for-each-ref', '--format=%(refname)') == b'refs/heads/main\n'


def test_incremental_bundle_requires_matching_expected_head(transport, repositories):
    with pytest.raises(ClientError):
        transport.publish(session(), arguments(repositories, incremental=True), lambda: None)
    assert repositories.remote_head('main') == repositories.initial


def test_recheck_failure_prevents_final_publication(transport, repositories):
    recheck = Mock(side_effect=RuntimeError('isolation no longer valid'))
    with pytest.raises(Exception):
        transport.publish(session(), arguments(repositories), recheck)
    recheck.assert_called()
    assert git(repositories.remote, 'for-each-ref', '--format=%(refname)') == b'refs/heads/main\n'


def test_push_policy_requires_explicit_grant_and_deny_wins(repositories):
    base = {'repositories': {'mode': 'all', 'exclude': ['acme/private']}, 'default_access': 'write'}
    for config, repo in [(base, 'acme/demo'), (dict(base, allow_actions=['git_push'], deny_actions=['git_push']), 'acme/demo'),
                         (dict(base, allow_actions=['git_push']), 'acme/private'),
                         (dict(base, deny_actions=['git_push'], repository_rules={'acme/demo': {'allow_actions':['git_push']}}), 'acme/demo')]:
        client = Mock()
        result = GitHubService(Policy.from_dict(config), client).execute('git_push', repo, arguments(repositories), recheck_isolation=lambda: None)
        assert result['code'] == 'policy_denied'
        client.session.assert_not_called()


@pytest.mark.parametrize('override', [
    {'branch':'--all'}, {'branch':'refs/heads/main'}, {'branch':'a:b'},
    {'commit_sha':'HEAD'}, {'commit_sha':'a'*64}, {'expected_head_sha':False},
    {'expected_head_sha':''}, {'bundle_base64':'!invalid!'}, {'bundle_base64':None},
    {'remote':'https://evil.invalid/repo'}, {'url':'ssh://evil.invalid/repo'},
    {'force':True}, {'token':'test-only-secret'}, {'headers':{}}, {'refspec':'+HEAD:main'},
])
def test_invalid_push_arguments_never_authenticate(repositories, override):
    client = Mock()
    policy = Policy.from_dict({'repositories':{'mode':'all','exclude':[]},'default_access':'read','allow_actions':['git_push']})
    result = GitHubService(policy, client).execute('git_push','acme/demo', dict(arguments(repositories), **override), recheck_isolation=lambda: None)
    assert result['code'] == 'invalid_arguments'
    client.session.assert_not_called()


def test_atomic_lease_rejects_race_after_validation(transport, repositories, monkeypatch):
    params = arguments(repositories, branch='main', expected=repositories.initial)
    competing = repositories.commit('race.txt', b'concurrent', 'Concurrent commit')
    original = transport._run
    injected = []
    def race(repo_path, args, *positional, **keywords):
        if 'push' in args and not injected:
            git(repositories.work, 'push', str(repositories.remote), competing+':refs/heads/main')
            injected.append(True)
        return original(repo_path, args, *positional, **keywords)
    monkeypatch.setattr(transport, '_run', race)
    with pytest.raises(ClientError):
        transport.publish(session(), params, lambda: None)
    assert injected and repositories.remote_head('main') == competing


def test_extra_advertised_ref_is_rejected(transport, repositories):
    params = arguments(repositories)
    path = repositories.work.parent/'extra.bundle'
    git(repositories.work,'bundle','create',str(path),'refs/heads/main','refs/heads/feature')
    params['bundle_base64'] = base64.b64encode(path.read_bytes()).decode()
    with pytest.raises(ClientError):
        transport.publish(session(), params, lambda: None)
    assert repositories.remote_head('main') == repositories.initial


def test_blob_advertised_as_commit_is_rejected(transport, repositories):
    params = arguments(repositories)
    raw = base64.b64decode(params['bundle_base64'])
    blob = git(repositories.work,'rev-parse','HEAD:binary.bin').decode().strip()
    params['bundle_base64'] = base64.b64encode(raw.replace(repositories.head.encode(),blob.encode(),1)).decode()
    params['commit_sha'] = blob
    with pytest.raises(ClientError):
        transport.publish(session(), params, lambda: None)
    assert git(repositories.remote, 'for-each-ref', '--format=%(refname)') == b'refs/heads/main\n'


def test_inherited_git_configuration_and_hooks_are_not_executed(transport, repositories, monkeypatch, tmp_path):
    marker = tmp_path/'unexpected-execution'
    hook = tmp_path/'hooks'
    hook.mkdir()
    script = hook/'pre-push'
    script.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\nexit 1\n')
    script.chmod(0o700)
    config = tmp_path/'evil-config'
    config.write_text('[core]\n hooksPath = '+str(hook)+'\n[credential]\n helper = !touch '+str(marker)+'\n[url "https://invalid.example/"]\n insteadOf = '+str(repositories.remote)+'\n')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL',str(config))
    monkeypatch.setenv('GIT_CONFIG_COUNT','1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0','core.hooksPath')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0',str(hook))
    monkeypatch.setenv('GIT_DIR',str(repositories.work/'.git'))
    monkeypatch.setenv('GIT_TRACE',str(marker))
    monkeypatch.setenv('GIT_SSH_COMMAND','touch '+str(marker))
    transport.publish(session(), arguments(repositories), lambda: None)
    assert not marker.exists()
    assert repositories.remote_head('feature') == repositories.head


def test_temp_directory_cleanup_on_success_and_invalid_pack(transport, repositories, monkeypatch):
    original = transport._run
    directories = set()
    def record(repo_path, args, *positional, **keywords):
        directories.add(repo_path)
        return original(repo_path, args, *positional, **keywords)
    monkeypatch.setattr(transport,'_run',record)
    transport.publish(session(), arguments(repositories), lambda: None)
    assert directories and all(not path.exists() for path in directories)
    params = arguments(repositories,branch='bad')
    raw = base64.b64decode(params['bundle_base64'])
    params['bundle_base64'] = base64.b64encode(raw[:-40]).decode()
    with pytest.raises(ClientError):
        transport.publish(session(),params,lambda: None)
    assert all(not path.exists() for path in directories)


def test_object_resource_limits_reject_before_mutation(transport, repositories, monkeypatch):
    monkeypatch.setattr(transport,'MAX_OBJECT_BYTES',1)
    with pytest.raises(ClientError) as error:
        transport.publish(session(),arguments(repositories),lambda: None)
    assert error.value.code == 'size_limit'
    assert git(repositories.remote,'for-each-ref','--format=%(refname)') == b'refs/heads/main\n'


def test_push_failure_is_uncertain_without_retry_or_secret_error(transport, repositories, monkeypatch):
    original = transport._run
    calls = []
    def failed(repo_path, args, *positional, **keywords):
        if 'push' in args:
            calls.append(args)
            return 128, b'test-only-installation-secret\nprivate-local-detail'
        return original(repo_path,args,*positional,**keywords)
    monkeypatch.setattr(transport,'_run',failed)
    with pytest.raises(ClientError) as error:
        transport.publish(session(),arguments(repositories),lambda: None)
    assert error.value.code == 'uncertain_outcome'
    assert len(calls) == 1
    assert 'test-only-installation-secret' not in str(error.value)
    assert 'private-local-detail' not in str(error.value)


def test_subprocess_receives_clean_environment_and_no_token_in_command(monkeypatch,tmp_path):
    from hermes_github_app import git_push
    captured = []
    class Process:
        returncode=0
        def wait(self,timeout):
            return 0
    def spawn(command,**kwargs):
        captured.append((command,kwargs))
        return Process()
    monkeypatch.setattr(git_push.subprocess,'Popen',spawn)
    monkeypatch.setenv('GH_TOKEN','inherited-test-secret')
    monkeypatch.setenv('HTTPS_PROXY','http://untrusted.invalid')
    git_push._run(tmp_path,['ls-remote','https://github.com/acme/demo.git'],time.monotonic()+10,token='scoped-test-token')
    command,kwargs=captured[0]
    assert 'scoped-test-token' not in repr(command)
    assert kwargs['env']['HERMES_PUSH_TOKEN']=='scoped-test-token'
    assert 'GH_TOKEN' not in kwargs['env'] and 'HTTPS_PROXY' not in kwargs['env']
    assert kwargs['env']['GIT_CONFIG_GLOBAL']=='/dev/null'
    assert 'http.followRedirects=false' in command and 'http.sslVerify=true' in command
    captured.clear()
    git_push._run(tmp_path,['fsck'],time.monotonic()+10)
    assert 'HERMES_PUSH_TOKEN' not in captured[0][1]['env']


def test_bundle_encoding_and_size_validation():
    from hermes_github_app.git_push import decode_bundle, MAX_BUNDLE_BYTES
    for invalid in ('', 'YQ==\n', 'YR==', '\ud800', 'A'*(4*((MAX_BUNDLE_BYTES+2)//3)+1)):
        with pytest.raises((ValueError, UnicodeError)):
            decode_bundle(invalid)
    assert decode_bundle('YQ==') == b'a'


def test_timeout_kills_group_and_redacts_process_error(monkeypatch,tmp_path):
    from hermes_github_app import git_push
    killed=[]
    class Process:
        pid=54321
        def __init__(self): self.waits=0
        def wait(self,timeout=None):
            self.waits+=1
            if self.waits==1:
                raise subprocess.TimeoutExpired('private-test-command',timeout)
            return -9
    process=Process()
    monkeypatch.setattr(git_push.subprocess,'Popen',lambda *args,**kwargs:process)
    monkeypatch.setattr(git_push.os,'killpg',lambda pid,signal:killed.append(pid))
    with pytest.raises(ClientError) as error:
        git_push._run(tmp_path,['push'],time.monotonic()+10,token='test-secret',mutation=True)
    assert killed==[54321] and process.waits==2
    assert error.value.code=='uncertain_outcome'
    assert 'private-test-command' not in str(error.value) and 'test-secret' not in str(error.value)


def test_git_push_has_no_rest_request_alias(repositories):
    from hermes_github_app.actions import ActionError, build_request, ACTIONS, READ_ACTIONS, WRITE_ACTIONS
    assert ACTIONS['git_push'].permissions == {'contents':'write'}
    assert 'git_push' not in READ_ACTIONS and 'git_push' not in WRITE_ACTIONS
    request=build_request('git_push','acme/demo',arguments(repositories))
    assert request.method=='GIT' and request.body is None


def test_concurrent_same_tip_is_not_misreported_as_our_publication(transport,repositories,monkeypatch):
    params=arguments(repositories,branch='main',expected=repositories.initial)
    original=transport._run
    injected=[]
    def race(repo_path,args,*positional,**keywords):
        if 'push' in args and not injected:
            git(repositories.work,'push',str(repositories.remote),repositories.head+':refs/heads/main')
            injected.append(True)
        return original(repo_path,args,*positional,**keywords)
    monkeypatch.setattr(transport,'_run',race)
    with pytest.raises(ClientError) as error:
        transport.publish(session(),params,lambda:None)
    assert error.value.code=='uncertain_outcome'
    assert injected and repositories.remote_head('main')==repositories.head
