from types import SimpleNamespace
from unittest.mock import Mock
from hermes_github_app.policy import PolicyError
from hermes_github_app.service import GitHubService


def policy():
    p=Mock();p.authorize.return_value='acme/demo';return p

def test_denied_policy_never_authenticates():
    p=policy();p.authorize.side_effect=PolicyError('denied');client=Mock()
    result=GitHubService(p,client).execute('repo_get','acme/demo',{},recheck_isolation=lambda:None)
    assert result['code']=='policy_denied';client.session.assert_not_called()

def test_isolation_failure_zero_network():
    client=Mock()
    def refuse():raise RuntimeError('private credential')
    result=GitHubService(policy(),client).execute('repo_get','acme/demo',{},recheck_isolation=refuse)
    assert result['code']=='isolation_refusal';assert 'credential' not in str(result)
    client.session.assert_not_called()

def test_missing_trusted_context_zero_network():
    client=Mock()
    assert GitHubService(policy(),client).execute('repo_get','acme/demo',{})['code']=='isolation_refusal'
    client.session.assert_not_called()

def test_invalid_action_zero_network():
    client=Mock()
    result=GitHubService(policy(),client).execute('raw.request','acme/demo',{},recheck_isolation=lambda:None)
    assert result['code']=='invalid_arguments';client.session.assert_not_called()

def test_authorized_canonical_repo():
    client=Mock();client.session.return_value.repo='acme/demo';client.session.return_value.execute.return_value={'name':'demo'}
    assert GitHubService(policy(),client).execute('repo_get','Acme/Demo',{},recheck_isolation=lambda:None)=={'ok':True,'data':{'name':'demo'}}
    client.session.assert_called_once_with('acme/demo',{'metadata':'read'})

def test_legacy_dotted_action_names_are_not_aliases():
    client=Mock()
    for action in ('repo.get','issues.comment','pulls.merge'):
        result=GitHubService(policy(),client).execute(action,'acme/demo',{},recheck_isolation=lambda:None)
        assert result['code']=='invalid_arguments'
    client.session.assert_not_called()


def test_unexpected_client_failure_is_not_misclassified_as_isolation():
    client=Mock();client.session.side_effect=RuntimeError('private data')
    result=GitHubService(policy(),client).execute('repo_get','acme/demo',{},recheck_isolation=lambda:None)
    assert result=={'ok':False,'code':'github_unavailable','error':'GitHub operation failed.'}


def merge_case():
    target={'repo':'acme/demo','number':1,'base_branch':'main','head_branch':'feature','expected_head_sha':'a'*40,'merge_method':'squash'}
    params={'number':1,'expected_head_sha':'a'*40,'merge_method':'squash'}
    client=Mock();session=client.session.return_value
    session.repo='acme/demo';session.inspect_merge.return_value=target
    session.merge.return_value={'merged':True}
    return client,session,target,params


def test_policy_authorized_merge_rechecks_and_dispatches_without_adapter():
    client,session,target,params=merge_case()
    isolation=Mock();p=policy()
    result=GitHubService(p,client).execute('pr_merge','acme/demo',params,recheck_isolation=isolation)
    assert result=={'ok':True,'data':{'merged':True}}
    assert isolation.call_count==2 and session.inspect_merge.call_count==2
    assert p.authorize.call_count==4
    client.session.assert_called_once_with('acme/demo',{'contents':'write','pull_requests':'read'})
    session.merge.assert_called_once_with(params)


def test_merge_target_change_refuses_without_dispatch():
    client,session,target,params=merge_case()
    session.inspect_merge.side_effect=[target,{**target,'base_branch':'other'}]
    result=GitHubService(policy(),client).execute('pr_merge','acme/demo',params,recheck_isolation=lambda:None)
    assert result['code']=='target_changed';session.merge.assert_not_called()


def test_merge_second_isolation_check_refuses_without_dispatch():
    client,session,target,params=merge_case()
    result=GitHubService(policy(),client).execute('pr_merge','acme/demo',params,recheck_isolation=Mock(side_effect=[None,RuntimeError()]))
    assert result['code']=='isolation_refusal';session.merge.assert_not_called()


def test_merge_policy_revocation_refuses_without_dispatch():
    client,session,target,params=merge_case();p=policy()
    p.authorize.side_effect=['acme/demo','acme/demo',PolicyError('denied')]
    result=GitHubService(p,client).execute('pr_merge','acme/demo',params,recheck_isolation=lambda:None)
    assert result['code']=='policy_denied';session.merge.assert_not_called()


def test_merge_uncertain_result_is_not_retried():
    from hermes_github_app.client import ClientError
    client,session,target,params=merge_case()
    session.merge.side_effect=ClientError('Mutation outcome is uncertain.', 'uncertain_outcome')
    result=GitHubService(policy(),client).execute('pr_merge','acme/demo',params,recheck_isolation=lambda:None)
    assert result['code']=='uncertain_outcome';session.merge.assert_called_once()


def test_merge_explicit_policy_deny_never_authenticates():
    from hermes_github_app.policy import Policy
    client,session,target,params=merge_case()
    p=Policy.from_dict({'repositories':{'mode':'all','exclude':[]},'default_access':'write','allow_actions':['pr_merge'],'deny_actions':['pr_merge']})
    result=GitHubService(p,client).execute('pr_merge','acme/demo',params,recheck_isolation=lambda:None)
    assert result['code']=='policy_denied';client.session.assert_not_called()
