from types import SimpleNamespace
from unittest.mock import Mock
from hermes_github_app.policy import PolicyError
from hermes_github_app.service import GitHubService
from hermes_github_app.approvals import MergeApprovals


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

def test_merge_unavailable_without_host_approval():
    client=Mock()
    result=GitHubService(policy(),client).execute('pr_merge','acme/demo',{'number':1,'expected_head_sha':'a'*40,'merge_method':'squash'},recheck_isolation=lambda:None)
    assert result['code']=='approval_required_unavailable';client.session.assert_not_called()

def test_merge_rechecks_isolation_policy_and_target():
    target={'repo':'acme/demo','number':1,'base_branch':'main','head_branch':'feature','expected_head_sha':'a'*40,'merge_method':'squash'}
    adapter=Mock();adapter.available.return_value=True
    def present(request_id,target,deadline,callback):callback(request_id,'123',False,True);return True
    adapter.present.side_effect=present
    client=Mock();session=client.session.return_value;session.repo='acme/demo';session.inspect_merge.return_value=target;session.merge.return_value={'merged':True}
    isolation=Mock();p=policy()
    result=GitHubService(p,client,MergeApprovals(adapter,['123'])).execute('pr_merge','acme/demo',{'number':1,'expected_head_sha':'a'*40,'merge_method':'squash'},context=SimpleNamespace(identity='host-call',cancelled=lambda:False),recheck_isolation=isolation)
    assert result=={'ok':True,'data':{'merged':True}}
    assert isolation.call_count==2 and client.session.call_count==2 and session.inspect_merge.call_count==2
    session.merge.assert_called_once()


def test_legacy_dotted_action_names_are_not_aliases():
    client=Mock()
    for action in ('repo.get','issues.comment','pulls.merge'):
        result=GitHubService(policy(),client).execute(action,'acme/demo',{},recheck_isolation=lambda:None)
        assert result['code']=='invalid_arguments'
    client.session.assert_not_called()


def test_merge_without_available_approvers_mints_no_write_token():
    for approvals in (MergeApprovals(None,[]),MergeApprovals(Mock(available=lambda:False),['123'])):
        client=Mock()
        result=GitHubService(policy(),client,approvals).execute('pr_merge','acme/demo',
            {'number':1,'expected_head_sha':'a'*40,'merge_method':'squash'},
            context=SimpleNamespace(identity='host-call',cancelled=lambda:False),recheck_isolation=lambda:None)
        assert result=={'ok':False,'code':'approval_required_unavailable','error':'approval_required_unavailable'}
        client.session.assert_not_called()


def test_unexpected_client_failure_is_not_misclassified_as_isolation():
    client=Mock();client.session.side_effect=RuntimeError('private data')
    result=GitHubService(policy(),client).execute('repo_get','acme/demo',{},recheck_isolation=lambda:None)
    assert result=={'ok':False,'code':'github_unavailable','error':'GitHub operation failed.'}
