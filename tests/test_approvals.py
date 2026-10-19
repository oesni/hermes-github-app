from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from hermes_github_app.approvals import ApprovalError, MergeApprovals

TARGET={'repo':'acme/demo','number':1,'base_branch':'main','head_branch':'feature','expected_head_sha':'a'*40,'merge_method':'squash'}

class Adapter:
    def __init__(self,decision=True):self.decision=decision;self.ids=[];self.finished=[];self.hook=None
    def present(self,request_id,target,deadline,callback):
        self.ids.append(request_id)
        if self.hook:self.hook(request_id,target,deadline,callback)
        else:callback(request_id,'123',False,self.decision)
        return deadline
    def finish(self,request_id,status):self.finished.append(status)

def context():return SimpleNamespace(identity='session:call:instance',cancelled=lambda:False)

def test_single_use_distinct_invocations_no_poll_handle():
    adapter=Adapter();manager=MergeApprovals(adapter,['123']);dispatch=Mock(return_value={'merged':True})
    for _ in range(2):assert manager.run(TARGET,context(),lambda:dict(TARGET),dispatch)=={'merged':True}
    assert len(set(adapter.ids))==2 and dispatch.call_count==2
    assert not manager._pending

@pytest.mark.parametrize('decision,code',[(False,'approval_denied')])
def test_denial_never_dispatches(decision,code):
    adapter=Adapter(decision);dispatch=Mock()
    with pytest.raises(ApprovalError) as caught:MergeApprovals(adapter,['123']).run(TARGET,context(),lambda:TARGET,dispatch)
    assert caught.value.code==code;dispatch.assert_not_called()

def test_bot_and_unlisted_and_wrong_request_cannot_decide():
    adapter=Adapter();clock=[0]
    def hook(request_id,target,deadline,callback):
        callback(request_id,'123',True,True)
        callback(request_id,'999',False,False)
        callback('copied-request','123',False,True)
        clock[0]=601
    adapter.hook=hook;dispatch=Mock()
    with pytest.raises(ApprovalError) as caught:MergeApprovals(adapter,['123'],clock=lambda:clock[0]).run(TARGET,context(),lambda:TARGET,dispatch)
    assert caught.value.code=='approval_expired';dispatch.assert_not_called()

def test_target_change_invalidates_approved_request():
    dispatch=Mock()
    with pytest.raises(ApprovalError) as caught:MergeApprovals(Adapter(),['123']).run(TARGET,context(),lambda:{**TARGET,'base_branch':'release'},dispatch)
    assert caught.value.code=='target_changed';dispatch.assert_not_called()

def test_expiry_during_recheck_prevents_dispatch():
    clock=[0];dispatch=Mock()
    def recheck():clock[0]=601;return TARGET
    with pytest.raises(ApprovalError) as caught:MergeApprovals(Adapter(),['123'],clock=lambda:clock[0]).run(TARGET,context(),recheck,dispatch)
    assert caught.value.code=='approval_expired';dispatch.assert_not_called()

@pytest.mark.parametrize('cause',['cancel','identity','restart'])
def test_lifecycle_changes_cancel(cause):
    ctx=context();manager=MergeApprovals(Adapter(),['123']);dispatch=Mock()
    def recheck():
        if cause=='cancel':ctx.cancelled=lambda:True
        if cause=='identity':ctx.identity='another-session'
        if cause=='restart':manager.close()
        return TARGET
    with pytest.raises(ApprovalError) as caught:manager.run(TARGET,ctx,recheck,dispatch)
    assert caught.value.code=='approval_cancelled';dispatch.assert_not_called()

def test_empty_approvers_unavailable():
    adapter=Adapter()
    with pytest.raises(ApprovalError) as caught:MergeApprovals(adapter,[]).run(TARGET,context(),lambda:TARGET,Mock())
    assert caught.value.code=='approval_required_unavailable';assert not adapter.ids

def test_duplicate_decision_cannot_reverse_first():
    adapter=Adapter()
    adapter.hook=lambda request_id,target,deadline,callback:(callback(request_id,'123',False,False),callback(request_id,'123',False,True))
    with pytest.raises(ApprovalError) as caught:MergeApprovals(adapter,['123']).run(TARGET,context(),lambda:TARGET,Mock())
    assert caught.value.code=='approval_denied'


def test_dispatch_interruption_is_uncertain_and_never_retried():
    adapter=Adapter();dispatch=Mock(side_effect=KeyboardInterrupt())
    with pytest.raises(ApprovalError) as caught:
        MergeApprovals(adapter,['123']).run(TARGET,context(),lambda:TARGET,dispatch)
    assert caught.value.code=='uncertain_outcome'
    dispatch.assert_called_once()
    assert adapter.finished==['uncertain_outcome']


def test_deadline_begins_at_confirmed_presentation():
    adapter=Adapter();clock=[0];dispatch=Mock(return_value={})
    def present(request_id,target,deadline,callback):
        clock[0]=15
        callback(request_id,'123',False,True)
        return 615.0
    adapter.present=present
    def recheck():clock[0]=610;return TARGET
    assert MergeApprovals(adapter,['123'],clock=lambda:clock[0]).run(TARGET,context(),recheck,dispatch)=={}
    dispatch.assert_called_once()


def test_disconnected_adapter_is_unavailable_not_internal_error():
    adapter=Adapter();adapter.present=Mock(side_effect=RuntimeError('private data'))
    with pytest.raises(ApprovalError) as caught:
        MergeApprovals(adapter,['123']).run(TARGET,context(),lambda:TARGET,Mock())
    assert caught.value.code=='approval_required_unavailable'
    assert 'private data' not in str(caught.value)
