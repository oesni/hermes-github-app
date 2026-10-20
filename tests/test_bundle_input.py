"""Sandbox transport integrity checks; no host file-path assumptions."""
import base64
import hashlib
import json
import subprocess
from unittest.mock import Mock

import pytest

from hermes_github_app import bundle_input


def response(data, offset=0, digest=None, identity=None):
    digest = digest or hashlib.sha256(data).hexdigest()
    chunk={'identity':identity or [1,2,len(data),4,5],'offset':offset,
           'data':base64.b64encode(data).decode(),'sha256':digest}
    return json.dumps({'exit_code':0,'output':json.dumps(chunk)})


def test_real_reader_handles_quoted_filename_and_preserves_context(tmp_path):
    path=tmp_path/"bundle'; harmless file"
    content=b'PACK\x00\xff'*5000
    path.write_bytes(content)
    calls=[]
    def dispatcher(name,args,**context):
        calls.append((name,args,context))
        result=subprocess.run(args['command'],shell=True,capture_output=True,text=True)
        return json.dumps({'exit_code':result.returncode,'output':result.stdout})
    context={'task_id':'task-1','session_id':'session-1'}
    result=bundle_input.resolve_bundle_path(dispatcher,str(path),context,100000)
    assert base64.b64decode(result)==content
    assert len(calls)>1
    assert all(name=='terminal' and ctx==context for name,args,ctx in calls)


@pytest.mark.parametrize('content',[
    'not json',json.dumps({'exit_code':1,'output':'private-error'}),
    json.dumps({'exit_code':0,'output':'not json'}),
    json.dumps({'exit_code':True,'output':'{}'}),
    json.dumps({'exit_code':0,'output':'{}','error':'blocked'}),
])
def test_transport_failures_are_sanitized(content):
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(Mock(return_value=content),'/sandbox/bundle',{'task_id':'t'},10000)
    assert 'private-error' not in str(error.value)


def test_forged_digest_and_changed_identity_are_rejected(monkeypatch):
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.resolve_bundle_path(Mock(return_value=response(b'abc',digest='a'*64)),'/sandbox/bundle',{'task_id':'t'},10000)
    monkeypatch.setattr(bundle_input,'CHUNK_BYTES',2)
    one=response(b'ab',identity=[1,2,4,4,5],digest=hashlib.sha256(b'abcd').hexdigest())
    two=response(b'cd',offset=2,identity=[1,3,4,4,5],digest=hashlib.sha256(b'abcd').hexdigest())
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.resolve_bundle_path(Mock(side_effect=[one,two]),'/sandbox/bundle',{'task_id':'t'},10000)


def test_deadline_checked_after_dispatch(monkeypatch):
    monkeypatch.setattr(bundle_input.time,'monotonic',Mock(side_effect=[0,0,121]))
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.resolve_bundle_path(Mock(return_value=response(b'a')),'/sandbox/bundle',{'task_id':'t'},10000)


@pytest.mark.parametrize('context',[{}, {'task_id':''},{'task_id':None}])
def test_no_default_task_fallback(context):
    dispatch=Mock()
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.resolve_bundle_path(dispatch,'/sandbox/bundle',context,10000)
    dispatch.assert_not_called()


def test_policy_denies_path_before_terminal_dispatch():
    from hermes_github_app import plugin
    from hermes_github_app.policy import Policy
    from hermes_github_app.service import GitHubService
    policy=Policy.from_dict({'repositories':{'mode':'all','exclude':[]},'default_access':'write'})
    client=Mock();dispatch=Mock()
    result=plugin._execute_host_operation(Mock(),GitHubService(policy,client),'git_push',
        {'repo':'acme/demo','branch':'feature','commit_sha':'a'*40,'expected_head_sha':None,'bundle_path':'/sandbox/bundle'},
        dispatcher=dispatch,context={'task_id':'t'})
    assert result['code']=='policy_denied'
    dispatch.assert_not_called();client.session.assert_not_called()


@pytest.mark.parametrize('kind',['symlink','directory','empty'])
def test_real_reader_refuses_non_regular_and_empty_input(tmp_path,kind):
    target=tmp_path/'data';target.write_bytes(b'content')
    path=tmp_path/'input'
    if kind=='symlink':path.symlink_to(target)
    elif kind=='directory':path.mkdir()
    else:path.write_bytes(b'')
    def dispatcher(name,args,**context):
        result=subprocess.run(args['command'],shell=True,capture_output=True,text=True)
        return json.dumps({'exit_code':result.returncode,'output':result.stdout})
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.resolve_bundle_path(dispatcher,str(path),{'task_id':'t'},10000)


@pytest.mark.parametrize("path",["/sandbox/a\u0080", "/sandbox/a\u009f"])
def test_c1_control_paths_rejected(path):
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.validate_bundle_path(path)
