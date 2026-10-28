"""Sandbox transport integrity checks; no host file-path assumptions."""
import base64
import hashlib
import json
import random
import re
import shlex
import subprocess
from unittest.mock import Mock

import pytest

from hermes_github_app import bundle_input


def chunk_responder(content, *, identity=None, file_digest=None):
    """Fake terminal that answers the reader protocol for in-memory content."""
    def dispatcher(name, args, **context):
        argv = shlex.split(args['command'])
        offset, limit, nonce = int(argv[5]), int(argv[6]), bytes.fromhex(argv[8])
        data = content[offset:offset+limit]
        whole = file_digest or hashlib.sha256(content).digest()
        last = offset + len(data) == len(content)
        chunk = {'identity': identity(offset) if identity else [1, 2, len(content), 4, 5],
                 'offset': offset, 'data': bundle_input._mask(data, nonce).hex(),
                 'chunk_sha256': hashlib.sha256(nonce+data).hexdigest(),
                 'sha256': hashlib.sha256(nonce+whole).hexdigest() if offset == 0 or last else None}
        return json.dumps({'exit_code': 0, 'output': json.dumps(chunk)})
    return dispatcher


def real_terminal(rewrite=lambda output, call: output):
    calls = []
    def dispatcher(name, args, **context):
        calls.append(args)
        result = subprocess.run(args['command'], shell=True, capture_output=True, text=True)
        output = rewrite(result.stdout.strip(), len(calls))
        return json.dumps({'exit_code': result.returncode, 'output': output})
    dispatcher.calls = calls
    return dispatcher


# Representative model-output redaction: token-shaped substrings are masked.
TOKEN_LIKE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}|(?<![A-Za-z0-9_-])(?:sk|ghp|hf)[-_][A-Za-z0-9]{10,}')


def redact(output, call):
    return TOKEN_LIKE.sub(lambda m: m.group(0)[:6] + '...' + m.group(0)[-4:], output)


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


def test_fake_protocol_round_trip(monkeypatch):
    monkeypatch.setattr(bundle_input,'CHUNK_BYTES',3)
    content=bytes(range(256))*3
    result=bundle_input.resolve_bundle_path(chunk_responder(content),'/sandbox/bundle',{'task_id':'t'},10000)
    assert base64.b64decode(result)==content


def test_forged_digest_and_changed_identity_are_rejected(monkeypatch):
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(chunk_responder(b'abc',file_digest=b'x'*32),'/sandbox/bundle',{'task_id':'t'},10000)
    assert 'changed' in str(error.value)
    monkeypatch.setattr(bundle_input,'CHUNK_BYTES',2)
    identity=lambda offset:[1,2 if offset == 0 else 3,4,4,5]
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(chunk_responder(b'abcd',identity=identity),'/sandbox/bundle',{'task_id':'t'},10000)
    assert 'changed' in str(error.value)


def test_deadline_checked_after_dispatch(monkeypatch):
    monkeypatch.setattr(bundle_input.time,'monotonic',Mock(side_effect=[0,0,121]))
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(chunk_responder(b'a'),'/sandbox/bundle',{'task_id':'t'},10000)
    assert 'deadline' in str(error.value)


def test_redacted_terminal_output_does_not_corrupt_large_bundle(tmp_path):
    content=random.Random(1691).randbytes(1024*1024)
    # The former base64 chunk encoding contains token-shaped text for this data.
    assert TOKEN_LIKE.search(base64.b64encode(content).decode())
    path=tmp_path/'large.bundle';path.write_bytes(content)
    terminal=real_terminal(redact)
    result=bundle_input.resolve_bundle_path(terminal,str(path),{'task_id':'t'},len(content))
    assert base64.b64decode(result)==content
    assert len(terminal.calls)==len(content)//bundle_input.CHUNK_BYTES


def test_altered_chunk_is_read_again_with_a_fresh_mask(tmp_path):
    content=random.Random(7).randbytes(3*bundle_input.CHUNK_BYTES)
    path=tmp_path/'bundle';path.write_bytes(content)
    def alter_second_call(output, call):
        if call != 2:
            return output
        start=output.index('"data":"')+8
        return output[:start]+('0' if output[start] != '0' else '1')+output[start+1:]
    terminal=real_terminal(alter_second_call)
    result=bundle_input.resolve_bundle_path(terminal,str(path),{'task_id':'t'},len(content))
    assert base64.b64decode(result)==content
    assert len(terminal.calls)==4
    nonces=[shlex.split(args['command'])[-1] for args in terminal.calls]
    assert len(set(nonces))==4


@pytest.mark.parametrize('rewrite',[
    lambda output, call: output[:1000],
    lambda output, call: output.replace('"chunk_sha256":"','"chunk_sha256":"***',1),
])
def test_persistent_alteration_fails_with_specific_reason_after_bounded_reads(tmp_path,rewrite):
    path=tmp_path/'bundle';path.write_bytes(b'PACK'*5000)
    terminal=real_terminal(rewrite)
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(terminal,str(path),{'task_id':'t'},100000)
    assert 'altered or truncated' in str(error.value)
    assert len(terminal.calls)==bundle_input.CHUNK_ATTEMPTS


def test_total_altered_reads_are_bounded(tmp_path,monkeypatch):
    monkeypatch.setattr(bundle_input,'CHUNK_BYTES',64)
    path=tmp_path/'bundle';path.write_bytes(b'x'*(64*20))
    # Every chunk needs one retry; the global budget stops the transfer.
    terminal=real_terminal(lambda output, call: output if call % 2 == 0 else output[:10])
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(terminal,str(path),{'task_id':'t'},100000)
    assert 'altered or truncated' in str(error.value)
    assert len(terminal.calls)==2*bundle_input.MAX_ALTERED_READS-1


def test_missing_file_reports_specific_reason(tmp_path):
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(real_terminal(),str(tmp_path/'absent'),{'task_id':'t'},10000)
    assert 'not found' in str(error.value)


def test_plugin_reports_static_transport_reason(tmp_path):
    from hermes_github_app import plugin
    from hermes_github_app.policy import Policy
    from hermes_github_app.service import GitHubService
    policy=Policy.from_dict({'repositories':{'mode':'all','exclude':[]},'default_access':'read','allow_actions':['git_push']})
    client=Mock()
    result=plugin._execute_host_operation(Mock(),GitHubService(policy,client),'git_push',
        {'repo':'acme/demo','branch':'feature','commit_sha':'a'*40,'expected_head_sha':None,'bundle_path':str(tmp_path/'absent')},
        dispatcher=real_terminal(),context={'task_id':'t'})
    assert result['code']=='bundle_unavailable'
    assert result['error'].endswith('Bundle file was not found in the active terminal task.')
    client.session.assert_not_called()


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
    with pytest.raises(bundle_input.BundleInputError) as error:
        bundle_input.resolve_bundle_path(dispatcher,str(path),{'task_id':'t'},10000)
    assert 'regular file' in str(error.value)


@pytest.mark.parametrize("path",["/sandbox/a\u0080", "/sandbox/a\u009f"])
def test_c1_control_paths_rejected(path):
    with pytest.raises(bundle_input.BundleInputError):
        bundle_input.validate_bundle_path(path)
