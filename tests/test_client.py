import base64
import json
from pathlib import Path
import tempfile

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hermes_github_app.actions import ACTIONS, build_request, validate_params
from hermes_github_app.client import ClientError, GitHubClient, MAX_FILE_BYTES, MAX_RESPONSE_BYTES

SHA='a'*40
TREE='b'*40
BLOB='c'*40
OTHER='d'*40

@pytest.fixture
def key_file():
    with tempfile.TemporaryDirectory(prefix='.test-key-',dir=Path.cwd()) as directory:
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        path=Path(directory)/'app.pem'
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        path.chmod(0o600)
        yield path

class API:
    def __init__(self,key_file,routes=None,permissions=None,scope=None):
        self.calls=[];self.routes=routes or {};self.permissions=permissions
        self.scope=scope or {'total_count':1,'repositories':[{'full_name':'Acme/Demo'}]}
        self.client=GitHubClient(12,34,str(key_file),transport=httpx.MockTransport(self.handle))
    def handle(self,req):
        self.calls.append(req)
        assert req.url.host=='api.github.com'
        if req.url.path=='/app/installations/34/access_tokens':
            grant=json.loads(req.content)
            assert grant['repositories']==['demo']
            return httpx.Response(201,json={'token':'secret-token','permissions':self.permissions or grant['permissions']})
        if req.url.path=='/installation/repositories':return httpx.Response(200,json=self.scope)
        path=req.url.path.removeprefix('/repos/acme/demo')
        route=self.routes.get((req.method,path),self.routes.get(path))
        if route is None and path=='':route={'full_name':'acme/demo','default_branch':'main','allow_squash_merge':True}
        if route is None:return httpx.Response(404,json={})
        if isinstance(route,Exception):raise route
        if callable(route):return route(req)
        if isinstance(route,httpx.Response):return route
        return httpx.Response(200,json=route)
    def run(self,action,params):
        params=validate_params(action,params)
        session=self.client.session('acme/demo',ACTIONS[action].permissions)
        return session.execute(action,params,build_request(action,'acme/demo',params))


def ref(kind,name,sha=SHA,type='commit'):
    return {'ref':f'refs/{kind}/{name}','object':{'type':type,'sha':sha}}

def test_scoped_auth_and_redaction(key_file):
    api=API(key_file,{'/issues/1':{'number':1,'title':'secret-token'}})
    assert api.run('issues.get',{'number':1})['title']=='[REDACTED]'
    assert json.loads(api.calls[0].content)['permissions']=={'issues':'read'}
    assert len(api.calls)==4

@pytest.mark.parametrize('scope',[
    {'total_count':2,'repositories':[{'full_name':'acme/demo'}]},
    {'total_count':1,'repositories':[{'full_name':'other/demo'}]},
    {'total_count':1,'repositories':[]},
])
def test_wrong_repo_scope_never_dispatches(key_file,scope):
    api=API(key_file,scope=scope)
    with pytest.raises(ClientError):api.run('repo.get',{})
    assert len(api.calls)==2

def test_excess_permissions_denied(key_file):
    api=API(key_file,permissions={'metadata':'read','contents':'write'})
    with pytest.raises(ClientError):api.run('repo.get',{})
    assert len(api.calls)==1

@pytest.mark.parametrize('kind',['redirect','error','oversize','invalid_json','exception'])
def test_failure_sanitized_no_retry(key_file,kind):
    responses={'redirect':httpx.Response(302,headers={'location':'https://evil.example/secret-token'}),
      'error':httpx.Response(403,text='secret-token'),'oversize':httpx.Response(200,content=b'x'*(MAX_RESPONSE_BYTES+1)),
      'invalid_json':httpx.Response(200,text='secret-token'),'exception':RuntimeError('secret-token')}
    api=API(key_file,{'/issues/1':responses[kind]})
    with pytest.raises(ClientError) as caught:api.run('issues.get',{'number':1})
    assert 'secret-token' not in str(caught.value)
    assert len(api.calls)==4

def test_key_permissions_and_symlink(key_file):
    key_file.chmod(0o644)
    with pytest.raises(ClientError):GitHubClient(1,2,str(key_file))
    key_file.chmod(0o600)
    link=key_file.with_name('link');link.symlink_to(key_file)
    with pytest.raises(ClientError):GitHubClient(1,2,str(link))

@pytest.mark.parametrize('action,is_pull,allow',[
    ('issues.comment',False,True),('issues.comment',True,False),
    ('pulls.comment',True,True),('pulls.comment',False,False),
    ('issues.comments.list',False,True),('issues.comments.list',True,False),
    ('pulls.comments.list',True,True),('pulls.comments.list',False,False),
])
def test_comment_type_guard(key_file,action,is_pull,allow):
    target={'number':1,**({'pull_request':{}} if is_pull else {})}
    resource='pulls' if action.startswith('pulls') else 'issues'
    routes={f'/{resource}/1':target if (resource=='issues' or is_pull) else httpx.Response(404),
      '/issues/1/comments':[] if action.endswith('list') else {'id':2}}
    api=API(key_file,routes)
    params={'number':1,**({} if action.endswith('list') else {'body':'hello'})}
    if allow:api.run(action,params)
    else:
        with pytest.raises(ClientError):api.run(action,params)
        assert not any(r.url.path.endswith('/comments') for r in api.calls)

def test_list_pagination_uses_upstream_page_before_filter(key_file):
    api=API(key_file,{'/issues':httpx.Response(200,json=[{'number':2,'pull_request':{}}],headers={'link':'<https://evil.example>; rel="next"'})})
    assert api.run('issues.list',{'page':2,'per_page':1})=={'items':[],'page':2,'per_page':1,'has_more':True}
    assert len(api.calls)==4

def test_metadata_canonical_mismatch_refuses_before_mutation(key_file):
    api=API(key_file,{'':{'full_name':'other/demo'}})
    with pytest.raises(ClientError):api.run('issues.create',{'title':'title'})
    assert len(api.calls)==3

def test_ambiguous_mutation_timeout_never_retries(key_file):
    api=API(key_file,{('POST','/issues'):httpx.ReadTimeout('secret-token')})
    with pytest.raises(ClientError) as caught:api.run('issues.create',{'title':'title'})
    assert caught.value.code=='uncertain_outcome'
    assert len(api.calls)==4

def content_routes(entry,blob=None):
    result={'/git/ref/heads/main':ref('heads','main'),'/git/commits/'+SHA:{'sha':SHA,'tree':{'sha':TREE}},
      '/git/trees/'+TREE:{'truncated':False,'tree':[entry]}}
    if blob is not None:result['/git/blobs/'+BLOB]=blob
    return result

def test_binary_file_one_mib_allowed(key_file):
    data=b'\x00\xff'*(MAX_FILE_BYTES//2)
    api=API(key_file,content_routes({'path':'file','mode':'100644','sha':BLOB,'size':len(data)},
      {'encoding':'base64','size':len(data),'content':base64.b64encode(data).decode()}))
    result=api.run('contents.read',{'path':'file'})
    assert base64.b64decode(result['content'])==data
    assert not any('/contents' in r.url.path for r in api.calls)

def test_large_file_rejected_without_blob_read(key_file):
    api=API(key_file,content_routes({'path':'file','mode':'100644','sha':BLOB,'size':MAX_FILE_BYTES+1}))
    with pytest.raises(ClientError) as caught:api.run('contents.read',{'path':'file'})
    assert caught.value.code=='size_limit'
    assert not any('/blobs/' in r.url.path for r in api.calls)

@pytest.mark.parametrize('mode,type_name',[('120000','symlink'),('160000','submodule')])
def test_special_files_metadata_only_no_ancestor_traversal(key_file,mode,type_name):
    api=API(key_file,content_routes({'path':'link','mode':mode,'sha':BLOB,'size':12}))
    result=api.run('contents.read',{'path':'link'})
    assert result['type']==type_name and 'content' not in result
    with pytest.raises(ClientError):api.run('contents.read',{'path':'link/secret'})
    assert not any('/blobs/' in r.url.path or '/contents' in r.url.path for r in api.calls)

def test_ambiguous_ref_denied(key_file):
    api=API(key_file,{'/git/ref/heads/release':ref('heads','release'),'/git/ref/tags/release':ref('tags','release')})
    with pytest.raises(ClientError):api.run('contents.read',{'path':'','ref':'release'})

def test_annotated_tag_resolution(key_file):
    routes=content_routes({'path':'link','mode':'120000','sha':BLOB})
    routes.update({'/git/ref/tags/v1':ref('tags','v1',OTHER,'tag'),'/git/tags/'+OTHER:{'object':{'type':'commit','sha':SHA}}})
    api=API(key_file,routes)
    assert api.run('contents.read',{'path':'link','ref':'v1'})['type']=='symlink'

def test_branch_expected_source_and_actual_creation(key_file):
    routes={'/git/ref/heads/main':ref('heads','main'),'/git/commits/'+SHA:{'sha':SHA},
      ('POST','/git/refs'):ref('heads','feature')}
    api=API(key_file,routes)
    result=api.run('branches.create',{'branch':'feature','source_branch':'main','expected_source_sha':SHA})
    assert result=={'branch':'feature','sha':SHA}
    assert json.loads(api.calls[-1].content)=={'ref':'refs/heads/feature','sha':SHA}
    with pytest.raises(ClientError):api.run('branches.create',{'branch':'feature','source_branch':'main','expected_source_sha':OTHER})

def test_branch_reachability_and_tag_collision(key_file):
    routes={'/git/matching-refs/heads/':[ref('heads','main',OTHER)],
      '/compare/'+SHA+'...'+OTHER:{'status':'ahead','merge_base_commit':{'sha':SHA}},
      '/git/commits/'+SHA:{'sha':SHA},('POST','/git/refs'):ref('heads','feature')}
    api=API(key_file,routes)
    assert api.run('branches.create',{'branch':'feature','source_commit_sha':SHA})['sha']==SHA
    api.routes['/git/ref/tags/feature']=ref('tags','feature')
    previous=len(api.calls)
    with pytest.raises(ClientError):api.run('branches.create',{'branch':'feature','source_commit_sha':SHA})
    assert not any(r.method=='POST' and r.url.path.endswith('/git/refs') for r in api.calls[previous:])

def test_unreachable_fork_network_object_denied(key_file):
    api=API(key_file,{'/git/matching-refs/heads/':[],'/git/matching-refs/tags/':[],'/git/commits/'+SHA:{'sha':SHA}})
    with pytest.raises(ClientError):api.run('branches.create',{'branch':'feature','source_commit_sha':SHA})
    assert not any(r.url.path.endswith('/git/commits/'+SHA) for r in api.calls)

def test_pull_create_verifies_existing_same_repo_branches(key_file):
    api=API(key_file,{'/git/ref/heads/main':ref('heads','main'),'/git/ref/heads/feature':ref('heads','feature'),
      ('POST','/pulls'):{'number':1,'base':{'repo':{'full_name':'acme/demo'}}}})
    api.run('pulls.create',{'title':'title','head':'feature','base':'main'})
    assert json.loads(api.calls[0].content)['permissions']=={'pull_requests':'write','contents':'read'}

def merge_pr(**changes):
    return {'number':1,'title':'title','state':'open','draft':False,'merged':False,
      'head':{'ref':'feature','sha':SHA,'repo':{'full_name':'acme/demo'}},
      'base':{'ref':'main','repo':{'full_name':'acme/demo'}},**changes}

def test_merge_preconditions_and_atomic_head_body(key_file):
    api=API(key_file,{'/pulls/1':merge_pr(),('PUT','/pulls/1/merge'):{'merged':True,'sha':OTHER}})
    params={'number':1,'expected_head_sha':SHA,'merge_method':'squash'}
    session=api.client.session('acme/demo',ACTIONS['pulls.merge'].permissions)
    assert session.inspect_merge(params)['base_branch']=='main'
    assert session.merge(params)=={'merged':True,'sha':OTHER}
    assert json.loads(api.calls[-1].content)=={'sha':SHA,'merge_method':'squash'}

@pytest.mark.parametrize('changes',[{'draft':True},{'merged':True},{'state':'closed'},
  {'head':{'ref':'feature','sha':OTHER,'repo':{'full_name':'acme/demo'}}},
  {'head':{'ref':'feature','sha':SHA,'repo':{'full_name':'fork/demo'}}}])
def test_merge_invalid_target_no_put(key_file,changes):
    api=API(key_file,{'/pulls/1':merge_pr(**changes)})
    session=api.client.session('acme/demo',ACTIONS['pulls.merge'].permissions)
    with pytest.raises(ClientError):session.inspect_merge({'number':1,'expected_head_sha':SHA,'merge_method':'squash'})
    assert not any(r.method=='PUT' for r in api.calls)


@pytest.mark.parametrize('method,field',[('merge','allow_merge_commit'),('squash','allow_squash_merge'),('rebase','allow_rebase_merge')])
def test_all_merge_methods_use_correct_repository_flag(key_file,method,field):
    api=API(key_file,{'':{'full_name':'acme/demo',field:True},'/pulls/1':merge_pr()})
    session=api.client.session('acme/demo',ACTIONS['pulls.merge'].permissions)
    assert session.inspect_merge({'number':1,'expected_head_sha':SHA,'merge_method':method})['merge_method']==method
