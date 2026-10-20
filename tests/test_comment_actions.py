"""Closed source-comment and eyes-only operations through fake HTTP."""
import json
import httpx
import pytest
from hermes_github_app.actions import ACTIONS, ActionError, build_request, validate_params
from hermes_github_app.client import ClientError
from test_client import API, key_file

READS=[('issue_comment_get','issues','issue_url','issues',{'issues':'read'}),
       ('pr_review_comment_get','pulls','pull_request_url','pulls',{'pull_requests':'read'})]
WRITES=[('issue_comment_reaction','issues',{'issues':'write'}),
        ('pr_review_comment_reaction','pulls',{'pull_requests':'write'})]
ACTOR={'id':9,'login':'human','type':'User'}
BOT={'id':10,'login':'sample-app[bot]','type':'Bot'}


@pytest.mark.parametrize('action,resource,parent_field,parent_resource,permissions',READS)
def test_source_read_exact_namespace_minimal_permission_and_allowlist(key_file,action,resource,parent_field,parent_resource,permissions):
    parent=f'https://api.github.com/repos/Acme/Demo/{parent_resource}/1'
    html_url='https://github.com/Acme/Demo/'+('issues/1#issuecomment-3' if resource=='issues' else 'pull/1#discussion_r3')
    source={'id':3,'body':'Comment text secret-token','html_url':html_url,'user':{**ACTOR,'avatar_url':'hidden'},
            parent_field:parent,'diff_hunk':'private code','arbitrary':'hidden'}
    api=API(key_file,{f'/{resource}/comments/3':source})
    result=api.run(action,{'comment_id':3})
    assert result=={'id':3,'body':'Comment text [REDACTED]','user':ACTOR,parent_field:parent,'html_url':html_url}
    assert json.loads(api.calls[0].content)['permissions']==permissions
    assert api.calls[-1].url.path==f'/repos/acme/demo/{resource}/comments/3'
    assert len(api.calls)==4


@pytest.mark.parametrize('action,resource,parent_field,parent_resource,permissions',READS)
@pytest.mark.parametrize('override',[
    {'id':4},{'id':True},{'body':None},{'user':None},
    {'user':{'id':True,'login':'human','type':'User'}},
    {'user':{'id':9,'login':'','type':'User'}},
    {'user':{'id':9,'login':'human','type':None}},
])
def test_invalid_source_metadata_is_refused(key_file,action,resource,parent_field,parent_resource,permissions,override):
    source={'id':3,'body':'hello','html_url':'https://github.com/acme/demo/'+('issues/1#issuecomment-3' if resource=='issues' else 'pull/1#discussion_r3'), 'user':ACTOR,parent_field:f'https://api.github.com/repos/acme/demo/{parent_resource}/1',**override}
    api=API(key_file,{f'/{resource}/comments/3':source})
    with pytest.raises(ClientError):api.run(action,{'comment_id':3})
    assert not any(r.method in {'PATCH','DELETE'} or (r.method=='POST' and '/comments/' in r.url.path) for r in api.calls)


@pytest.mark.parametrize('action,resource,parent_field,parent_resource,permissions',READS)
@pytest.mark.parametrize('failure',['repository','zero','leading_zero','query','fragment','dot_segment','cross_kind'])
def test_source_parent_must_be_same_repository_and_fixed_kind(key_file,action,resource,parent_field,parent_resource,permissions,failure):
    suffix=f'acme/demo/{parent_resource}/1'
    if failure=='repository':suffix=f'other/demo/{parent_resource}/1'
    elif failure=='zero':suffix=f'acme/demo/{parent_resource}/0'
    elif failure=='leading_zero':suffix=f'acme/demo/{parent_resource}/01'
    elif failure=='query':suffix+='?x=1'
    elif failure=='fragment':suffix+='#f'
    elif failure=='dot_segment':suffix=f'acme/demo/{parent_resource}/../1'
    else:suffix='acme/demo/'+('pulls' if parent_resource=='issues' else 'issues')+'/1'
    source={'id':3,'body':'hello','user':ACTOR,parent_field:'https://api.github.com/repos/'+suffix}
    api=API(key_file,{f'/{resource}/comments/3':source})
    with pytest.raises(ClientError) as caught:api.run(action,{'comment_id':3})
    assert caught.value.code=='target_changed'


@pytest.mark.parametrize('action,resource,permissions',WRITES)
@pytest.mark.parametrize('status,created',[(200,False),(201,True)])
def test_eyes_only_single_post_status_and_actor_allowlist(key_file,action,resource,permissions,status,created):
    reaction={'id':7,'content':'eyes','user':{**BOT,'avatar_url':'hidden'},'extra':'private'}
    api=API(key_file,{('POST',f'/{resource}/comments/3/reactions'):httpx.Response(status,json=reaction)})
    result=api.run(action,{'comment_id':3})
    assert result=={'id':7,'content':'eyes','user':BOT,'created':created}
    assert json.loads(api.calls[0].content)['permissions']==permissions
    assert json.loads(api.calls[-1].content)=={'content':'eyes'}
    assert len(api.calls)==4


@pytest.mark.parametrize('action,resource,permissions',WRITES)
@pytest.mark.parametrize('failure,code',[
    (httpx.Response(404,text='secret-token'),'github_denied'),
    (httpx.Response(403),'github_denied'),(httpx.Response(422),'github_denied'),
    (httpx.Response(503),'uncertain_outcome'),(httpx.ReadTimeout('secret-token'),'uncertain_outcome'),
    (httpx.Response(202,json={'id':7,'content':'eyes','user':BOT}),'uncertain_outcome'),
    (httpx.Response(201,json={'id':True,'content':'eyes','user':BOT}),'uncertain_outcome'),
    (httpx.Response(201,json={'id':7,'content':'heart','user':BOT}),'uncertain_outcome'),
    (httpx.Response(201,json={'id':7,'content':'eyes','user':None}),'uncertain_outcome'),
    (httpx.Response(201,json={'id':7,'content':'eyes','user':BOT,'repository':{'full_name':'other/demo'}}),'uncertain_outcome'),
])
def test_reaction_denial_or_ambiguous_write_never_retries(key_file,action,resource,permissions,failure,code):
    api=API(key_file,{('POST',f'/{resource}/comments/3/reactions'):failure})
    with pytest.raises(ClientError) as caught:api.run(action,{'comment_id':3})
    assert caught.value.code==code and 'secret-token' not in str(caught.value)
    assert len(api.calls)==4


@pytest.mark.parametrize('action',[item[0] for item in READS+WRITES])
def test_comment_identifier_and_no_generic_overrides(action):
    assert validate_params(action,{'comment_id':2**63-1})=={'comment_id':2**63-1}
    for value in ('3',True,False,0,-1,2**63,None,'3/reactions'):
        with pytest.raises(ActionError):validate_params(action,{'comment_id':value})
    for field in ('number','content','url','body','token','method','permissions','config_path'):
        with pytest.raises(ActionError):validate_params(action,{'comment_id':3,field:'override'})
    request=build_request(action,'Acme/Demo',{'comment_id':3})
    assert request.body==({'content':'eyes'} if action.endswith('_reaction') else None)


@pytest.mark.skipif(not __import__('os').getenv('HERMES_GITHUB_APP_HERMES_SOURCE'),reason='opt-in real Hermes dispatch')
def test_native_new_operations_with_real_service_and_fake_http(key_file,tmp_path):
    import os
    import subprocess
    import sys
    config=key_file.parent/'native-config.yaml'
    config.write_text(f'''version: 1
auth:
  app_id: 12
  installation_id: 34
  private_key_path: {key_file}
policy:
  repositories:
    mode: allowlist
    allow: [acme/demo]
    exclude: []
  default_access: read
  allow_actions: [pr_update_body, issue_comment_get, pr_review_comment_get, issue_comment_reaction, pr_review_comment_reaction]
''')
    config.chmod(0o600)
    profile=tmp_path/'native-profile';profile.mkdir()
    (profile/'config.yaml').write_text('toolsets: [github_app]\n')
    script=r'''
import json, secrets, sys
sys.path.insert(0,sys.argv[1])
import httpx
import model_tools
from hermes_cli.plugins import PluginContext, PluginManifest, get_plugin_manager
from hermes_github_app import plugin
from hermes_github_app.client import GitHubClient
calls=[]
bot={'id':10,'login':'sample-app[bot]','type':'Bot'}
human={'id':9,'login':'human','type':'User'}
dummy=secrets.token_urlsafe(32)
def handle(req):
    calls.append(req)
    path=req.url.path
    if path=='/app/installations/34/access_tokens':
        return httpx.Response(201,json={'token':dummy,'permissions':json.loads(req.content)['permissions']})
    if path=='/installation/repositories':
        return httpx.Response(200,json={'total_count':1,'repositories':[{'full_name':'acme/demo'}]})
    if path=='/repos/acme/demo':return httpx.Response(200,json={'full_name':'acme/demo'})
    if req.method=='GET' and path=='/repos/acme/demo/pulls/1':
        return httpx.Response(200,json={'number':1,'state':'closed','merged':True})
    if req.method=='PATCH' and path=='/repos/acme/demo/pulls/1':
        assert json.loads(req.content)=={'body':''}
        return httpx.Response(200,json={'number':1,'body':'','private':'hidden'})
    resource='issues' if '/issues/' in path else 'pulls'
    if req.method=='GET' and path.endswith('/comments/3'):
        field='issue_url' if resource=='issues' else 'pull_request_url'
        html_url='https://github.com/acme/demo/'+('issues/1#issuecomment-3' if resource=='issues' else 'pull/1#discussion_r3')
        return httpx.Response(200,json={'id':3,'body':'Comment text '+dummy,'html_url':html_url,'user':human,
            field:'https://api.github.com/repos/acme/demo/'+resource+'/1','diff_hunk':'hidden-code'})
    if req.method=='POST' and path.endswith('/comments/3/reactions'):
        assert json.loads(req.content)=={'content':'eyes'}
        return httpx.Response(201,json={'id':8,'content':'eyes','user':bot,'arbitrary':'hidden'})
    raise AssertionError('unexpected closed request')
plugin.GitHubClient=lambda **kw:GitHubClient(**kw,transport=httpx.MockTransport(handle))
ctx=PluginContext(PluginManifest(name='hermes-github-app'),get_plugin_manager())
plugin.register(ctx)
for action in ('issue_comment_get','pr_review_comment_get','issue_comment_reaction','pr_review_comment_reaction'):
    args={'repo':'acme/demo','comment_id':3}
    result=json.loads(model_tools.handle_function_call('github_'+action,args,task_id='default',session_id='native-comments',tool_call_id=action))
    assert result['ok'],result
    if action.endswith('_get'):
        assert result['data']['body']=='Comment text [REDACTED]'
        assert result['data']['user']==human
        assert 'diff_hunk' not in result['data']
    else:
        assert result['data']=={'id':8,'content':'eyes','created':True,'user':bot}
    before=len(calls)
    for override in ({'comment_id':'3'},{'comment_id':True},{'content':'heart'},{'url':'https://evil.invalid'}):
        rejected=json.loads(model_tools.handle_function_call('github_'+action,{**args,**override},task_id='default',session_id='native-comments',tool_call_id='bad-'+action))
        assert rejected['code']=='invalid_arguments',rejected
    assert len(calls)==before
result=json.loads(model_tools.handle_function_call('github_pr_update_body',{'repo':'acme/demo','number':1,'body':''},task_id='default',session_id='native-comments',tool_call_id='body'))
assert result=={'ok':True,'data':{'number':1,'html_url':'https://github.com/acme/demo/pull/1'}},result
assert len(calls)==21
print('Five native operations used real protected startup, service and closed mock HTTP')
'''
    env={'HOME':os.environ['HOME'],'PATH':os.environ.get('PATH',''),'HERMES_HOME':str(profile),
         'HERMES_GITHUB_APP_CONFIG':str(config)}
    result=subprocess.run([sys.executable,'-c',script,os.environ['HERMES_GITHUB_APP_HERMES_SOURCE']],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('action,resource,parent_field,parent_resource,permissions',READS)
@pytest.mark.parametrize('failure',['foreign','number','id','anchor','query','missing','wrong_type'])
def test_source_html_url_bound_to_repository_parent_and_comment(key_file,action,resource,parent_field,parent_resource,permissions,failure):
    kind='issues' if resource=='issues' else 'pull'
    anchor='issuecomment-3' if resource=='issues' else 'discussion_r3'
    url=f'https://github.com/acme/demo/{kind}/1#{anchor}'
    if failure=='foreign':url=url.replace('acme/demo','other/demo')
    elif failure=='number':url=url.replace('/1#','/2#')
    elif failure=='id':url=url[:-1]+'4'
    elif failure=='anchor':url=url.replace(anchor,'other-3')
    elif failure=='query':url=url.replace('#','?x=1#')
    elif failure=='missing':url=None
    else:url=3
    source={'id':3,'body':'hello','user':ACTOR,'html_url':url,
            parent_field:f'https://api.github.com/repos/acme/demo/{parent_resource}/1'}
    api=API(key_file,{f'/{resource}/comments/3':source})
    with pytest.raises(ClientError) as caught:api.run(action,{'comment_id':3})
    assert caught.value.code=='target_changed'


def test_pr_conversation_comment_uses_shared_issues_namespace_and_minimal_read(key_file):
    source={'id':3,'body':'Comment text','user':ACTOR,
        'issue_url':'https://api.github.com/repos/acme/demo/issues/17',
        'html_url':'https://github.com/acme/demo/pull/17#issuecomment-3'}
    api=API(key_file,{'/issues/comments/3':source})
    assert api.run('issue_comment_get',{'comment_id':3})==source
    assert json.loads(api.calls[0].content)['permissions']=={'issues':'read'}
    assert api.calls[-1].url.path=='/repos/acme/demo/issues/comments/3'
