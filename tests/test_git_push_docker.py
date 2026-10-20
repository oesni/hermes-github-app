"""Opt-in real Docker producer → public tool → host Git publication."""
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

from git_fixtures import git
from hermes_github_app import plugin, git_push
from hermes_github_app.policy import Policy
from hermes_github_app.service import GitHubService
from hermes_github_app.client import Session
import time


@pytest.mark.skipif(not os.getenv('HERMES_GITHUB_APP_DOCKER_IMAGE'), reason='opt-in isolated Docker integration')
def test_docker_bundle_path_public_handler(monkeypatch,tmp_path):
    image=os.environ['HERMES_GITHUB_APP_DOCKER_IMAGE']
    def docker(*args):
        return subprocess.run(['docker',*args],capture_output=True,text=True,check=True).stdout.strip()
    container=docker('run','-d','--rm',image,'sleep','300')
    try:
        docker('exec',container,'git','--version')
        script='''mkdir /sandbox && cd /sandbox && git init -b feature && git config user.name "Test Author" && git config user.email author@example.invalid && printf first > file.txt && git add file.txt && git commit -m "First" && printf second >> file.txt && git commit -am "Second" && git bundle create /sandbox/publish.bundle refs/heads/feature'''
        docker('exec',container,'sh','-c',script)
        sha=docker('exec',container,'git','-C','/sandbox','rev-parse','HEAD')
        assert not Path('/sandbox/publish.bundle').exists()
        remote=tmp_path/'remote.git';remote.mkdir();git(remote,'init','--bare')
        monkeypatch.setattr(git_push,'_remote',lambda repo:str(remote))
        original=git_push._run
        monkeypatch.setattr(git_push,'_run',lambda root,args,*a,**kw:original(root,['-c','protocol.file.allow=always',*args],*a,**kw))
        client=Mock()
        client.session.return_value=Session(client,'acme/demo','test-only-secret',[],time.monotonic()+120)
        policy=Policy.from_dict({'repositories':{'mode':'all','exclude':[]},'default_access':'read','allow_actions':['git_push']})
        runtime=Mock()
        monkeypatch.setattr(plugin,'_open_host_service',lambda:(runtime,client,GitHubService(policy,client)))
        ctx=Mock();calls=[]
        def dispatch(name,args,**context):
            calls.append((name,context))
            completed=subprocess.run(['docker','exec',container,'sh','-c',args['command']],capture_output=True,text=True)
            return json.dumps({'exit_code':completed.returncode,'output':completed.stdout})
        ctx.dispatch_tool=dispatch
        plugin.register(ctx)
        handlers={c.kwargs['name']:c.kwargs['handler'] for c in ctx.register_tool.call_args_list}
        result=json.loads(handlers['github_git_push']({'repo':'acme/demo','branch':'feature','commit_sha':sha,'expected_head_sha':None,'bundle_path':'/sandbox/publish.bundle'},task_id='docker-task',session_id='docker-session'))
        assert result['ok'],result
        assert git(remote,'rev-parse','refs/heads/feature').decode().strip()==sha
        assert git(remote,'show','feature:file.txt')==b'firstsecond'
        assert git(remote,'rev-list','--count','feature').strip()==b'2'
        assert calls and all(name=='terminal' and context=={'task_id':'docker-task','session_id':'docker-session'} for name,context in calls)
        inspected=json.loads(docker('inspect',container))[0]
        assert not inspected['Mounts']
        assert not any('TOKEN=' in item for item in inspected['Config']['Env'])
        assert 'test-only-secret' not in json.dumps(result)
    finally:
        docker('rm','-f',container)
