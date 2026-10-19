"""Host-only, repository-scoped GitHub App transport and closed operations."""
from __future__ import annotations
import base64
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import quote
import httpx
import jwt

MAX_RESPONSE_BYTES = 3 * 1048576
MAX_FILE_BYTES = 1048576
MAX_KEY_BYTES = 32768
OPERATION_TIMEOUT = 120

class ClientError(Exception):
    def __init__(self, message="GitHub request failed.", code="github_unavailable"):
        super().__init__(message)
        self.code = code

@dataclass
class Response:
    data: object
    has_more: bool = False

class GitHubClient:
    def __init__(self, app_id, installation_id, private_key_path, *, transport=None):
        if any(type(v) is not int or not 1 <= v <= 2**63 - 1 for v in (app_id, installation_id)):
            raise ClientError("Invalid GitHub App configuration.")
        self._app_id, self._installation_id = str(app_id), str(installation_id)
        self._key = self._read_key(private_key_path)
        self._http = httpx.Client(base_url="https://api.github.com", trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(15, connect=5), transport=transport)

    @staticmethod
    def _read_key(path):
        try:
            from .secure_files import read_secure_file
            key = read_secure_file(path, MAX_KEY_BYTES).decode("ascii")
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            parsed = load_pem_private_key(key.encode(), password=None)
            if not isinstance(parsed, RSAPrivateKey) or parsed.key_size < 2048:
                raise ValueError()
            return key
        except Exception:
            raise ClientError("Cannot load secure GitHub App private key.") from None

    def close(self):
        self._http.close()

    def _request(self, method, path, token, *, query=None, body=None, missing=False, mutation=False, deadline=None):
        if deadline is not None and time.monotonic() >= deadline:
            raise ClientError("GitHub operation timed out.")
        started = time.monotonic()
        try:
            with self._http.stream(method, path, params=query, json=body, headers={
                "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "hermes-github-app",
                "Accept-Encoding": "identity",
            }) as response:
                if response.status_code == 404 and missing:
                    return Response(None)
                if not 200 <= response.status_code < 300:
                    if mutation and response.status_code >= 500:
                        raise ClientError("GitHub mutation outcome is uncertain.", "uncertain_outcome")
                    raise ClientError("GitHub denied the request.", "github_denied")
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise ValueError()
                payload = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > 30 or (deadline and time.monotonic() >= deadline):
                        raise TimeoutError()
                    if len(payload) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ClientError("GitHub response exceeds the size limit.", "size_limit")
                    payload.extend(chunk)
                return Response(json.loads(payload) if payload else None,
                    any(re.search(r';\s*rel="next"', part) for part in response.headers.get("link", "").split(",")))
        except ClientError as exc:
            if mutation and exc.code not in {"github_denied", "uncertain_outcome"}:
                raise ClientError("GitHub mutation outcome is uncertain.", "uncertain_outcome") from None
            raise
        except BaseException as exc:
            if mutation:
                raise ClientError("GitHub mutation outcome is uncertain.", "uncertain_outcome") from None
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ClientError("GitHub request failed.") from None

    def session(self, repo, permissions):
        from .actions import canonical_repo
        repo = canonical_repo(repo)
        now = int(time.time())
        try:
            app_jwt = jwt.encode({"iat": now-60, "exp": now+540, "iss": self._app_id}, self._key, algorithm="RS256")
        except Exception:
            raise ClientError("GitHub App authentication failed.") from None
        deadline = time.monotonic() + OPERATION_TIMEOUT
        grant = self._request("POST", f"/app/installations/{self._installation_id}/access_tokens", app_jwt,
            body={"repositories": [repo.split('/')[1]], "permissions": permissions}, deadline=deadline).data
        allowed = {**permissions, "metadata": "read"}
        if (not isinstance(grant, dict) or not isinstance(grant.get("token"), str) or not grant['token']
            or not isinstance(grant.get('permissions'), dict)
            or any(grant['permissions'].get(k) != v for k,v in permissions.items())
            or any(allowed.get(k) != v for k,v in grant['permissions'].items())):
            raise ClientError("GitHub token scope verification failed.")
        token = grant['token']
        scope = self._request("GET", "/installation/repositories", token, query={"per_page":2}, deadline=deadline).data
        if (not isinstance(scope,dict) or scope.get('total_count') != 1
            or not isinstance(scope.get('repositories'),list) or len(scope['repositories']) != 1
            or not isinstance(scope['repositories'][0],dict)
            or str(scope['repositories'][0].get('full_name','')).lower() != repo):
            raise ClientError("GitHub token repository verification failed.")
        session = Session(self, repo, token, (self._key,app_jwt,token), deadline)
        session.metadata = session.get("")
        session.check_repo(session.metadata, required=True)
        return session

    @classmethod
    def _redact(cls,value,secrets):
        if isinstance(value,str):
            for secret in secrets:
                value = value.replace(secret,"[REDACTED]")
            return value
        if isinstance(value,list): return [cls._redact(x,secrets) for x in value]
        if isinstance(value,dict): return {cls._redact(k,secrets):cls._redact(v,secrets) for k,v in value.items()}
        return value

class Session:
    def __init__(self,client,repo,token,secrets,deadline):
        self.client,self.repo,self._token,self._secrets,self.deadline = client,repo,token,secrets,deadline
        self.prefix = '/repos/'+repo
        self.metadata = None

    def request(self,method,path,**kwargs):
        if not path.startswith('/') and path != '': raise ClientError("Invalid GitHub operation.")
        return self.client._request(method,self.prefix+path,self._token,deadline=self.deadline,**kwargs)
    def get(self,path,**kwargs): return self.request('GET',path,**kwargs).data
    def safe(self,value): return self.client._redact(value,self._secrets)
    def check_repo(self,value,required=False):
        if not isinstance(value,dict) or (required and str(value.get('full_name','')).lower()!=self.repo):
            raise ClientError("GitHub repository identity mismatch.","target_changed")
        if 'full_name' in value and str(value['full_name']).lower()!=self.repo:
            raise ClientError("GitHub repository identity mismatch.","target_changed")
        if 'repository' in value: self.check_repo(value['repository'],True)
        if isinstance(value.get('base'),dict) and 'repo' in value['base']: self.check_repo(value['base']['repo'],True)
    def sha(self,value):
        if not isinstance(value,str) or not re.fullmatch(r'(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):
            raise ClientError("Unverifiable GitHub object.")
        return value.lower()
    def ref(self,kind,name,missing=False):
        value=self.get('/git/ref/'+kind+'/'+quote(name,safe=''),missing=missing)
        if value is None and missing:return None
        if not isinstance(value,dict) or value.get('ref')!='refs/'+kind+'/'+name or not isinstance(value.get('object'),dict):
            raise ClientError("Unverifiable GitHub reference.")
        return value['object']
    def peel(self,obj):
        for _ in range(16):
            if not isinstance(obj,dict): break
            sha=self.sha(obj.get('sha'))
            if obj.get('type')=='commit': return sha
            if obj.get('type')!='tag':break
            tag=self.get('/git/tags/'+sha)
            obj=tag.get('object') if isinstance(tag,dict) else None
        raise ClientError("Unverifiable GitHub reference.")
    def branch(self,name): return self.peel(self.ref('heads',name))
    def resolve(self,name=None):
        if name is None:
            from .actions import valid_ref
            name=valid_ref(self.metadata.get('default_branch'),branch=True)
            return self.branch(name)
        branch,tag=self.ref('heads',name,True),self.ref('tags',name,True)
        if (branch is None)==(tag is None):raise ClientError("Missing or ambiguous GitHub reference.","invalid_arguments")
        return self.peel(branch if branch is not None else tag)
    def target(self,number,pull):
        value=self.get('/pulls/'+str(number) if pull else '/issues/'+str(number),missing=True)
        if not isinstance(value,dict) or (not pull and 'pull_request' in value):
            raise ClientError("GitHub action target type is not permitted.","invalid_arguments")
        if value.get('number')!=number:raise ClientError("GitHub target mismatch.","target_changed")
        self.check_repo(value)
        return value

    def contents(self,params):
        commit=self.get('/git/commits/'+self.resolve(params.get('ref')))
        tree_sha=self.sha(commit.get('tree',{}).get('sha')) if isinstance(commit,dict) else self.sha(None)
        parts=params['path'].split('/') if params['path'] else []
        for index in range(len(parts)+1):
            tree=self.get('/git/trees/'+tree_sha)
            if not isinstance(tree,dict) or tree.get('truncated') or not isinstance(tree.get('tree'),list):
                raise ClientError("Unverifiable directory listing.")
            entries=tree['tree']
            if index==len(parts):
                return {'type':'dir','path':params['path'],'entries':[self.entry(e) for e in entries]}
            matches=[e for e in entries if isinstance(e,dict) and e.get('path')==parts[index]]
            if len(matches)!=1:raise ClientError("Content not found.","github_denied")
            entry=matches[0]
            mode=entry.get('mode')
            if index<len(parts)-1:
                if mode!='040000':raise ClientError("Content traversal is not permitted.","invalid_arguments")
                tree_sha=self.sha(entry.get('sha'));continue
            result=self.entry(entry);result['path']=params['path']
            if mode=='040000':
                tree_sha=self.sha(entry.get('sha'));continue
            if mode in {'120000','160000'}:return result
            if mode not in {'100644','100755'}:raise ClientError("Unsupported content type.")
            if type(entry.get('size')) is not int or not 0<=entry['size']<=MAX_FILE_BYTES:raise ClientError("File exceeds the size limit.","size_limit")
            blob=self.get('/git/blobs/'+self.sha(entry.get('sha')))
            try:
                if blob.get('encoding')!='base64':raise ValueError()
                decoded=base64.b64decode(''.join(blob['content'].split()),validate=True)
                if len(decoded)!=entry['size'] or blob.get('size')!=len(decoded):raise ValueError()
                if len(decoded)>MAX_FILE_BYTES:raise ValueError()
            except Exception:raise ClientError("Invalid file content or size.","size_limit") from None
            result.update(encoding='base64',content=base64.b64encode(decoded).decode('ascii'),size=len(decoded))
            return result
        raise ClientError("Content lookup failed.")
    def entry(self,e):
        if not isinstance(e,dict):raise ClientError("Invalid tree entry.")
        kinds={'040000':'dir','100644':'file','100755':'file','120000':'symlink','160000':'submodule'}
        if e.get('mode') not in kinds:raise ClientError("Unsupported tree entry.")
        return {'name':e.get('path'),'sha':self.sha(e.get('sha')),'type':kinds[e['mode']],**({'size':e['size']} if 'size' in e else {})}

    def create_branch(self,params):
        name=params['branch']
        if self.ref('heads',name,True) is not None or self.ref('tags',name,True) is not None:
            raise ClientError("Branch or tag already exists.","invalid_arguments")
        if 'source_branch' in params:
            sha=self.branch(params['source_branch'])
            if sha!=params['expected_source_sha']:raise ClientError("Source branch changed.","target_changed")
        else:
            sha=params['source_commit_sha'];reachable=False
            for kind in ('heads','tags'):
                refs=self.get('/git/matching-refs/'+kind+'/')
                if not isinstance(refs,list):raise ClientError("Cannot verify source reachability.")
                for ref in refs:
                    if not isinstance(ref,dict) or not str(ref.get('ref','')).startswith('refs/'+kind+'/'):raise ClientError("Invalid source reference.")
                    tip=self.peel(ref.get('object'))
                    if len(tip)!=len(sha):continue
                    if tip==sha:reachable=True;break
                    comparison=self.get('/compare/'+sha+'...'+tip,missing=True)
                    if isinstance(comparison,dict) and comparison.get('status') in {'ahead','identical'}:
                        if self.sha(comparison.get('merge_base_commit',{}).get('sha'))==sha:reachable=True;break
                if reachable:break
            if not reachable:raise ClientError("Source commit is not reachable from repository references.","invalid_arguments")
        commit=self.get('/git/commits/'+sha)
        if not isinstance(commit,dict) or self.sha(commit.get('sha'))!=sha:raise ClientError("Unverifiable source commit.")
        result=self.request('POST','/git/refs',body={'ref':'refs/heads/'+name,'sha':sha},mutation=True).data
        try:
            if not isinstance(result,dict) or result.get('ref')!='refs/heads/'+name or not isinstance(result.get('object'),dict) or result['object'].get('sha')!=sha:
                raise ValueError()
            return {'branch':name,'sha':sha}
        except BaseException:
            raise ClientError("GitHub mutation outcome is uncertain.","uncertain_outcome") from None

    def inspect_merge(self,params):
        value=self.target(params['number'],True)
        try:
            self.check_repo(value['head']['repo'],True)
            if value['state']!='open' or value.get('draft') is not False or value.get('merged') is not False or self.sha(value['head']['sha'])!=params['expected_head_sha']:
                raise ValueError()
            from .actions import valid_ref
            base=valid_ref(value['base']['ref'],branch=True);head=valid_ref(value['head']['ref'],branch=True)
            if self.metadata.get({'merge':'allow_merge_commit','squash':'allow_squash_merge','rebase':'allow_rebase_merge'}[params['merge_method']]) is False:raise ValueError()
            return self.safe({'repo':self.repo,'number':params['number'],'base_branch':base,'head_branch':head,
                'expected_head_sha':params['expected_head_sha'],'merge_method':params['merge_method'],
                'url':f'https://github.com/{self.repo}/pull/{params["number"]}','title':str(value.get('title',''))})
        except ClientError:raise
        except Exception:raise ClientError("Merge prerequisites are not satisfied.","target_changed") from None
    def merge(self,params):
        result=self.request('PUT',f'/pulls/{params["number"]}/merge',body={'sha':params['expected_head_sha'],'merge_method':params['merge_method']},mutation=True).data
        if not isinstance(result,dict) or result.get('merged') is not True:
            raise ClientError("GitHub did not confirm the merge.","uncertain_outcome")
        try:sha=self.sha(result.get('sha'))
        except ClientError:raise ClientError("GitHub mutation outcome is uncertain.","uncertain_outcome") from None
        return self.safe({'merged':True,'sha':sha})

    def execute(self,action,params,request):
        if action=='contents_read':result=self.contents(params)
        elif action=='branch_create':result=self.create_branch(params)
        else:
            if action in {'issue_comments_list','pr_comments_list','issue_comment','pr_comment'}:
                self.target(params['number'],action.startswith('pr_'))
            if action=='pr_create':
                self.branch(params['head']);self.branch(params['base'])
            if action in {'issue_get','pr_get'}:
                return self.safe(self.target(params['number'],action.startswith('pr_')))
            response=self.request(request.method,request.path.removeprefix(self.prefix),query=request.query,body=request.body,mutation=request.method!='GET')
            try:
                result=response.data
                if action.endswith('_list'):
                    if not isinstance(result,list):raise ClientError("Invalid GitHub list response.")
                    for item in result:self.check_repo(item)
                    if action=='issue_list':result=[x for x in result if 'pull_request' not in x]
                    result={'items':result,'page':params['page'],'per_page':params['per_page'],'has_more':response.has_more}
                elif isinstance(result,dict):self.check_repo(result)
                elif request.method!='GET':raise ValueError()
                return self.safe(result)
            except BaseException:
                if request.method!='GET':raise ClientError('GitHub mutation outcome is uncertain.','uncertain_outcome') from None
                raise
        try:
            return self.safe(result)
        except BaseException:
            if action=='branch_create':
                raise ClientError('GitHub mutation outcome is uncertain.','uncertain_outcome') from None
            raise
