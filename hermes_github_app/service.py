"""Policy and isolation gates around closed GitHub operations."""
from .actions import ACTIONS, ActionError, build_request, validate_params
from .client import ClientError
from .policy import PolicyError

class IsolationError(Exception):
    pass


def check_isolation(callback):
    try:
        callback()
    except Exception:
        raise IsolationError() from None


class GitHubService:
    def __init__(self,policy,client):
        self.policy,self.client=policy,client

    def execute(self,action,repo,params,*,recheck_isolation=None):
        try:
            if recheck_isolation is None:
                return {'ok':False,'code':'isolation_refusal','error':'Trusted isolation context is unavailable.'}
            check_isolation(recheck_isolation)
            canonical=self.policy.authorize(repo,action)
            params=validate_params(action,params)
            if action == 'git_push' and 'bundle_path' in params:
                raise ActionError('Bundle path requires native tool dispatch.')
            if action == 'git_push':
                from .git_push import require_supported_host
                require_supported_host()
            request=build_request(action,canonical,params)
            session=self.client.session(canonical,ACTIONS[action].permissions)
            # Session establishes GitHub's canonical name; policy must cover it too.
            self.policy.authorize(session.repo,action)
            if action == 'git_push':
                from .git_push import publish
                def recheck():
                    check_isolation(recheck_isolation)
                    self.policy.authorize(canonical, action)
                    self.policy.authorize(session.repo, action)
                return {'ok': True, 'data': publish(session, params, recheck)}
            if action!='pr_merge':
                return {'ok':True,'data':session.execute(action,params,request)}
            target=session.inspect_merge(params)
            check_isolation(recheck_isolation)
            self.policy.authorize(canonical,action)
            self.policy.authorize(session.repo,action)
            fresh=session.inspect_merge(params)
            fields=('repo','number','base_branch','head_branch','expected_head_sha','merge_method')
            if any(target.get(field) != fresh.get(field) for field in fields):
                raise ClientError('Merge target changed.', 'target_changed')
            data=session.merge(params)
            return {'ok':True,'data':data}
        except PolicyError:
            return {'ok':False,'code':'policy_denied','error':'GitHub action is not permitted.'}
        except ActionError:
            return {'ok':False,'code':'invalid_arguments','error':'Invalid GitHub action parameters.'}
        except ClientError as exc:
            return {'ok':False,'code':exc.code,'error':str(exc)}
        except IsolationError:
            return {'ok':False,'code':'isolation_refusal','error':'Trusted calling context check failed.'}
        except Exception:
            return {'ok':False,'code':'github_unavailable','error':'GitHub operation failed.'}
