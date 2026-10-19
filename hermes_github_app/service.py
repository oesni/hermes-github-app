"""Policy and isolation gates around closed GitHub operations."""
from .actions import ACTIONS, ActionError, build_request, validate_params
from .approvals import ApprovalError
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
    def __init__(self,policy,client,approvals=None):
        self.policy,self.client,self.approvals=policy,client,approvals

    def execute(self,action,repo,params,*,context=None,recheck_isolation=None):
        try:
            if recheck_isolation is None:
                return {'ok':False,'code':'isolation_refusal','error':'Trusted isolation context is unavailable.'}
            check_isolation(recheck_isolation)
            canonical=self.policy.authorize(repo,action)
            params=validate_params(action,params)
            request=build_request(action,canonical,params)
            if action=='pr_merge' and (self.approvals is None or context is None or not self.approvals.available()):
                raise ApprovalError('approval_required_unavailable')
            session=self.client.session(canonical,ACTIONS[action].permissions)
            # Session establishes GitHub's canonical name; policy must cover it too.
            self.policy.authorize(session.repo,action)
            if action!='pr_merge':
                return {'ok':True,'data':session.execute(action,params,request)}
            target=session.inspect_merge(params)
            def recheck():
                check_isolation(recheck_isolation)
                self.policy.authorize(canonical,action)
                # Fresh token/metadata/prerequisites after the potentially long wait.
                nonlocal session
                session=self.client.session(canonical,ACTIONS[action].permissions)
                self.policy.authorize(session.repo,action)
                return session.inspect_merge(params)
            data=self.approvals.run(target,context,recheck,lambda:session.merge(params))
            return {'ok':True,'data':data}
        except PolicyError:
            return {'ok':False,'code':'policy_denied','error':'GitHub action is not permitted.'}
        except ActionError:
            return {'ok':False,'code':'invalid_arguments','error':'Invalid GitHub action parameters.'}
        except ApprovalError as exc:
            return {'ok':False,'code':exc.code,'error':exc.code}
        except ClientError as exc:
            return {'ok':False,'code':exc.code,'error':str(exc)}
        except IsolationError:
            return {'ok':False,'code':'isolation_refusal','error':'Trusted calling context check failed.'}
        except Exception:
            return {'ok':False,'code':'github_unavailable','error':'GitHub operation failed.'}
