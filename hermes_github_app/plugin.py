"""Native Hermes entrypoint. Secrets and approvals stay on the trusted host."""
from __future__ import annotations
import atexit
import json
import logging
import os
from dataclasses import asdict
from .actions import ACTIONS
from .approvals import MergeApprovals
from .client import GitHubClient
from .config import ConfigError, parse_config
from .discord_approval import DiscordApprovalAdapter
from .isolation import IsolationError
from .runtime import HermesRuntime
from .secure_files import SecureFileError, read_secure_file
from .service import GitHubService

logger = logging.getLogger(__name__)


def register(ctx):
    client = runtime = adapter = approvals = None
    try:
        path = os.environ.get('HERMES_GITHUB_APP_CONFIG')
        if not path:
            logger.warning('GitHub App unavailable: configuration path is missing.')
            return
        config = parse_config(read_secure_file(path, 1024 * 1024))
        runtime = HermesRuntime(ctx, path, config.auth.private_key_path)
        runtime.check()
        client = GitHubClient(**asdict(config.auth))
        ids = tuple(a.user_id for a in config.merge_approval.approvers)
        adapter = DiscordApprovalAdapter(ids)
        approvals = MergeApprovals(adapter, ids)
        service = GitHubService(config.policy, client, approvals)
    except ConfigError as exc:
        # ConfigError is contractually value-free and safe to show to the admin.
        logger.warning('GitHub App unavailable: %s', exc)
        return
    except SecureFileError:
        logger.warning('GitHub App unavailable: protected file ownership, mode, or path check failed.')
        return
    except IsolationError:
        logger.warning('GitHub App unavailable: sandbox or tool-surface isolation check failed.')
        return
    except Exception:
        if client is not None:
            client.close()
        logger.warning('GitHub App unavailable: private key or host compatibility check failed.')
        return

    def invoke(args, **kwargs):
        try:
            call = runtime.current_call()
            if not isinstance(args, dict) or set(args) != {'action', 'repo', 'params'}:
                return json.dumps({'ok': False, 'error': 'invalid_arguments'})
            result = service.execute(args['action'], args['repo'], args['params'],
                                     context=call, recheck_isolation=lambda: runtime.check(call))
            return json.dumps(result, ensure_ascii=False)
        except (IsolationError, SecureFileError):
            return json.dumps({'ok': False, 'error': 'isolation_refused'})
        except Exception:
            return json.dumps({'ok': False, 'error': 'github_unavailable'})

    def close():
        runtime.close()
        approvals.close()
        adapter.close()
        client.close()

    runtime.handler = invoke
    description = ('Perform a policy-bound GitHub action using host-owned App credentials. '
                   'Merge requires a separate authenticated human Discord confirmation; action grants never supply consent.')
    ctx.register_tool(name='github_app_action', toolset='github_app', handler=invoke, description=description,
        schema={'name': 'github_app_action', 'description': description, 'parameters': {
            'type': 'object', 'additionalProperties': False,
            'properties': {
                'action': {'type': 'string', 'enum': sorted(ACTIONS)},
                'repo': {'type': 'string', 'description': 'Exact owner/repository'},
                'params': {'type': 'object', 'description': (
                    'Closed action arguments. repo.get {}; contents.read {path,ref?}; '
                    'issues/pulls.list {state?,page?,per_page?}; issues/pulls.get {number}; '
                    'issues/pulls.comments.list {number,page?,per_page?}; issues.create {title,body?}; '
                    'issues/pulls.comment {number,body}; pulls.create {title,head,base,body?,draft?}; '
                    'branches.create {branch,source_branch,expected_source_sha} OR {branch,source_commit_sha}; '
                    'pulls.merge {number,expected_head_sha,merge_method:merge|squash|rebase}.')},
            }, 'required': ['action', 'repo', 'params'],
        }})
    ctx.register_middleware('tool_execution', runtime.middleware)
    ctx.register_hook('pre_tool_call', runtime.pre_tool)
    if callable(getattr(ctx, 'on_unload', None)):
        ctx.on_unload(close)
    atexit.register(close)
