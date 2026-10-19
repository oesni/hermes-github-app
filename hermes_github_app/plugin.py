"""Native Hermes entrypoint. Secrets and approvals stay on the trusted host."""
from __future__ import annotations
import atexit
import json
import logging
import os
from dataclasses import asdict
from .actions import ACTIONS, PARAMETER_FIELDS, ActionError, canonical_repo, validate_params
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

    def make_handler(action):
        def invoke(args, **kwargs):
            try:
                call = runtime.current_call()
                if not isinstance(args, dict) or 'repo' not in args:
                    raise ActionError('missing repo')
                repo = canonical_repo(args['repo'])
                params = {key: value for key, value in args.items() if key != 'repo'}
                validate_params(action, params)
                result = service.execute(action, repo, params,
                                         context=call, recheck_isolation=lambda: runtime.check(call))
                return json.dumps(result, ensure_ascii=False)
            except ActionError:
                return json.dumps({'ok': False, 'error': 'invalid_arguments'})
            except (IsolationError, SecureFileError):
                return json.dumps({'ok': False, 'error': 'isolation_refused'})
            except Exception:
                return json.dumps({'ok': False, 'error': 'github_unavailable'})
        return invoke

    def close():
        runtime.close()
        approvals.close()
        adapter.close()
        client.close()

    for action in ACTIONS:
        handler = make_handler(action)
        runtime.handlers[action] = handler
        schema = tool_schema(action)
        ctx.register_tool(name=action, toolset='github_app', handler=handler,
                          description=schema['description'], schema=schema)
    ctx.register_middleware('tool_execution', runtime.middleware)
    ctx.register_hook('pre_tool_call', runtime.pre_tool)
    if callable(getattr(ctx, 'on_unload', None)):
        ctx.on_unload(close)
    atexit.register(close)


def tool_schema(action):
    """Flat operation schema; preserve strict input types through native Hermes."""
    required, optional = PARAMETER_FIELDS[action]
    properties = {'repo': {'type': 'string', 'description': 'Exact owner/repository'}}
    for field in sorted(required | optional):
        prop = {'type': 'string'}
        if field in {'number', 'page', 'per_page'}:
            maximum = {'number': 2**31 - 1, 'page': 10000, 'per_page': 100}[field]
            # Hermes coerces property.type integer/boolean strings before the
            # middleware. An equivalent single-branch anyOf preserves the raw
            # JSON value so our strict validator can reject string coercion.
            prop = {'anyOf': [{'type': 'integer', 'minimum': 1, 'maximum': maximum}]}
        elif field == 'draft':
            prop = {'anyOf': [{'type': 'boolean'}]}
        elif field == 'state':
            prop['enum'] = ['open', 'closed', 'all']
        elif field == 'merge_method':
            prop['enum'] = ['merge', 'squash', 'rebase']
        elif field in {'title', 'body'}:
            prop['maxLength'] = 256 if field == 'title' else 65536
        properties[field] = prop
    description = action.replace('_', ' ').capitalize() + ' under host repository policy.'
    if action == 'branch_create':
        description += ' Supply source_branch plus expected_source_sha, or source_commit_sha; never both.'
    if action == 'pr_merge':
        description += ' Requires a separate authenticated human Discord confirmation for this exact PR and head.'
    return {'name': action, 'description': description, 'parameters': {
        'type': 'object', 'additionalProperties': False,
        'properties': properties, 'required': ['repo', *sorted(required)],
    }}
