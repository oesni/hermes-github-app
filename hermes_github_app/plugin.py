"""Native Hermes entrypoint. Secrets stay on the trusted host."""
from __future__ import annotations
import atexit
import json
import logging
import os
from dataclasses import asdict
from .actions import ACTIONS, PARAMETER_FIELDS, ActionError, canonical_repo, validate_params
from .client import GitHubClient
from .config import ConfigError, parse_config
from .isolation import IsolationError
from .runtime import HostBoundary
from .secure_files import SecureFileError, read_secure_file
from .service import GitHubService

logger = logging.getLogger(__name__)


def register(ctx):
    client = runtime = None
    stage = "config_path"
    try:
        path = os.environ.get('HERMES_GITHUB_APP_CONFIG')
        if not path:
            logger.warning('GitHub App unavailable: configuration path is missing.')
            return
        config_bytes = read_secure_file(path, 1024 * 1024)
        stage = "configuration"
        config = parse_config(config_bytes)
        stage = "private_key"
        from .secure_files import check_secure_file
        check_secure_file(config.auth.private_key_path)
        runtime = HostBoundary(path, config.auth.private_key_path)
        stage = "isolation"
        runtime.check()
        stage = "private_key"
        client = GitHubClient(**asdict(config.auth))
        service = GitHubService(config.policy, client)
    except ConfigError as exc:
        # ConfigError is contractually value-free and safe to show to the admin.
        logger.warning('GitHub App unavailable: %s', exc)
        return
    except SecureFileError as exc:
        logger.warning("GitHub App unavailable: %s %s check failed.", stage, exc.category)
        return
    except IsolationError:
        logger.warning('GitHub App unavailable: protected-file check failed.')
        return
    except Exception:
        if client is not None:
            client.close()
        logger.warning('GitHub App unavailable: %s validation failed.', stage)
        return

    def make_handler(action):
        def invoke(args, **kwargs):
            try:
                runtime.check()
                if not isinstance(args, dict) or 'repo' not in args:
                    raise ActionError('missing repo')
                repo = canonical_repo(args['repo'])
                params = {key: value for key, value in args.items() if key != 'repo'}
                validate_params(action, params)
                result = service.execute(action, repo, params, recheck_isolation=runtime.check)
                return json.dumps(result, ensure_ascii=False)
            except ActionError:
                return json.dumps({'ok': False, 'code': 'invalid_arguments', 'error': 'Invalid tool arguments.'})
            except (IsolationError, SecureFileError):
                return json.dumps({'ok': False, 'code': 'isolation_refusal', 'error': 'Host isolation could not be established.'})
            except Exception:
                return json.dumps({'ok': False, 'code': 'github_unavailable', 'error': 'GitHub operation unavailable.'})
        return invoke

    def close():
        runtime.close()
        client.close()

    for action in ACTIONS:
        handler = make_handler(action)
        schema = tool_schema(action)
        ctx.register_tool(name=schema['name'], toolset='github_app', handler=handler,
                          description=schema['description'], schema=schema)
    if callable(getattr(ctx, 'on_unload', None)):
        ctx.on_unload(close)
    atexit.register(close)


def tool_schema(action):
    """Flat operation schema; preserve strict input types through native Hermes."""
    required, optional = PARAMETER_FIELDS[action]
    properties = {'repo': {'type': 'string', 'description': 'Exact owner/repository'}}
    for field in sorted(required | optional):
        prop = {'type': 'string'}
        if field in {'number', 'page', 'per_page', 'line', 'start_line'}:
            maximum = {'number': 2**31 - 1, 'page': 10000, 'per_page': 100, 'line': 2**31 - 1, 'start_line': 2**31 - 1}[field]
            # Hermes coerces property.type integer/boolean strings before the
            # handler. An equivalent single-branch anyOf preserves the raw
            # JSON value so our strict validator can reject string coercion.
            prop = {'anyOf': [{'type': 'integer', 'minimum': 1, 'maximum': maximum}]}
        elif field == 'labels':
            prop = {'anyOf': [{'type': 'array', 'minItems': 1, 'maxItems': 100, 'uniqueItems': True,
                              'items': {'type': 'string', 'minLength': 1, 'maxLength': 50}}]}
        elif field == 'label':
            prop.update(minLength=1, maxLength=50)
        elif field == 'draft':
            prop = {'anyOf': [{'type': 'boolean'}]}
        elif field == 'state':
            prop['enum'] = ['open', 'closed', 'all']
        elif field in {'side', 'start_side'}:
            prop['enum'] = ['LEFT', 'RIGHT']
        elif field == 'merge_method':
            prop['enum'] = ['merge', 'squash', 'rebase']
        elif field == 'path' and action == 'pr_review_comment':
            prop['maxLength'] = 4096
        elif field in {'title', 'body'}:
            prop['maxLength'] = 256 if field == 'title' else 65536
        properties[field] = prop
    description = action.replace('_', ' ').capitalize() + ' under host repository policy.'
    if action == 'branch_create':
        description += ' Supply source_branch plus expected_source_sha, or source_commit_sha; never both.'
    if action == 'issue_labels_add':
        description += ' Add existing repository labels to an issue; preserve unrelated labels. Requires explicit policy allowance.'
    if action == 'issue_label_remove':
        description += ' Remove one named label from an issue; preserve unrelated labels. Requires explicit policy allowance.'
    if action == 'pr_review_comment':
        description += ' Add an inline diff comment to an open PR whose head matched commit_id when checked. Optional start_line/start_side must be paired on the same side.'
    if action == 'pr_merge':
        description += ' Requires explicit policy allowance and the expected PR head SHA; GitHub protections apply.'
    return {'name': 'github_' + action, 'description': description, 'parameters': {
        'type': 'object', 'additionalProperties': False,
        'properties': properties, 'required': ['repo', *sorted(required)],
    }}
