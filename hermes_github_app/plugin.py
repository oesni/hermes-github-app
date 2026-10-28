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
from .policy import PolicyError
from .bundle_input import BundleInputError, resolve_bundle_path

logger = logging.getLogger(__name__)


def _open_host_service():
    client = runtime = None
    ready = False
    stage = "config_path"
    try:
        path = os.environ.get('HERMES_GITHUB_APP_CONFIG')
        if not path:
            logger.warning('GitHub App unavailable: configuration path is missing.')
            return None
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
        ready = True
    except ConfigError as exc:
        # ConfigError is contractually value-free and safe to show to the admin.
        logger.warning('GitHub App unavailable: %s', exc)
        return None
    except SecureFileError as exc:
        logger.warning("GitHub App unavailable: %s %s check failed.", stage, exc.category)
        return None
    except IsolationError:
        logger.warning('GitHub App unavailable: protected-file check failed.')
        return None
    except Exception:
        logger.warning('GitHub App unavailable: %s validation failed.', stage)
        return None
    finally:
        if not ready:
            for resource in (client, runtime):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass

    return runtime, client, service


def _execute_host_operation(runtime, service, action, args, *, dispatcher=None, context=None):
    """Validate and execute one closed operation for a registered tool."""
    try:
        runtime.check()
        if not isinstance(args, dict) or 'repo' not in args:
            raise ActionError('missing repo')
        repo = canonical_repo(args['repo'])
        params = {key: value for key, value in args.items() if key != 'repo'}
        validate_params(action, params)
        if action == 'git_push' and 'bundle_path' in params:
            # Policy precedes sandbox reads; the service repeats policy/isolation
            # checks after transfer and immediately before the remote write.
            service.policy.authorize(repo, action)
            from .git_push import MAX_BUNDLE_BYTES
            encoded = resolve_bundle_path(dispatcher, params['bundle_path'], context, MAX_BUNDLE_BYTES)
            params = {key: value for key, value in params.items() if key != 'bundle_path'}
            params['bundle_base64'] = encoded
        return service.execute(action, repo, params, recheck_isolation=runtime.check)
    except PolicyError:
        return {'ok': False, 'code': 'policy_denied', 'error': 'GitHub action is not permitted.'}
    except BundleInputError as exc:
        # Messages are fixed strings chosen by bundle_input, never terminal output.
        return {'ok': False, 'code': 'bundle_unavailable', 'error': 'Sandbox bundle could not be read safely in the active terminal task: ' + str(exc)}
    except ActionError:
        return {'ok': False, 'code': 'invalid_arguments', 'error': 'Invalid tool arguments.'}
    except (IsolationError, SecureFileError):
        return {'ok': False, 'code': 'isolation_refusal', 'error': 'Host isolation could not be established.'}
    except Exception:
        return {'ok': False, 'code': 'github_unavailable', 'error': 'GitHub operation unavailable.'}


def register(ctx):
    opened = _open_host_service()
    if opened is None:
        return
    runtime, client, service = opened

    def make_handler(action):
        def invoke(args, **kwargs):
            return json.dumps(_execute_host_operation(runtime, service, action, args,
                            dispatcher=getattr(ctx, 'dispatch_tool', None), context=kwargs), ensure_ascii=False)
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
        if field == 'expected_head_sha' and action == 'git_push':
            prop = {'anyOf': [{'type': 'string', 'pattern': '^[a-fA-F0-9]{40}$'}, {'type': 'null'}]}
        elif field == 'bundle_path':
            prop.update(minLength=1, maxLength=4096, description='Absolute Git bundle path in the active terminal sandbox; requires terminal task context and python3.')
        elif field == 'bundle_base64':
            from .git_push import MAX_BUNDLE_BYTES
            prop.update(maxLength=4 * ((MAX_BUNDLE_BYTES + 2) // 3))
        elif field in {'number', 'comment_id', 'page', 'per_page', 'line', 'start_line'}:
            maximum = {'number': 2**31 - 1, 'comment_id': 2**63 - 1, 'page': 10000, 'per_page': 100, 'line': 2**31 - 1, 'start_line': 2**31 - 1}[field]
            # Hermes coerces property.type integer/boolean strings before the
            # handler. An equivalent single-branch anyOf preserves the raw
            # JSON value so our strict validator can reject string coercion.
            prop = {'anyOf': [{'type': 'integer', 'minimum': 1, 'maximum': maximum}]}
        elif field == 'labels':
            prop = {'anyOf': [{'type': 'array', 'minItems': 1, 'maxItems': 100, 'uniqueItems': True,
                              'items': {'type': 'string', 'minLength': 1, 'maxLength': 50}}]}
        elif field == 'name' and action in {'label_create', 'label_get'}:
            prop.update(minLength=1, maxLength=50)
        elif field == 'color' and action == 'label_create':
            prop.update(pattern='^[a-fA-F0-9]{6}$', description='Six hexadecimal digits without #.')
        elif field == 'description' and action == 'label_create':
            prop.update(maxLength=100)
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
    if action == 'git_push':
        description += ' Supply exactly one of bundle_path (active terminal sandbox) or bundle_base64 (direct data). Publish a bounded Git bundle without exposing credentials. Requires explicit allowance; expected_head_sha is null for creation or the exact current head for a fast-forward. An incremental bundle may exclude commits already in the repository, including a merged base branch. Never retries uncertain pushes.'
    if action == 'branch_create':
        description += ' Supply source_branch plus expected_source_sha, or source_commit_sha; never both.'
    if action in {'issue_comment_get', 'pr_review_comment_get'}:
        description += ' Read one source comment by ID with body, actor and parent metadata only. Requires explicit policy allowance.'
    if action in {'issue_comment_reaction', 'pr_review_comment_reaction'}:
        description += ' Add only an eyes reaction to one comment ID. Requires explicit policy allowance; never retries uncertain writes.'
    if action == 'pr_update_body':
        description += ' Replace only the body of an existing PR, including an empty body. Requires explicit policy allowance; concurrent edits are not protected.'
    if action == 'label_get':
        description += ' Read one repository label by name. Requires explicit policy allowance. Returns current existence and metadata only; does not establish why a previous creation failed, who created it, or whether a prior request is still pending. Never creates or retries mutations.'
    if action == 'label_create':
        description += ' Create a repository label with name, six-digit color and optional description. Requires explicit policy allowance. Existing names are rejected; never updates labels or retries uncertain writes.'
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
