"""Local checks and optional receipt validation for the isolated VM probe."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import pytest
from hermes_github_app.actions import ACTIONS


def test_candidate_addition_preserves_operator_permissions():
    helper = Path(__file__).resolve().parents[1] / 'tools/gormes_coexistence_probe.py'
    spec = importlib.util.spec_from_file_location('coexist_helper', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    old = frozenset({'terminal', 'orpheus_spawn', 'existing_security_tool'})
    public_tools = {'github_' + action for action in ACTIONS}
    candidate = module.add_candidate_actions(old, public_tools)
    assert old <= candidate
    assert candidate - old == public_tools
    assert old == frozenset({'terminal', 'orpheus_spawn', 'existing_security_tool'})


@pytest.mark.skipif(not os.getenv('HERMES_GITHUB_APP_GORMES_RECEIPT'), reason='opt-in isolated Gormes receipt')
def test_isolated_gormes_receipt():
    receipt = json.loads(Path(os.environ['HERMES_GITHUB_APP_GORMES_RECEIPT']).read_text())
    assert receipt['passed'] is True
    assert receipt['production_changed'] is False
    assert receipt['github_network'] is False
    assert receipt['stages']['unchanged_production_hook']['new_tool_blocked'] is True
    candidate = receipt['stages']['additive_policy_candidate']
    assert candidate['added_exact_tool_count'] == len(ACTIONS)
    assert candidate['policy_denial_before_upstream'] and candidate['real_service_mock_http']
    assert candidate['provenance_gate_still_blocks'] and candidate['secret_nonexposure']
    assert receipt['stages']['orpheus']['result_received']
    assert receipt['stages']['docker']['same_container_reused']

    source = Path(__file__).resolve().parents[1]
    expected = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted([*(source / 'hermes_github_app').glob('*.py'), source / '__init__.py', source / 'plugin.yaml'])}
    assert receipt['product_hashes'] == expected
    assert receipt['probe_sha256'] == hashlib.sha256((source / 'tools/gormes_coexistence_probe.py').read_bytes()).hexdigest()

    assert receipt['stages']['directory_entrypoint']
    assert receipt['stages']['hooks_preserved']
    assert candidate['unknown_tool_still_blocked'] and candidate['preserved_old_permissions']
    assert receipt['stages']['docker']['cross_process_reuse_tested'] is False


def test_directory_manifest_matches_action_catalog():
    from ruamel.yaml import YAML
    source = Path(__file__).resolve().parents[1]
    manifest = YAML(typ='safe').load((source / 'plugin.yaml').read_text())
    assert len(manifest['provides_tools']) == len(ACTIONS)
    assert set(manifest['provides_tools']) == {'github_' + action for action in ACTIONS}
