"""Technique catalog: every executable technique maps to a documented framework strategy that exists in the
installed version; nothing maps to AgentShield-authored content. Offline."""

import pytest

from agentshield.catalog import catalog, execution_key, inventory, taxonomy

ENGINES_UP = {"pyrit": {"available": True, "version": "1.1.0"}, "garak": {"available": True, "version": "0.17.1"},
              "deepagents": {"available": True, "version": "0.7.32"}}


def test_every_technique_has_kind_and_only_framework_executions():
    cat = catalog()
    assert cat["version"] == "2026.10.2"
    for tid, t in cat["techniques"].items():
        assert t["kind"] in ("plumbing", "security"), tid
        assert "engines" not in t and "scoring" not in t, f"{tid} still references removed native engines/scorers"
        for e in t["executions"]:
            assert e["engine"] in ("garak", "pyrit"), tid
            if e["engine"] == "garak":
                assert e["probe"] and e["detector"], tid
            else:
                assert e["strategy"] in ("PromptSendingAttack", "MultiPromptSendingAttack"), tid
                assert e.get("dataset") or e.get("input") in ("operator_benign_prompt", "operator_benign_turns"), tid
        if not t["executions"]:
            assert t["not_executable_reason"], tid
        if t["kind"] == "plumbing":
            assert t["risks"] == [] and t["severity"] == "Info"
    assert {"PLUMB-PYRIT", "PLUMB-PYRIT-MT", "PLUMB-GARAK"} <= set(cat["techniques"])
    garak_test = cat["techniques"]["PLUMB-GARAK"]["executions"][0]
    assert garak_test["probe"] == "test.Test" and garak_test["honours_prompt_cap"] is False


def test_inventory_reflects_engine_availability():
    inv = inventory(ENGINES_UP)
    rows = {r["id"]: r for r in inv["techniques"]}
    assert rows["AS-SPL-01"]["executable"] and len(rows["AS-SPL-01"]["executions"]) == 2
    assert not rows["AS-JB-01"]["executable"] and rows["AS-JB-01"]["not_executable_reason"]
    assert inv["executable_security_techniques"] == 5 and inv["security_techniques"] == 14
    down = inventory(ENGINES_UP | {"garak": {"available": False, "version": ""}})
    rows = {r["id"]: r for r in down["techniques"]}
    assert not rows["AS-PI-01"]["executable"] and "not installed" in rows["AS-PI-01"]["not_executable_reason"]
    assert rows["AS-SPL-01"]["executable"]  # PyRIT execution still available
    tested = {r["id"]: r["tested_by"] for r in down["risk_categories"]}
    assert "AS-PI-01" not in tested["LLM01"]


def test_execution_keys_are_unique_within_technique():
    for tid, t in catalog()["techniques"].items():
        keys = [execution_key(e) for e in t["executions"]]
        assert len(keys) == len(set(keys)), tid
    assert execution_key({"engine": "garak", "probe": "test.Test"}) == "garak:test.Test"
    assert execution_key({"engine": "pyrit", "strategy": "PromptSendingAttack", "dataset": "d"}) == "pyrit:PromptSendingAttack:d"


def test_taxonomy_merges_import_categories_and_techniques():
    tx = taxonomy()
    assert {"T-01", "T-05", "AS-SPL-01", "PLUMB-GARAK"} <= set(tx["categories"])
    assert tx["categories"]["PLUMB-GARAK"]["kind"] == "plumbing"
    assert tx["categories"]["AS-SPL-01"]["remediation_key"] in tx["remediations"]


def test_pyrit_datasets_load_from_installed_pyrit():
    pytest.importorskip("pyrit")
    from agentshield.assessment.plans import pyrit_dataset

    for t in catalog()["techniques"].values():
        for e in t["executions"]:
            if e.get("dataset"):
                seeds, meta = pyrit_dataset(e["dataset"])
                assert seeds and meta["seed_count"] == len(seeds) and len(meta["sha256"]) == 64


def test_garak_probes_exist_in_installed_garak():
    """Asks the installed garak's own plugin registry (some probe classes are generated at import time), and checks
    each catalog detector is that probe's primary detector."""
    import json
    import subprocess

    from agentshield.config import get_settings

    exe = get_settings().garak_python_path
    if not exe.exists():
        pytest.skip("garak venv not installed")
    pairs = [(e["probe"], e["detector"]) for t in catalog()["techniques"].values() for e in t["executions"]
             if e["engine"] == "garak"]
    script = ("import json,sys\nfrom garak import _plugins\nout={}\n"
              "for p,d in json.loads(sys.argv[1]):\n"
              "    out[p]=[_plugins.plugin_info('probes.'+p).get('primary_detector'), bool(_plugins.plugin_info('detectors.'+d))]\n"
              "print(json.dumps(out))")
    res = subprocess.run([str(exe), "-c", script, json.dumps(pairs)], capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr[-2000:]
    found = json.loads(res.stdout.strip().splitlines()[-1])
    for probe, det in pairs:
        assert found[probe] == [det, True], (probe, found[probe])
