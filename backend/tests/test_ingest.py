"""Parser tests. Fixture text is neutral placeholder content — the parsers only read result structure."""
import json

import pytest

from agentshield.ingest import garak, pyrit, traps
from agentshield.ingest.common import IngestError, categorize, load_category_map
from agentshield.config import get_settings


def garak_line(uuid, probe, scores, status=2, content_as_str=False):
    turn_content = "placeholder input" if content_as_str else {"text": "placeholder input", "lang": "en"}
    return json.dumps({
        "entry_type": "attempt", "uuid": uuid, "seq": 0, "status": status, "probe_classname": probe,
        "prompt": {"turns": [{"role": "user", "content": turn_content}], "notes": {}},
        "outputs": [{"text": "placeholder reply", "lang": "en"}],
        "detector_results": {"det.Example": scores}, "notes": {}, "goal": "placeholder goal"})


def test_garak_verdicts_from_detector_scores():
    lines = [json.dumps({"entry_type": "start_run setup", "garak_version": "0.13.0"}),
             garak_line("a1", "probes.promptinject.X", [0.9]),
             garak_line("a2", "probes.promptinject.X", [0.1]),
             garak_line("a3", "probes.dan.Y", [], ),
             garak_line("a4", "probes.dan.Y", [0.9], status=1),  # not evaluated -> skipped
             garak_line("a5", "probes.latentinjection.Z", [0.7], content_as_str=True)]
    res = garak.parse(lines, fail_threshold=0.5)
    by = {a.external_id: a for a in res.attempts}
    assert res.tool_version == "0.13.0"
    assert set(by) == {"a1", "a2", "a3", "a5"}
    assert by["a1"].verdict == "fail" and by["a1"].score == 0.9 and by["a1"].detector == "det.Example"
    assert by["a2"].verdict == "pass"
    assert by["a3"].verdict == "inconclusive"
    assert by["a5"].turns[0]["text"] == "placeholder input"  # legacy string content handled
    assert by["a5"].turns[-1] == {"role": "assistant", "text": "placeholder reply", "generation": 0}


def test_garak_rejects_non_report():
    with pytest.raises(IngestError):
        garak.parse(['{"foo": 1}'], fail_threshold=0.5)


def pyrit_doc():
    return {
        "pyrit_version": "1.1.0",
        "message_pieces": [
            {"id": "p1", "conversation_id": "c1", "sequence": 0, "role": "user", "original_value": "o", "converted_value": "placeholder input",
             "labels": {"agentshield_category": "T-02", "test_id": "fixture.action"}, "timestamp": "2026-10-29T10:00:00Z"},
            {"id": "p2", "conversation_id": "c1", "sequence": 1, "role": "assistant", "original_value": "placeholder reply"},
            {"id": "p3", "conversation_id": "c2", "sequence": 0, "role": "user", "converted_value": "placeholder input"},
            {"id": "p4", "conversation_id": "c2", "sequence": 1, "role": "assistant", "original_value": "placeholder reply"},
            {"id": "p5", "conversation_id": "c3", "sequence": 0, "role": "user", "converted_value": "placeholder input",
             "labels": {"test_id": "fixture.float"}},
            {"id": "p6", "conversation_id": "c3", "sequence": 1, "role": "assistant", "original_value": "placeholder reply"},
        ],
        "scores": [
            {"message_piece_id": "p4", "score_type": "true_false", "score_value": "False", "scorer_class_identifier": {"__type__": "SomeScorer"}},
            {"message_piece_id": "p6", "score_type": "float_scale", "score_value": "0.8", "score_rationale": "placeholder rationale",
             "scorer_class_identifier": "ScaleScorer"},
        ],
        "attack_results": [{"conversation_id": "c1", "outcome": "SUCCESS", "outcome_reason": "objective achieved"}],
    }


def test_pyrit_verdict_rules():
    res = pyrit.parse(json.dumps(pyrit_doc()).encode(), fail_threshold=0.5)
    by = {a.external_id: a for a in res.attempts}
    assert by["c1"].verdict == "fail" and by["c1"].category_hint == "T-02" and by["c1"].test_id == "fixture.action"
    assert by["c1"].turns[0]["text"] == "placeholder input"  # converted_value preferred
    assert by["c2"].verdict == "pass"
    assert by["c3"].verdict == "fail" and by["c3"].score == 0.8 and "ScaleScorer" in by["c3"].rationale


def test_pyrit_requires_message_pieces():
    with pytest.raises(IngestError):
        pyrit.parse(b'{"scores": []}', fail_threshold=0.5)


def test_traps_parse_and_skip_incomplete():
    res = traps.parse(['{"token_id":"tok-1","external_id":"a1","received_at":"2026-10-29T10:00:00Z"}', '{"token_id":"x"}'])
    assert len(res.trap_hits) == 1 and res.trap_hits[0].received_at.year == 2026
    assert res.warnings


def test_categorize_prefers_explicit_label_then_prefix():
    cmap = load_category_map(str(get_settings().category_map_file))
    assert categorize("anything", "T-04", cmap) == "T-04"
    assert categorize("probes.latentinjection.Foo", "", cmap) == "T-01"
    assert categorize("probes.unknown.Foo", "", cmap) == "unmapped"
