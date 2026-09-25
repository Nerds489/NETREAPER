# SPDX-License-Identifier: GPL-3.0-or-later
"""The ffuf and nuclei adapters (#93).

Both were catalogue rows with no adapter and, until #91, no manifest chain to run
them. These tests cover the two things an adapter must get right without a live
tool: the argv it builds and the output it parses. Nothing here spawns a process.
"""
from __future__ import annotations

from netreaper.tools.ffuf import FfufTool
from netreaper.tools.nuclei import NucleiTool

# ── ffuf ──────────────────────────────────────────────────────────────────────


def test_ffuf_appends_a_fuzz_keyword_to_a_bare_url():
    argv = FfufTool().build_command("http://example.com", {})
    i = argv.index("-u")
    assert argv[i + 1] == "http://example.com/FUZZ"
    assert "-w" in argv and "-mc" in argv


def test_ffuf_keeps_an_explicit_fuzz_keyword():
    argv = FfufTool().build_command("http://example.com/FUZZ.php", {})
    assert argv[argv.index("-u") + 1] == "http://example.com/FUZZ.php"


def test_ffuf_emits_machine_readable_output_flags():
    argv = FfufTool().build_command("http://x", {})
    assert "-json" in argv and "-s" in argv


def test_ffuf_parses_a_per_hit_object():
    out = '{"input":{"FUZZ":"admin"},"url":"http://x/admin","status":200,"length":42}'
    parsed = FfufTool().parse_output(out)
    assert parsed["summary"]["total_hits"] == 1
    assert parsed["hits"][0]["input"] == "admin"
    assert parsed["hits"][0]["status"] == 200


def test_ffuf_parses_a_results_array_shape():
    out = '{"results":[{"input":{"FUZZ":"a"},"url":"http://x/a","status":200,"length":1},{"input":{"FUZZ":"b"},"url":"http://x/b","status":301,"length":2}]}'
    parsed = FfufTool().parse_output(out)
    assert parsed["summary"]["total_hits"] == 2


def test_ffuf_ignores_non_json_noise():
    parsed = FfufTool().parse_output("banner line\n\nnot json\n")
    assert parsed["summary"]["total_hits"] == 0


# ── nuclei ────────────────────────────────────────────────────────────────────


def test_nuclei_targets_the_url_and_asks_for_jsonl():
    argv = NucleiTool().build_command("http://example.com", {})
    assert argv[argv.index("-u") + 1] == "http://example.com"
    assert "-jsonl" in argv and "-silent" in argv


def test_nuclei_passes_severity_when_given():
    argv = NucleiTool().build_command("http://x", {"severity": "critical,high"})
    assert argv[argv.index("-severity") + 1] == "critical,high"


def test_nuclei_omits_severity_by_default():
    assert "-severity" not in NucleiTool().build_command("http://x", {})


def test_nuclei_parses_jsonl_findings_and_counts_severity():
    out = (
        '{"template-id":"cve-2023-1","info":{"name":"A","severity":"high"},"matched-at":"http://x/a"}\n'
        '{"template-id":"expo-2","info":{"name":"B","severity":"high"},"matched-at":"http://x/b"}\n'
        '{"template-id":"low-3","info":{"name":"C","severity":"low"},"host":"http://x"}\n'
    )
    parsed = NucleiTool().parse_output(out)
    assert parsed["summary"]["total_findings"] == 3
    assert parsed["summary"]["by_severity"] == {"high": 2, "low": 1}
    assert parsed["findings"][0]["template_id"] == "cve-2023-1"
    assert parsed["findings"][2]["matched_at"] == "http://x"  # falls back to host


def test_nuclei_ignores_non_json_lines():
    parsed = NucleiTool().parse_output("[INF] running\n\ngarbage\n")
    assert parsed["summary"]["total_findings"] == 0


# ── catalogue agreement ───────────────────────────────────────────────────────


def test_adapters_agree_with_the_catalogue():
    from netreaper.detection.tools import ToolRegistry

    for cls, name in ((FfufTool, "ffuf"), (NucleiTool, "nuclei")):
        entry = ToolRegistry.TOOL_DEFINITIONS[name]
        assert entry.name == cls.TOOL_BINARY
        assert entry.requires_root is False
