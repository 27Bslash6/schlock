"""Tests for the spec §6 tier state machine and the `SCHLOCK_PARSER` switch (LAB-409 T5).

Tier order is fixed: native → in-process bashlex → deny. Every failure row of
the §6 table is driven through a REAL `NativeBridge` against a scripted
stand-in binary, so the routing is exercised end to end rather than mocked at
the exception. The one row that must NOT rescue — bashlex also raising — ends
in `ParseError`, which `validator.py` turns into BLOCKED.
"""

import json
import logging
import subprocess
import time

import bashlex.ast
import pytest

from schlock.core import native_bridge
from schlock.core import parser as parser_mod
from schlock.core.ast_view import AstView
from schlock.core.native_bridge import MAX_COMMAND_SIZE, NativeBridge, NativeBridgeError, resolve_binary
from schlock.core.parser import PARSER_TIERS, TieredParser, resolve_parser_tier
from schlock.exceptions import ParseError

LOGGER = "schlock.core.parser"


def _is_bashlex(nodes) -> bool:
    return bool(nodes) and all(isinstance(n, bashlex.ast.node) for n in nodes)


def _is_native(nodes) -> bool:
    return bool(nodes) and all(isinstance(n, AstView) for n in nodes)


def _call_expr_file(command: str, end: "int | None" = None) -> dict:
    """Minimal typed-JSON `File` for a single `CallExpr` of whitespace-separated literals."""
    args, offset = [], 0
    for token in command.split(" "):
        span = {"Pos": {"Offset": offset}, "End": {"Offset": offset + len(token)}}
        args.append({**span, "Parts": [{"Type": "Lit", **span, "Value": token}]})
        offset += len(token) + 1
    stmt_span = {"Pos": {"Offset": 0}, "End": {"Offset": len(command)}}
    return {
        "Type": "File",
        "Pos": {"Offset": 0},
        "End": {"Offset": len(command) if end is None else end},
        "Stmts": [{**stmt_span, "Cmd": {"Type": "CallExpr", **stmt_span, "Args": args}}],
    }


def _emit(payload) -> str:
    return f"sys.stdout.write({json.dumps(payload)!r})\n"


def _recording_popen(monkeypatch) -> list:
    spawned = []
    real_popen = subprocess.Popen

    def recording(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", recording)
    return spawned


def _auto(binary, **bridge_kwargs) -> TieredParser:
    return TieredParser(tier="auto", bridge=NativeBridge(binary_path=binary, **bridge_kwargs))


class TestFailureTableLandsOnBashlex:
    """One test per spec §6 row: each native failure yields the bashlex tier's AST."""

    @pytest.mark.parametrize("via", ["path-probe", "spawn-error"])
    def test_missing_binary_falls_back_and_warns_once(self, tmp_path, monkeypatch, caplog, via):
        if via == "path-probe":
            monkeypatch.setattr(native_bridge, "DEFAULT_BIN_ROOT", tmp_path)  # nothing vendored here
            bridge = NativeBridge()
        else:
            bridge = NativeBridge(binary_path=tmp_path / "absent")
        tiers = TieredParser(tier="auto", bridge=bridge)

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert _is_bashlex(tiers.parse("echo one"))
            assert _is_bashlex(tiers.parse("echo two"))

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1, [r.getMessage() for r in warnings]
        assert "native parser" in warnings[0].getMessage()

    @pytest.mark.parametrize(
        "body",
        ["sys.exit(9)\n", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n"],
        ids=["exit-gt-3", "signal"],
    )
    def test_exec_crash_falls_back(self, fake_binary, body):
        assert _is_bashlex(_auto(fake_binary(body)).parse("echo hi"))

    def test_native_parse_error_exit_2_falls_back(self, fake_binary):
        binary = fake_binary('sys.stderr.write("1:1: bad syntax")\nsys.exit(2)\n')
        assert _is_bashlex(_auto(binary).parse("echo hi"))

    def test_stdin_read_error_exit_3_falls_back(self, fake_binary):
        assert _is_bashlex(_auto(fake_binary("sys.exit(3)\n")).parse("echo hi"))

    def test_short_span_falls_back(self, fake_binary):
        # The binary "parsed" only `echo hi`; the trailing `; rm x` would otherwise vanish.
        binary = fake_binary(_emit(_call_expr_file("echo hi", end=7)))
        assert _is_bashlex(_auto(binary).parse("echo hi; rm x"))

    def test_timeout_kills_reaps_and_falls_back(self, fake_binary, monkeypatch):
        binary = fake_binary("import time\nsys.stdin.read()\ntime.sleep(30)\n")
        spawned = _recording_popen(monkeypatch)

        started = time.perf_counter()
        assert _is_bashlex(_auto(binary, timeout=0.1).parse("echo hi"))

        assert time.perf_counter() - started < 5
        assert len(spawned) == 1
        assert spawned[0].returncode is not None  # kill+wait: no zombie

    def test_input_guard_trip_falls_back_without_spawning(self, monkeypatch):
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        assert _is_bashlex(TieredParser(tier="auto").parse("echo " + "a" * MAX_COMMAND_SIZE))

    def test_output_guard_trip_falls_back(self, fake_binary):
        binary = fake_binary("sys.stdout.write('x' * 100000)\n")
        assert _is_bashlex(_auto(binary, max_ast_json_size=1024).parse("echo hi"))

    def test_malformed_json_falls_back(self, fake_binary):
        assert _is_bashlex(_auto(fake_binary("sys.stdout.write('not json')\n")).parse("echo hi"))

    def test_unmapped_node_falls_back(self, fake_binary):
        payload = _call_expr_file("echo hi")
        payload["Stmts"][0]["Cmd"]["Type"] = "FrobExpr"
        assert _is_bashlex(_auto(fake_binary(_emit(payload))).parse("echo hi"))

    def test_bashlex_also_failing_raises_parse_error(self, fake_binary):
        # Terminal row: no tier left, so ParseError → validator.py → BLOCKED. The message is
        # bashlex's own — validator's heredoc special-case matches on that text.
        binary = fake_binary("sys.exit(2)\n")
        with pytest.raises(ParseError, match="Failed to parse bash command"):
            _auto(binary).parse("echo $(a &&)")


class TestNativeSuccess:
    def test_native_ast_is_returned_and_bashlex_is_not_consulted(self, fake_binary, monkeypatch):
        monkeypatch.setattr(parser_mod, "parse_bashlex", lambda *a, **k: pytest.fail("bashlex consulted"))
        nodes = _auto(fake_binary(_emit(_call_expr_file("echo hi")))).parse("echo hi")
        assert _is_native(nodes)
        assert nodes[0].kind == "command"

    def test_vendored_binary_serves_the_native_tier(self):
        try:
            resolve_binary()
        except NativeBridgeError as exc:
            pytest.skip(str(exc))
        assert _is_native(TieredParser(tier="auto").parse("echo hello"))


class TestForcedTiers:
    """`native` isolates the native path (parse-error → deny, no rescue); `bashlex` never spawns."""

    def test_native_mode_parse_error_denies_without_bashlex_rescue(self, fake_binary, monkeypatch):
        monkeypatch.setattr(parser_mod, "parse_bashlex", lambda *a, **k: pytest.fail("bashlex rescued"))
        binary = fake_binary("sys.exit(2)\n")
        with pytest.raises(ParseError):
            TieredParser(tier="native", bridge=NativeBridge(binary_path=binary)).parse("echo hi")

    def test_native_mode_bridge_failure_denies(self, tmp_path, monkeypatch):
        monkeypatch.setattr(parser_mod, "parse_bashlex", lambda *a, **k: pytest.fail("bashlex rescued"))
        tiers = TieredParser(tier="native", bridge=NativeBridge(binary_path=tmp_path / "absent"))
        with pytest.raises(ParseError) as info:
            tiers.parse("echo hi")
        assert isinstance(info.value.original_error, NativeBridgeError)

    def test_bashlex_mode_never_spawns(self, monkeypatch):
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        assert _is_bashlex(TieredParser(tier="bashlex").parse("echo hi"))

    def test_unknown_tier_is_rejected_at_construction(self):
        with pytest.raises(ValueError):
            TieredParser(tier="regex")


def _pin(root, filename, value="bashlex"):
    settings = root / ".claude" / filename
    settings.parent.mkdir(exist_ok=True)
    settings.write_text(json.dumps({"env": {"SCHLOCK_PARSER": value}}), encoding="utf-8")
    return settings


class TestSchlockParserSwitch:
    """Spec §6: allowlisted, `auto` default, honored from user/global scope only."""

    def test_allowlist_is_the_spec_set(self):
        assert frozenset({"auto", "native", "bashlex"}) == PARSER_TIERS

    def test_unset_is_auto(self, tmp_path):
        assert resolve_parser_tier(environ={}, project_dirs=[tmp_path]) == "auto"

    @pytest.mark.parametrize(
        "raw, tier", [("native", "native"), ("bashlex", "bashlex"), ("auto", "auto"), (" Native ", "native")]
    )
    def test_user_scope_value_is_honored(self, tmp_path, raw, tier):
        assert resolve_parser_tier(environ={"SCHLOCK_PARSER": raw}, project_dirs=[tmp_path]) == tier

    def test_junk_value_is_auto_with_warning(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "regex"}, project_dirs=[tmp_path]) == "auto"
        assert any("regex" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("filename", ["settings.json", "settings.local.json"])
    def test_project_scope_pin_is_ignored_with_warning(self, tmp_path, caplog, filename):
        settings = _pin(tmp_path, filename)
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "bashlex"}, project_dirs=[tmp_path]) == "auto"
        assert any(str(settings) in r.getMessage() for r in caplog.records)

    def test_project_settings_without_the_key_do_not_taint(self, tmp_path):
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps({"env": {"OTHER": "1"}, "permissions": {}}), encoding="utf-8")
        assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "native"}, project_dirs=[tmp_path]) == "native"

    def test_unreadable_project_settings_fail_toward_auto(self, tmp_path, caplog):
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text("{not json", encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "native"}, project_dirs=[tmp_path]) == "auto"
        assert any(str(settings) in r.getMessage() for r in caplog.records)

    def test_default_project_dirs_cover_claude_project_dir_and_cwd(self, tmp_path, monkeypatch):
        project, elsewhere = tmp_path / "project", tmp_path / "elsewhere"
        project.mkdir()
        elsewhere.mkdir()
        _pin(project, "settings.json")

        monkeypatch.chdir(elsewhere)
        env = {"SCHLOCK_PARSER": "bashlex", "CLAUDE_PROJECT_DIR": str(project)}
        assert resolve_parser_tier(environ=env) == "auto"

        monkeypatch.chdir(project)
        assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "bashlex"}) == "auto"

        monkeypatch.chdir(elsewhere)
        assert resolve_parser_tier(environ={"SCHLOCK_PARSER": "bashlex"}) == "bashlex"

    def test_tiered_parser_reads_the_switch_by_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
        monkeypatch.setenv("SCHLOCK_PARSER", "bashlex")
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
        tiers = TieredParser()
        assert tiers.tier == "bashlex"
        assert _is_bashlex(tiers.parse("echo hi"))
