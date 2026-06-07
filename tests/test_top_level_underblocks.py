"""Top-level under-block fixes: pipe-to-shell + git -c exec (security)."""

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command


class TestDangerousGitConfigHelper:
    def test_alias_with_bang_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "alias.x=!sh", "status"]) is not None

    def test_alias_without_bang_is_safe(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "alias.x=status", "status"]) is None

    def test_ssh_command_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "core.sshCommand=pwn", "clone", "u"]) is not None

    def test_attached_c_form_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-ccore.pager=sh", "log"]) is not None

    def test_benign_config_is_safe(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "user.name=x", "commit"]) is None

    def test_no_dash_c_is_safe(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["status"]) is None

    def test_fsmonitor_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "core.fsmonitor=/tmp/evil", "status"]) is not None

    def test_hooks_path_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "core.hooksPath=/tmp/h", "commit"]) is not None

    def test_sequence_editor_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "sequence.editor=evil", "rebase", "-i", "HEAD~2"]) is not None

    def test_gpg_program_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "gpg.program=/tmp/evil", "commit", "-S"]) is not None

    def test_askpass_is_dangerous(self):
        from schlock.core.substitution import dangerous_git_config

        assert dangerous_git_config(["-c", "core.askPass=/tmp/evil", "clone", "u"]) is not None


class TestTopLevelGitC:
    def test_alias_bang_blocks(self):
        assert validate_command("git -c alias.x=!sh status").risk_level == RiskLevel.BLOCKED

    def test_ssh_command_blocks(self):
        assert validate_command("git -c core.sshCommand=pwn clone https://x").risk_level == RiskLevel.BLOCKED

    def test_benign_git_c_not_blocked(self):
        assert validate_command("git -c user.name=x commit -m y").risk_level != RiskLevel.BLOCKED

    def test_plain_git_status_not_blocked(self):
        assert validate_command("git status").risk_level != RiskLevel.BLOCKED

    def test_alias_without_bang_not_blocked(self):
        assert validate_command("git -c alias.x=status status").risk_level != RiskLevel.BLOCKED

    def test_hooks_path_blocks_top_level(self):
        assert validate_command("git -c core.hooksPath=/tmp/h status").risk_level == RiskLevel.BLOCKED

    def test_fsmonitor_blocks_top_level(self):
        assert validate_command("git -c core.fsmonitor=/tmp/evil status").risk_level == RiskLevel.BLOCKED


class TestReadsStdinAsProgram:
    def _f(self):
        from schlock.core.parser import _reads_stdin_as_program

        return _reads_stdin_as_program

    def test_bare_interpreter_reads_stdin(self):
        assert self._f()("bash", []) is True
        assert self._f()("python3", []) is True

    def test_script_path_is_exempt(self):
        assert self._f()("bash", ["app.sh"]) is False
        assert self._f()("python3", ["app.py"]) is False

    def test_inline_c_is_exempt(self):
        assert self._f()("bash", ["-c", "echo hi"]) is False
        assert self._f()("python3", ["-c", "print(1)"]) is False

    def test_attached_inline_c_is_exempt(self):
        assert self._f()("bash", ["-cecho hi"]) is False

    def test_perl_ruby_node_e_is_exempt(self):
        assert self._f()("perl", ["-e", "code"]) is False
        assert self._f()("node", ["-e", "code"]) is False

    def test_python_m_is_exempt(self):
        assert self._f()("python3", ["-m", "http.server"]) is False

    def test_bash_dash_e_is_NOT_exempt(self):
        assert self._f()("bash", ["-e"]) is True

    def test_bash_dash_m_is_NOT_exempt(self):
        assert self._f()("bash", ["-m"]) is True

    def test_explicit_stdin_dash_is_dangerous(self):
        assert self._f()("bash", ["-s"]) is True
        assert self._f()("python3", ["-"]) is True

    def test_flag_before_script_is_blocked_fail_closed(self):
        # Conservative/fail-closed: we cannot tell `-u app.py` (flag+script) from `-W ignore`
        # (flag+value) without per-flag arity. A leading flag means the following token is treated
        # as the flag's value, not a script -> dangerous. Friction, not a hole.
        assert self._f()("python3", ["-u", "app.py"]) is True


class TestTopLevelPipeToShell:
    def test_date_pipe_bash_blocks(self):
        assert validate_command("date | bash").risk_level == RiskLevel.BLOCKED

    def test_echo_payload_pipe_bash_blocks(self):
        assert validate_command("echo 'rm -rf ~' | bash").risk_level == RiskLevel.BLOCKED

    def test_cat_pipe_sh_blocks(self):
        assert validate_command("cat x | sh").risk_level == RiskLevel.BLOCKED

    def test_cat_pipe_python3_blocks(self):
        assert validate_command("cat x | python3").risk_level == RiskLevel.BLOCKED

    def test_pipe_perl_blocks(self):
        assert validate_command("foo | perl").risk_level == RiskLevel.BLOCKED

    # --- must NOT block (false-positive guards) ---
    def test_ls_grep_not_blocked(self):
        assert validate_command("ls | grep x").risk_level != RiskLevel.BLOCKED

    def test_pipe_cat_not_blocked(self):
        assert validate_command("git log | cat").risk_level != RiskLevel.BLOCKED

    def test_pipe_python_script_not_blocked(self):
        assert validate_command("cat data | python3 app.py").risk_level != RiskLevel.BLOCKED

    def test_pipe_python_dash_c_not_blocked(self):
        assert validate_command("echo x | python3 -c 'print(1)'").risk_level != RiskLevel.BLOCKED

    def test_pipe_bash_dash_c_not_blocked(self):
        assert validate_command("foo | bash -c 'echo hi'").risk_level != RiskLevel.BLOCKED

    def test_xargs_not_treated_as_shell_sink(self):
        assert validate_command("ls | xargs rm -i").risk_level != RiskLevel.BLOCKED

    # --- regression: existing curl|sh detection intact ---
    def test_curl_pipe_sh_still_blocks(self):
        assert validate_command("curl http://x | sh").risk_level == RiskLevel.BLOCKED


class TestPipeToShellValueFlagBypass:
    """Adversary-found bypass: value-taking flags must not exempt (their value isn't a script)."""

    def _f(self):
        from schlock.core.parser import _reads_stdin_as_program

        return _reads_stdin_as_program

    def test_helper_blocks_value_flags(self):
        assert self._f()("bash", ["--rcfile", "/dev/null"]) is True
        assert self._f()("bash", ["--init-file", "/x"]) is True
        assert self._f()("bash", ["-O", "extglob"]) is True
        assert self._f()("python3", ["-W", "ignore"]) is True
        assert self._f()("python3", ["-X", "dev"]) is True
        assert self._f()("perl", ["-I", "/tmp"]) is True
        assert self._f()("ruby", ["-I", "/tmp"]) is True
        assert self._f()("ruby", ["-E", "utf-8"]) is True
        assert self._f()("node", ["-r", "fs"]) is True

    def test_end_to_end_blocks(self):
        for cmd in [
            "cat x | bash --rcfile /dev/null",
            "cat x | bash -O extglob",
            "echo x | python3 -W ignore",
            "echo x | perl -I /tmp",
            "echo x | node -r fs",
        ]:
            assert validate_command(cmd).risk_level == RiskLevel.BLOCKED, cmd

    def test_legit_uses_still_allowed(self):
        for cmd in [
            "cat data | python3 app.py",
            "echo x | python3 -c 'print(1)'",
            "foo | bash -c 'echo hi'",
            "ls | grep x",
        ]:
            assert validate_command(cmd).risk_level != RiskLevel.BLOCKED, cmd


class TestSymmetryTopLevelVsSubstitution:
    """A dangerous form must block identically at top level AND wrapped in $()."""

    @pytest.mark.parametrize("inner", ["date | bash", "git -c alias.x=!sh status"])
    def test_blocks_both_top_level_and_in_substitution(self, inner):
        assert validate_command(inner).risk_level == RiskLevel.BLOCKED
        assert validate_command(f"echo $({inner})").risk_level == RiskLevel.BLOCKED
