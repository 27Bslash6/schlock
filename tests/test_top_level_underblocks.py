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
