"""#113: write-via-arg file writes (sort/sdiff/xxd) blocked in substitution; top-level target-aware."""

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.substitution import _WRITE_ARG_COMMANDS, dangerous_write_arg
from schlock.core.validator import validate_command


class TestDangerousWriteArgHelper:
    def test_sort_dash_o_space_is_dangerous(self):
        assert dangerous_write_arg("sort", ["sort", "-o", "/etc/cron.d/x", "in"]) is not None

    def test_sort_long_output_equals_is_dangerous(self):
        assert dangerous_write_arg("sort", ["sort", "--output=/etc/cron.d/x"]) is not None

    def test_sort_attached_short_is_dangerous(self):
        assert dangerous_write_arg("sort", ["sort", "-o/etc/cron.d/x"]) is not None

    def test_sort_no_output_is_safe(self):
        assert dangerous_write_arg("sort", ["sort", "in.txt"]) is None

    def test_sdiff_dash_o_is_dangerous(self):
        assert dangerous_write_arg("sdiff", ["sdiff", "-o", "merged", "a", "b"]) is not None

    def test_xxd_reverse_is_dangerous(self):
        assert dangerous_write_arg("xxd", ["xxd", "-r", "-p", "in", "out"]) is not None

    def test_xxd_combined_reverse_is_dangerous(self):
        assert dangerous_write_arg("xxd", ["xxd", "-rp", "in", "out"]) is not None

    def test_xxd_forward_is_safe(self):
        assert dangerous_write_arg("xxd", ["xxd", "-p", "in"]) is None

    def test_unrelated_command_is_safe(self):
        assert dangerous_write_arg("cat", ["cat", "-o", "x"]) is None

    def test_sort_combined_short_flags_with_output_is_dangerous(self):
        # -ro = -r (reverse) + -o (output to file)
        assert dangerous_write_arg("sort", ["sort", "-ro", "/etc/cron.d/x", "in"]) is not None

    def test_xxd_long_reverse_is_dangerous(self):
        assert dangerous_write_arg("xxd", ["xxd", "--reverse", "in", "out"]) is not None

    def test_sdiff_attached_output_is_dangerous(self):
        assert dangerous_write_arg("sdiff", ["sdiff", "-o/etc/cron.d/x", "a", "b"]) is not None

    def test_sdiff_long_output_equals_is_dangerous(self):
        assert dangerous_write_arg("sdiff", ["sdiff", "--output=/etc/cron.d/x", "a", "b"]) is not None

    def test_every_write_arg_command_detected_with_output(self):
        invocations = {
            "sort": ["sort", "-o", "x"],
            "sdiff": ["sdiff", "-o", "x", "a", "b"],
            "xxd": ["xxd", "-r", "in", "out"],
        }
        for cmd in _WRITE_ARG_COMMANDS:
            assert dangerous_write_arg(cmd, invocations[cmd]) is not None, cmd

    def test_double_dash_ends_options_sort(self):
        # After `--`, `-o` is a positional filename (input), not the output flag.
        assert dangerous_write_arg("sort", ["sort", "--", "-o"]) is None

    def test_double_dash_ends_options_xxd(self):
        assert dangerous_write_arg("xxd", ["xxd", "--", "-r"]) is None

    def test_output_before_double_dash_still_detected(self):
        assert dangerous_write_arg("sort", ["sort", "-o", "/etc/cron.d/x", "--", "foo"]) is not None


class TestWriteViaArgSubstitution:
    """Blunt: any write-via-arg target inside a substitution is BLOCKED (#113)."""

    def test_sort_output_in_command_substitution_blocked(self):
        assert validate_command('echo "$(sort -o /etc/cron.d/pwn /tmp/payload)"').risk_level == RiskLevel.BLOCKED

    def test_sdiff_output_in_substitution_blocked(self):
        assert validate_command('echo "$(sdiff -o /etc/cron.d/pwn a b)"').risk_level == RiskLevel.BLOCKED

    def test_xxd_reverse_in_substitution_blocked(self):
        assert validate_command('echo "$(xxd -r -p payload /etc/cron.d/pwn)"').risk_level == RiskLevel.BLOCKED

    def test_sort_output_to_nonsensitive_in_substitution_blocked(self):
        # Accepted false-positive cost: writing ANY file inside $() is blunt-blocked.
        assert validate_command('X="$(sort -o tmpfile in.txt)"').risk_level == RiskLevel.BLOCKED

    def test_sort_read_only_in_substitution_still_safe(self):
        assert validate_command('X="$(sort in.txt)"').allowed is True

    def test_xxd_forward_in_substitution_still_safe(self):
        assert validate_command('X="$(xxd -p in.txt)"').allowed is True

    def test_tee_in_substitution_still_blocked_regression(self):
        # tee is covered by the existing truncation YAML rule, not the helper.
        assert validate_command('echo "$(tee /etc/cron.d/pwn)"').risk_level == RiskLevel.BLOCKED


class TestWriteViaArgTopLevel:
    """Target-aware: sort/sdiff -o to a SENSITIVE path -> HIGH; benign target stays SAFE (#113)."""

    def test_sort_output_to_cron_is_high(self):
        assert validate_command("sort -o /etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sort_output_equals_cron_is_high(self):
        assert validate_command("sort --output=/etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sdiff_output_to_authorized_keys_is_high(self):
        assert validate_command("sdiff -o ~/.ssh/authorized_keys a b").risk_level == RiskLevel.HIGH

    def test_sort_output_to_benign_file_stays_safe(self):
        # FP guard — must NOT be flagged.
        assert validate_command("sort -o out.txt in.txt").risk_level == RiskLevel.SAFE

    def test_sort_read_only_stays_safe(self):
        assert validate_command("sort in.txt").risk_level == RiskLevel.SAFE

    def test_sdiff_output_to_benign_file_stays_safe(self):
        # FP guard — sdiff parity with the sort benign-target guard.
        assert validate_command("sdiff -o out.txt a b").risk_level == RiskLevel.SAFE

    def test_sort_combined_short_flags_to_sensitive_is_high(self):
        # -ro = -r (reverse) + -o (output); the top-level rule must catch the combined form
        assert validate_command("sort -ro /etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sort_attached_output_to_sensitive_is_high(self):
        assert validate_command("sort -o/etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sort_quoted_sensitive_target_is_high(self):
        assert validate_command('sort -o "/etc/cron.d/pwn" payload').risk_level == RiskLevel.HIGH

    def test_sort_output_to_root_ssh_is_high(self):
        assert validate_command("sort -o /root/.ssh/authorized_keys k").risk_level == RiskLevel.HIGH

    def test_sort_output_to_braced_home_is_high(self):
        assert validate_command('sort -o "${HOME}/.bashrc" in').risk_level == RiskLevel.HIGH

    def test_sort_output_to_braced_home_ssh_is_high(self):
        assert validate_command('sort -o "${HOME}/.ssh/authorized_keys" k').risk_level == RiskLevel.HIGH


@pytest.mark.usefixtures("no_shellcheck")
class TestFindWriteFlagsTopLevel:
    """find -fprint/-fprint0/-fprintf/-fls share write_via_arg_persistence's sensitive-target set."""

    @pytest.mark.parametrize(
        "command",
        [
            "find . -fprintf /etc/cron.d/x 'rm -rf /'",
            "find . -fprint /etc/cron.d/x",
            "find . -fprint '/etc/cron.d/x'",
            "find . -fprint0 /root/.ssh/authorized_keys",
            "find . -fprint0 ~/.ssh/authorized_keys",
            "find . -fls /var/spool/cron/crontabs/root",
            "find . -name x -fprintf /etc/sudoers.d/x 'ALL ALL=(ALL) NOPASSWD: ALL'",
            'find . -fprintf "$HOME/.bashrc" %p',
            "timeout 5 find . -fprintf /etc/cron.d/x 'rm -rf /'",
        ],
    )
    def test_write_flag_to_sensitive_path_is_high(self, command):
        result = validate_command(command)
        assert result.risk_level >= RiskLevel.HIGH
        assert "write_via_arg_persistence" in result.matched_rules

    @pytest.mark.parametrize(
        "command",
        [
            "find . -name '*.py' -fprint files.txt",
            "find . -type f -fprintf report.txt '%p %s\\n'",
            # A sensitive START path is not a write target.
            "find /etc/cron.d -name x -fprint list.txt",
            "find . -printf '%p\\n'",
            "find . -print0",
            "find . -ls",
            "find . -exec grep -l TODO {} +",
            "grep -rn 'rm -rf' src/",
            "git log --grep 'git push --force'",
        ],
    )
    def test_benign_find_stays_safe(self, command):
        assert validate_command(command).risk_level == RiskLevel.SAFE
