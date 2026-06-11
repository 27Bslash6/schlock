"""#113: write-via-arg file writes (sort/sdiff/xxd) blocked in substitution; top-level target-aware."""

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

    def test_sort_combined_short_flags_to_sensitive_is_high(self):
        # -ro = -r (reverse) + -o (output); the top-level rule must catch the combined form
        assert validate_command("sort -ro /etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sort_attached_output_to_sensitive_is_high(self):
        assert validate_command("sort -o/etc/cron.d/pwn payload").risk_level == RiskLevel.HIGH

    def test_sort_quoted_sensitive_target_is_high(self):
        assert validate_command('sort -o "/etc/cron.d/pwn" payload').risk_level == RiskLevel.HIGH

    def test_sort_output_to_root_ssh_is_high(self):
        assert validate_command("sort -o /root/.ssh/authorized_keys k").risk_level == RiskLevel.HIGH
