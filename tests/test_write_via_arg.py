"""#113: write-via-arg file writes (sort/sdiff/xxd) blocked in substitution; top-level target-aware."""

from schlock.core.substitution import _WRITE_ARG_COMMANDS, dangerous_write_arg


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
