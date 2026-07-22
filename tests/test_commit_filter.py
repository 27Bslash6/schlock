"""Tests for commit message filtering.

Includes FIX 6: Multiple -m flags bypass test.
"""

import time
from unittest.mock import patch

import pytest
import yaml

from schlock.integrations.commit_filter import CommitMessageFilter, load_filter_config


class TestGitCommandDetection:
    """Test git commit command detection."""

    def test_detects_git_commit(self):
        """Detects basic git commit command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("git commit -m 'test'")

    def test_detects_git_commit_with_flags(self):
        """Detects git commit with various flags."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("git commit --no-verify -m 'test'")
        assert filter_instance.is_git_commit_command("git commit --amend -m 'test'")

    def test_rejects_non_git_commands(self):
        """Rejects non-git commands."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert not filter_instance.is_git_commit_command("ls -la")
        assert not filter_instance.is_git_commit_command("git status")
        assert not filter_instance.is_git_commit_command("git push")

    def test_detects_compound_command_with_git_add(self):
        """Detects git commit in compound command: git add && git commit."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("git add . && git commit -m 'test'")

    def test_detects_compound_command_with_cd(self):
        """Detects git commit in compound command: cd && git commit."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("cd project && git commit -m 'test'")

    def test_detects_compound_command_with_semicolon(self):
        """Detects git commit in compound command: git add; git commit."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("git add .; git commit -m 'test'")

    def test_detects_compound_command_triple_chain(self):
        """Detects git commit in triple-chained command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        assert filter_instance.is_git_commit_command("cd project && git add -A && git commit -m 'test'")


class TestMessageExtraction:
    """Test commit message extraction from commands."""

    def test_extracts_double_quoted_message(self):
        """Extracts message from double-quoted format."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message('git commit -m "test message"')
        assert msg == "test message"

    def test_extracts_single_quoted_message(self):
        """Extracts message from single-quoted format."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message("git commit -m 'test message'")
        assert msg == "test message"

    def test_extracts_message_with_literal_newlines(self):
        """Extracts message with literal \\n converted to actual newlines."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message('git commit -m "Line 1\\nLine 2"')
        assert msg == "Line 1\nLine 2"

    def test_returns_none_for_no_message(self):
        """Returns None when no -m flag present."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message("git commit --amend")
        assert msg is None

    def test_extracts_multiple_m_flags(self):
        """FIX 6: Extracts ALL -m messages and combines them."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = 'git commit -m "First paragraph" -m "Second paragraph"'
        msg = filter_instance.extract_commit_message(cmd)
        assert msg == "First paragraph\n\nSecond paragraph"

    def test_multiple_m_flags_with_advertising(self):
        """FIX 6: Multiple -m flags with advertising in second message."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = 'git commit -m "Clean feature" -m "Generated with Claude Code"'
        msg = filter_instance.extract_commit_message(cmd)
        # Should extract both and combine with double newline
        assert "Clean feature" in msg
        assert "Generated with Claude Code" in msg
        assert "\n\n" in msg

    def test_three_m_flags_combined(self):
        """FIX 6: Three -m flags should all be extracted."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = 'git commit -m "Title" -m "Body paragraph 1" -m "Body paragraph 2"'
        msg = filter_instance.extract_commit_message(cmd)
        assert msg == "Title\n\nBody paragraph 1\n\nBody paragraph 2"

    def test_extracts_message_from_compound_command(self):
        """Extracts message from compound command: git add && git commit."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message('git add . && git commit -m "test message"')
        assert msg == "test message"

    def test_extracts_message_from_triple_chain(self):
        """Extracts message from triple-chained command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        msg = filter_instance.extract_commit_message('cd project && git add -A && git commit -m "feature: add thing"')
        assert msg == "feature: add thing"

    def test_extracts_heredoc_message_content(self):
        """Extracts actual message content from heredoc format, not the $(cat...) wrapper."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        heredoc_cmd = '''git commit -m "$(cat <<'EOF'
Multi-line
message
EOF
)"'''
        msg = filter_instance.extract_commit_message(heredoc_cmd)
        # Should extract the message content, not the $(cat...) wrapper
        assert msg == "Multi-line\nmessage"
        assert "$(cat" not in msg

    def test_heredoc_with_advertising_filtered(self):
        """Heredoc format with advertising should be detected and filtered."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [
                        {"pattern": "Generated with Claude Code", "description": "Claude ad", "replacement": ""},
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)
        heredoc_cmd = '''git commit -m "$(cat <<'EOF'
Add feature

Generated with Claude Code
EOF
)"'''
        result = filter_instance.filter_commit_message(heredoc_cmd)
        assert result.was_modified
        assert "Generated with Claude Code" not in result.cleaned_message


class TestBashlexEdgeCases:
    """Test bashlex-specific edge cases and parsing robustness."""

    def test_nested_escaped_quotes(self):
        """Handles messages with escaped quotes inside."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = r'git commit -m "Message with \"escaped\" quotes"'
        msg = filter_instance.extract_commit_message(cmd)
        assert msg is not None
        assert "escaped" in msg

    def test_message_with_backslash(self):
        """Handles messages with backslashes."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = r'git commit -m "Path: C:\\Users\\test"'
        msg = filter_instance.extract_commit_message(cmd)
        assert msg is not None

    def test_bashlex_parse_failure_fails_open(self):
        """Malformed bash that bashlex can't parse returns original command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        # Unclosed quote - should fail-open
        cmd = 'git commit -m "unclosed'
        result = filter_instance.filter_commit_message(cmd)
        # Should not crash, should fail-open
        assert result.cleaned_command == cmd  # Original returned

    def test_empty_message(self):
        """Handles empty message gracefully."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        cmd = 'git commit -m ""'
        msg = filter_instance.extract_commit_message(cmd)
        # Empty string is valid extraction (not None)
        assert msg == ""

    def test_size_limit_prevents_dos(self):
        """Commands exceeding size limit are handled gracefully."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        # 100KB message (exceeds 64KB limit)
        huge_msg = "A" * (100 * 1024)
        cmd = f'git commit -m "{huge_msg}"'
        result = filter_instance.filter_commit_message(cmd)
        # Should fail-open without hanging
        assert result.cleaned_command == cmd  # Original returned


class TestMessageCleaning:
    """Test pattern-based message cleaning."""

    def test_removes_advertising_pattern(self):
        """Removes 'Generated with Claude Code' pattern."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [
                        {
                            "pattern": "Generated with Claude Code",
                            "description": "Claude advertising",
                            "replacement": "",
                        }
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        message = "Add feature\n\nGenerated with Claude Code"
        cleaned, patterns, categories = filter_instance.clean_message(message)

        assert "Generated with Claude Code" not in cleaned
        assert cleaned == "Add feature"
        assert len(patterns) == 1
        assert "advertising" in categories

    def test_removes_multiple_patterns(self):
        """Removes multiple advertising patterns from one message."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [
                        {"pattern": "Generated with Claude Code", "description": "", "replacement": ""},
                        {"pattern": "Co-Authored-By: Claude", "description": "", "replacement": ""},
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        message = "Add feature\n\nGenerated with Claude Code\nCo-Authored-By: Claude"
        cleaned, patterns, categories = filter_instance.clean_message(message)

        assert "Generated with Claude Code" not in cleaned
        assert "Co-Authored-By: Claude" not in cleaned
        assert len(patterns) == 2

    def test_preserves_message_without_patterns(self):
        """Preserves clean message without matching patterns."""
        config = {"enabled": True, "rules": {}}
        filter_instance = CommitMessageFilter(config)

        message = "Clean commit message"
        cleaned, patterns, categories = filter_instance.clean_message(message)

        assert cleaned == "Clean commit message"
        assert len(patterns) == 0
        assert len(categories) == 0

    def test_trims_excessive_whitespace(self):
        """Trims excessive whitespace (3+ newlines → 2)."""
        config = {"enabled": True, "rules": {}}
        filter_instance = CommitMessageFilter(config)

        message = "Message\n\n\n\n\nToo many newlines"
        cleaned, _, _ = filter_instance.clean_message(message)

        assert cleaned == "Message\n\nToo many newlines"


class TestCommandReconstruction:
    """Test git command reconstruction with cleaned message."""

    def test_reconstructs_with_escaped_format(self):
        """Reconstructs command with properly escaped message."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git commit -m "test"'
        cleaned_msg = "cleaned message"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "git commit -m" in reconstructed
        assert "cleaned message" in reconstructed

    def test_preserves_git_flags(self):
        """Preserves git flags in reconstructed command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git commit --no-verify -m "test"'
        cleaned_msg = "cleaned"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "git commit --no-verify -m" in reconstructed

    def test_escapes_quotes_in_message(self):
        """Escapes double quotes in message."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git commit -m "test"'
        cleaned_msg = 'Message with "quotes"'

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert '\\"' in reconstructed  # Quotes should be escaped

    def test_converts_newlines_to_literal(self):
        """Converts actual newlines to literal \\n."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git commit -m "test"'
        cleaned_msg = "Line 1\nLine 2"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "\\n" in reconstructed  # Newline should be literal \n

    def test_preserves_compound_command_prefix(self):
        """Preserves git add prefix in compound command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git add . && git commit -m "test"'
        cleaned_msg = "cleaned message"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "git add ." in reconstructed
        assert "&&" in reconstructed
        assert "git commit" in reconstructed
        assert "cleaned message" in reconstructed

    def test_preserves_triple_chain_command(self):
        """Preserves cd && git add prefix in triple-chained command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'cd project && git add -A && git commit -m "test"'
        cleaned_msg = "cleaned"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "cd project" in reconstructed
        assert "git add -A" in reconstructed
        assert "git commit" in reconstructed
        assert "cleaned" in reconstructed

    def test_preserves_semicolon_compound_command(self):
        """Preserves semicolon-separated compound command."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})
        original = 'git add .; git commit -m "test"'
        cleaned_msg = "cleaned"

        reconstructed = filter_instance.reconstruct_command(original, cleaned_msg)

        assert "git add ." in reconstructed
        assert ";" in reconstructed
        assert "git commit" in reconstructed
        assert "cleaned" in reconstructed


class TestFilterOrchestration:
    """Test complete filter_commit_message() flow."""

    def test_filters_advertising_from_commit(self):
        """Filters advertising from git commit command."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [{"pattern": "🤖 Generated with.*", "description": "Claude ad", "replacement": ""}],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        cmd = 'git commit -m "Add feature\\n\\n🤖 Generated with Claude Code"'
        result = filter_instance.filter_commit_message(cmd)

        assert result.was_modified
        assert "🤖 Generated" not in result.cleaned_message
        assert "Add feature" in result.cleaned_message
        assert "advertising" in result.categories_matched

    def test_passes_through_non_git_commands(self):
        """Passes through non-git commands unchanged."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})

        cmd = "ls -la"
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd

    def test_passes_through_when_disabled(self):
        """Passes through when filter disabled."""
        filter_instance = CommitMessageFilter({"enabled": False, "rules": {}})

        cmd = 'git commit -m "test"'
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd

    def test_amend_message_reuse_passes_through_cleanly(self):
        """git commit --amend reuses the existing message (no NEW content) -> clean pass.

        Previously this was treated as an extraction *failure* (error set). It is not a
        failure: there is simply no new author-supplied content to scan, so it must pass
        through cleanly without flagging, exactly like every routine amend/reuse.
        """
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})

        cmd = "git commit --amend"  # No -m flag: reuses existing message via editor
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd  # commit not broken
        assert result.message_delivery == "none"
        assert result.unscannable_decision is None
        assert result.error is None  # legitimate reuse, not a failure

    def test_fails_open_on_empty_message_after_filtering(self):
        """Returns original when cleaned message is empty."""
        config = {
            "enabled": True,
            "rules": {
                "test": {
                    "enabled": True,
                    "patterns": [
                        {"pattern": ".*", "description": "Remove all", "replacement": ""}  # Remove everything
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        cmd = 'git commit -m "test"'
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified  # Don't use cleaned (it's empty)
        assert result.cleaned_command == cmd  # Return original
        assert result.error is not None  # Error logged

    def test_multiple_m_flags_detected_and_filtered(self):
        """FIX 6: Multiple -m flags with advertising in second message."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [{"pattern": "Generated with Claude Code", "description": "Claude ad", "replacement": ""}],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        cmd = 'git commit -m "Clean feature" -m "Generated with Claude Code"'
        result = filter_instance.filter_commit_message(cmd)

        assert result.was_modified
        assert "Generated with Claude Code" not in result.cleaned_message
        assert "Clean feature" in result.cleaned_message
        # Should have filtered the advertising from combined message
        assert "advertising" in result.categories_matched

    def test_compound_command_with_advertising_blocked(self):
        """FIX 7: Compound command with advertising should be detected and blocked."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [
                        {
                            "pattern": "Co-Authored-By:\\s*Claude\\s*<noreply@anthropic\\.com>",
                            "description": "Claude co-author",
                            "replacement": "",
                        },
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        # This is the EXACT pattern that bypassed the filter
        cmd = '''git add src/foo.ts && git commit -m "refactor: do thing\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'''
        result = filter_instance.filter_commit_message(cmd)

        assert result.was_modified, "Compound command should trigger filter"
        assert "Co-Authored-By" not in result.cleaned_message
        assert "advertising" in result.categories_matched
        # Critical: compound command prefix must be preserved
        assert "git add" in result.cleaned_command
        assert "&&" in result.cleaned_command

    def test_triple_chain_command_with_advertising(self):
        """FIX 7: Triple-chained command with advertising should filter correctly."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [
                        {"pattern": "Generated with Claude Code", "description": "Claude ad", "replacement": ""},
                    ],
                }
            },
        }
        filter_instance = CommitMessageFilter(config)

        cmd = 'cd project && git add -A && git commit -m "feature: add thing\\n\\nGenerated with Claude Code"'
        result = filter_instance.filter_commit_message(cmd)

        assert result.was_modified
        assert "Generated with Claude Code" not in result.cleaned_message
        # Preserve all parts of compound command
        assert "cd project" in result.cleaned_command
        assert "git add -A" in result.cleaned_command
        assert "git commit" in result.cleaned_command


class TestErrorHandling:
    """Test error handling and fail-open behavior."""

    def test_handles_invalid_regex_pattern(self):
        """Skips invalid regex patterns without raising."""
        config = {
            "enabled": True,
            "rules": {
                "test": {
                    "enabled": True,
                    "patterns": [
                        {"pattern": "[invalid(regex", "description": "Bad pattern", "replacement": ""}  # Invalid regex
                    ],
                }
            },
        }

        # Should not raise - invalid pattern is skipped
        filter_instance = CommitMessageFilter(config)
        assert len(filter_instance._compiled_patterns) == 0  # Pattern skipped

    def test_off_action_passes_through_without_error(self):
        """With unscannable_message_action=off, an unscannable (file-delivered) message
        passes through cleanly. ``error`` is reserved for genuine filter FAILURES, so a
        deliberate config-driven pass-through must NOT set it (else downstream callers and
        audit data can't tell a chosen skip from a real failure). The skip is recorded by
        message_delivery="unscannable" + unscannable_decision=None instead.
        """
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}, "unscannable_message_action": "off"})

        cmd = "git commit -F /tmp/msg.txt"  # content on disk, not scannable
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd  # Original, commit not broken
        assert result.error is None  # deliberate skip is NOT a failure
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision is None  # off -> no warn/block surfaced

    def test_catches_unexpected_exceptions(self):
        """Catches unexpected exceptions and fails open."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})

        # Patch extract_commit_message to raise exception
        with patch.object(filter_instance, "extract_commit_message", side_effect=RuntimeError("Test error")):
            cmd = 'git commit -m "test"'
            result = filter_instance.filter_commit_message(cmd)

            assert not result.was_modified
            assert result.cleaned_command == cmd  # Original (fail-open)
            assert result.error is not None


class TestConfiguration:
    """Test configuration loading."""

    def test_loads_default_config(self, data_dir):
        """Loads config from data/commit_filter_rules.yaml."""
        config = load_filter_config()

        assert "rules" in config
        assert "advertising" in config["rules"]
        assert config["rules"]["advertising"]["enabled"] is True

    def test_disables_filter_on_missing_config(self):
        """Disables filter when config file missing."""
        config = load_filter_config("/nonexistent/path.yaml")

        assert config["enabled"] is False

    def test_loads_test_config(self, tmp_path):
        """Loads config from custom path."""
        test_config = {
            "enabled": True,
            "rules": {"test": {"enabled": True, "patterns": [{"pattern": "test", "description": "", "replacement": ""}]}},
        }

        config_file = tmp_path / "test_config.yaml"
        with open(config_file, "w") as f:
            yaml.dump(test_config, f)

        config = load_filter_config(str(config_file))

        assert config["enabled"] is True
        assert "test" in config["rules"]


class TestCategoryControl:
    """Test category-level enable/disable."""

    def test_respects_category_enabled_flag(self):
        """Skips disabled categories during pattern compilation."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": False,  # Disabled
                    "patterns": [{"pattern": "test", "description": "test", "replacement": ""}],
                }
            },
        }

        filter_instance = CommitMessageFilter(config)
        assert len(filter_instance._compiled_patterns) == 0  # No patterns (category disabled)

    def test_multiple_categories(self):
        """Supports multiple active categories."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [{"pattern": "ad", "description": "", "replacement": ""}],
                },
                "custom": {
                    "enabled": True,
                    "patterns": [{"pattern": "custom", "description": "", "replacement": ""}],
                },
            },
        }

        filter_instance = CommitMessageFilter(config)
        assert len(filter_instance._compiled_patterns) == 2  # Both categories active

    def test_tracks_categories_matched(self):
        """Tracks which categories matched during cleaning."""
        config = {
            "enabled": True,
            "rules": {
                "advertising": {
                    "enabled": True,
                    "patterns": [{"pattern": "ad", "description": "", "replacement": ""}],
                },
                "custom": {
                    "enabled": True,
                    "patterns": [{"pattern": "custom", "description": "", "replacement": ""}],
                },
            },
        }

        filter_instance = CommitMessageFilter(config)
        message = "This has ad and custom content"
        _, patterns, categories = filter_instance.clean_message(message)

        assert "advertising" in categories
        assert "custom" in categories
        assert len(patterns) == 2


class TestPerformance:
    """Test performance requirements."""

    @pytest.mark.slow
    def test_git_commit_filtering_performance(self):
        """Git commit filtering completes in <20ms."""
        config = load_filter_config()
        filter_instance = CommitMessageFilter(config)

        cmd = 'git commit -m "Add feature\\n\\nGenerated with Claude Code"'

        start = time.time()
        result = filter_instance.filter_commit_message(cmd)
        duration = time.time() - start

        assert result.was_modified  # Verify it actually filtered
        assert duration < 0.02  # <20ms

    @pytest.mark.slow
    def test_non_git_command_overhead(self):
        """Non-git command overhead is <2ms."""
        config = load_filter_config()
        filter_instance = CommitMessageFilter(config)

        cmd = "ls -la"

        start = time.time()
        result = filter_instance.filter_commit_message(cmd)
        duration = time.time() - start

        assert not result.was_modified
        assert duration < 0.002  # <2ms

    def test_pattern_compilation_at_init(self):
        """Patterns compiled once at init, not per filter call."""
        config = load_filter_config()
        filter_instance = CommitMessageFilter(config)

        # Verify patterns were compiled (should have >0 patterns for advertising category)
        assert len(filter_instance._compiled_patterns) > 0

        # Verify patterns are stored and not recompiled on each call
        patterns_before = filter_instance._compiled_patterns
        filter_instance.filter_commit_message('git commit -m "test"')
        patterns_after = filter_instance._compiled_patterns

        # Same object reference means no recompilation
        assert patterns_before is patterns_after


class TestMessageDeliveryClassification:
    """classify_message_delivery distinguishes three commit-message delivery classes.

    This is the content-aware detector that makes ``warn`` a safe default. The bare
    ``None`` extraction signal is overloaded: ``git commit --amend --no-edit``,
    ``git commit -C HEAD`` (legit message reuse) and ``git commit -F file`` (the #76
    advertising bypass) ALL extract to ``None``. Policy keyed on extraction alone would
    block every amend/reuse. The classifier separates them:

    - ``scannable``   a message extracted from argv (any ``-m "..."`` form). Its literal bytes
                      are present, so it is scanned as-is even if it embeds an incidental
                      ``$(...)`` - the literal parts (including a trailer) are still matched.
    - ``unscannable`` the message is delivered from OUTSIDE argv: ``-F``/``--file`` (a file, or
                      ``-`` for stdin). Nothing in the command to scan -> warn/block only.
    - ``none``        no NEW author-supplied content (bare commit, ``--amend --no-edit``,
                      ``-C``/``-c``/``--squash``/``--fixup``/``--template`` -> nothing to smuggle)
    """

    @staticmethod
    def _filter():
        return CommitMessageFilter({"enabled": True, "rules": {}})

    # --- scannable: content is inline in argv ---

    def test_inline_message_is_scannable(self):
        """Plain inline -m message is scannable."""
        assert self._filter().classify_message_delivery('git commit -m "fix: a bug"') == "scannable"

    def test_inline_heredoc_substitution_is_scannable(self):
        """-m "$(cat <<'EOF'...EOF)" inline heredoc body is literally in argv -> scannable."""
        cmd = "git commit -m \"$(cat <<'EOF'\nfix: a bug\nEOF\n)\""
        assert self._filter().classify_message_delivery(cmd) == "scannable"

    # --- unscannable: content-bearing flag points outside argv ---

    def test_file_flag_short_is_unscannable(self):
        """git commit -F file -> content on disk, not argv."""
        assert self._filter().classify_message_delivery("git commit -F /tmp/msg.txt") == "unscannable"

    def test_file_flag_attached_long_is_unscannable(self):
        """git commit --file=file -> unscannable."""
        assert self._filter().classify_message_delivery("git commit --file=/tmp/msg.txt") == "unscannable"

    def test_file_flag_separated_long_is_unscannable(self):
        """git commit --file file -> unscannable."""
        assert self._filter().classify_message_delivery("git commit --file /tmp/msg.txt") == "unscannable"

    def test_file_flag_attached_short_is_unscannable(self):
        """git commit -F/tmp/msg.txt (attached) -> unscannable."""
        assert self._filter().classify_message_delivery("git commit -F/tmp/msg.txt") == "unscannable"

    def test_amend_with_file_is_unscannable(self):
        """--amend alone would be 'none', but -F supplies content -> unscannable wins."""
        assert self._filter().classify_message_delivery("git commit --amend -F /tmp/msg.txt") == "unscannable"

    def test_stdin_dash_file_is_unscannable(self):
        """git commit -F - reads the message from stdin -> unscannable."""
        assert self._filter().classify_message_delivery("git commit -F -") == "unscannable"

    def test_external_command_substitution_is_scannable(self):
        """-m "$(cat externalfile)": the literal $(...) text IS in argv -> scannable.

        We scan the literal token (which matches nothing for a pure substitution), so it
        slips pre-execution; that niche bypass is deferred to the post-commit check. We do
        NOT treat it as unscannable, because doing so would also stop scanning -m messages
        that merely embed an incidental substitution alongside a literal trailer.
        """
        assert self._filter().classify_message_delivery('git commit -m "$(cat /tmp/msg.txt)"') == "scannable"

    def test_backtick_substitution_is_scannable(self):
        """-m "`cat externalfile`": the literal backtick text is in argv -> scannable (see above)."""
        assert self._filter().classify_message_delivery('git commit -m "`cat /tmp/msg.txt`"') == "scannable"

    # --- none: no NEW author-supplied content (legit reuse / defer) ---

    def test_bare_commit_is_none(self):
        """Bare git commit opens an editor; no new argv content."""
        assert self._filter().classify_message_delivery("git commit") == "none"

    def test_amend_no_edit_is_none(self):
        """--amend --no-edit reuses the existing message; nothing to smuggle."""
        assert self._filter().classify_message_delivery("git commit --amend --no-edit") == "none"

    def test_reuse_message_short_is_none(self):
        """-C HEAD reuses another commit's message."""
        assert self._filter().classify_message_delivery("git commit -C HEAD") == "none"

    def test_reuse_message_long_is_none(self):
        """--reuse-message=HEAD reuses another commit's message."""
        assert self._filter().classify_message_delivery("git commit --reuse-message=HEAD") == "none"

    def test_reedit_message_is_none(self):
        """-c HEAD~1 reedits a reused message (editor-based)."""
        assert self._filter().classify_message_delivery("git commit -c HEAD~1") == "none"

    def test_squash_is_none(self):
        """--squash=HEAD defers message to rebase."""
        assert self._filter().classify_message_delivery("git commit --squash=HEAD") == "none"

    def test_fixup_is_none(self):
        """--fixup=HEAD defers message to rebase."""
        assert self._filter().classify_message_delivery("git commit --fixup=HEAD") == "none"

    def test_template_is_none(self):
        """--template populates the editor; no non-interactive content."""
        assert self._filter().classify_message_delivery("git commit --template=/tmp/tpl.txt") == "none"

    def test_non_git_commit_is_none(self):
        """Non git-commit commands have no message to classify."""
        assert self._filter().classify_message_delivery("ls -la") == "none"

    def test_compound_command_with_file_is_unscannable(self):
        """Locates the git commit segment in a compound command."""
        cmd = "git add -A && git commit -F /tmp/msg.txt"
        assert self._filter().classify_message_delivery(cmd) == "unscannable"

    # --- a -m message that embeds substitution chars is still scannable (no false "unscannable") ---
    # (panel finding A: an earlier quote-aware classifier mis-flagged single-quoted literals; the
    #  fix is simpler - any extracted -m value is literally in argv, so it is always scannable.)

    def test_single_quoted_dollar_paren_is_scannable(self):
        """git commit -m 'fix $(x) parsing' is a literal in argv -> scannable."""
        assert self._filter().classify_message_delivery("git commit -m 'fix $(x) parsing'") == "scannable"

    def test_single_quoted_backtick_is_scannable(self):
        """git commit -m 'use `make` to build' is a literal in argv -> scannable."""
        assert self._filter().classify_message_delivery("git commit -m 'use `make` to build'") == "scannable"

    # --- combined short-flag cluster (panel finding B): -aF still delivers via file ---

    def test_combined_short_flag_cluster_is_unscannable(self):
        """git commit -aF /tmp/msg.txt clusters -a and -F; the -F file delivery must be seen."""
        assert self._filter().classify_message_delivery("git commit -aF /tmp/msg.txt") == "unscannable"

    # --- DoS guard (panel finding C): oversized command must not parse the whole string ---

    def test_oversized_command_skips_bashlex_parse(self):
        """An oversized command must never reach bashlex.parse (DoS guard), yet still classify."""
        cmd = "git commit -F /tmp/msg.txt " + ("a " * 40000)  # > MAX_COMMAND_SIZE, many tokens
        with patch("schlock.integrations.commit_filter.bashlex.parse") as mock_parse:
            result = self._filter().classify_message_delivery(cmd)
        mock_parse.assert_not_called()  # guard short-circuits before parsing the whole string
        assert result == "unscannable"  # split fallback still sees -F

    # --- compound-command bypass (CodeRabbit): a -F in ANY segment wins over an earlier -m ---

    def test_compound_inline_then_file_is_unscannable(self):
        """git commit -m "ok" && git commit -F file: the 2nd commit's -F must not be masked."""
        cmd = 'git commit -m "ok" && git commit -F /tmp/msg.txt'
        assert self._filter().classify_message_delivery(cmd) == "unscannable"

    # --- option terminator (CodeRabbit): tokens after -- are pathspecs, not message flags ---

    def test_file_flag_after_double_dash_is_not_a_message_flag(self):
        """git commit -- -F : '-F' is a pathspec here, not a message source -> none."""
        assert self._filter().classify_message_delivery("git commit -- -F") == "none"

    def test_long_file_flag_after_double_dash_is_not_a_message_flag(self):
        """git commit -- --file : '--file' is a pathspec here -> none."""
        assert self._filter().classify_message_delivery("git commit -- --file") == "none"


class TestUnscannableMessageAction:
    """filter_commit_message surfaces a warn/block decision for unscannable
    content-bearing commits (issue #76), governed by ``unscannable_message_action``
    (off | warn | block; default warn). ``none`` delivery (reuse/amend) is never flagged,
    and scannable advertising is still cleaned exactly as before.
    """

    @staticmethod
    def _filter(action=None, rules=None):
        cfg = {"enabled": True, "rules": rules or {}}
        if action is not None:
            cfg["unscannable_message_action"] = action
        return CommitMessageFilter(cfg)

    def test_default_action_is_warn(self):
        """Unspecified action defaults to warn (non-destructive, but not silent)."""
        assert self._filter().unscannable_action == "warn"

    def test_invalid_action_falls_back_to_warn(self):
        """An invalid action value falls back to the safe default rather than raising."""
        assert self._filter(action="bogus").unscannable_action == "warn"

    def test_off_action_respected(self):
        """unscannable_message_action: off is preserved on the instance."""
        assert self._filter(action="off").unscannable_action == "off"

    def test_file_form_warns_by_default(self):
        """git commit -F file is flagged warn by default, command left unmodified."""
        result = self._filter().filter_commit_message("git commit -F /tmp/msg.txt")
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision == "warn"
        assert not result.was_modified
        assert result.unscannable_reason  # non-empty human explanation
        assert result.cleaned_command == "git commit -F /tmp/msg.txt"

    def test_file_form_blocks_when_configured(self):
        """unscannable_message_action: block surfaces a block decision."""
        result = self._filter(action="block").filter_commit_message("git commit -F /tmp/msg.txt")
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision == "block"

    def test_file_form_silent_when_off(self):
        """unscannable_message_action: off restores today's silent fail-open (no decision)."""
        result = self._filter(action="off").filter_commit_message("git commit -F /tmp/msg.txt")
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision is None
        assert not result.was_modified

    def test_stdin_form_warns(self):
        """git commit -F - (message on stdin) is flagged unscannable -> warn."""
        result = self._filter().filter_commit_message("git commit -F -")
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision == "warn"

    def test_inline_substitution_is_scannable_not_flagged(self):
        """-m "$(cat externalfile)": literal $(...) is in argv -> scannable, never warn/block."""
        result = self._filter().filter_commit_message('git commit -m "$(cat /tmp/msg.txt)"')
        assert result.message_delivery == "scannable"
        assert result.unscannable_decision is None

    def test_amend_no_edit_not_flagged(self):
        """--amend --no-edit reuses a message; never flagged regardless of action."""
        result = self._filter(action="block").filter_commit_message("git commit --amend --no-edit")
        assert result.message_delivery == "none"
        assert result.unscannable_decision is None
        assert not result.was_modified

    def test_reuse_message_not_flagged(self):
        """-C HEAD reuses a message; never flagged."""
        result = self._filter(action="block").filter_commit_message("git commit -C HEAD")
        assert result.message_delivery == "none"
        assert result.unscannable_decision is None

    def test_scannable_advertising_still_cleaned(self):
        """Regression: scannable inline advertising is still detected and cleaned."""
        rules = {
            "advertising": {
                "enabled": True,
                "patterns": [{"pattern": "Generated with Claude Code", "description": "ad", "replacement": ""}],
            }
        }
        cmd = 'git commit -m "feat: x\\n\\nGenerated with Claude Code"'
        result = self._filter(rules=rules).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed
        assert result.unscannable_decision is None

    def test_scannable_clean_message_unmodified(self):
        """A clean scannable message is neither modified nor flagged."""
        result = self._filter().filter_commit_message('git commit -m "feat: clean"')
        assert result.message_delivery == "scannable"
        assert result.unscannable_decision is None
        assert not result.was_modified

    def test_inline_substitution_with_literal_trailer_is_still_cleaned(self):
        """Regression guard: a -m message with an INCIDENTAL substitution but a LITERAL trailer
        must still be scanned and the trailer stripped. The literal bytes are in argv; an
        incidental $(...) elsewhere must not disable scanning of the rest."""
        rules = {
            "advertising": {
                "enabled": True,
                "patterns": [
                    {"pattern": "\\n*Co-Authored-By:.*Claude.*\\n*", "description": "claude trailer", "replacement": "\n"}
                ],
            }
        }
        cmd = 'git commit -m "Deploy $(date)\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=rules).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed  # the literal trailer IS caught despite the $(date)
        assert result.unscannable_decision is None


class TestGitGlobalOptions:
    """Issue #82: git accepts GLOBAL options between `git` and the `commit` subcommand
    (`git -C <path> commit`, `git -c k=v commit`, `git --git-dir=… commit`, `git --work-tree …
    commit`). The filter assumed adjacency (`git commit`), so these forms bypassed detection,
    extraction, file-flag classification, and ultimately the advertising blocker entirely.
    """

    CLAUDE_TRAILER_RULES = {
        "advertising": {
            "enabled": True,
            "patterns": [
                {
                    "pattern": "\\n*Co-Authored-By:.*(?:Claude|@anthropic\\.com).*\\n*",
                    "description": "Claude co-author trailer",
                    "replacement": "\n",
                }
            ],
        }
    }

    @staticmethod
    def _filter(rules=None):
        return CommitMessageFilter({"enabled": True, "rules": rules or {}})

    # --- detection: is_git_commit_command tolerates global options ---

    def test_detects_chdir_option(self):
        """git -C <path> commit is a git commit."""
        assert self._filter().is_git_commit_command('git -C /tmp/r commit -m "x"')

    def test_detects_dash_c_config(self):
        """git -c key=val commit is a git commit (the value is not mistaken for the subcommand)."""
        assert self._filter().is_git_commit_command('git -c user.name=Ada commit -m "x"')

    def test_detects_git_dir_attached(self):
        """git --git-dir=<dir> commit is a git commit."""
        assert self._filter().is_git_commit_command('git --git-dir=/tmp/r/.g commit -m "x"')

    def test_detects_work_tree_separate(self):
        """git --work-tree <dir> commit (separate-word value) is a git commit."""
        assert self._filter().is_git_commit_command('git --work-tree /tmp/r commit -m "x"')

    def test_detects_valueless_global_flag(self):
        """git --no-pager commit (value-less global flag) is a git commit."""
        assert self._filter().is_git_commit_command('git --no-pager commit -m "x"')

    def test_detects_global_options_in_compound(self):
        """Compound command with a global-option git commit is detected."""
        assert self._filter().is_git_commit_command('cd proj && git -C /tmp/r commit -m "x"')

    # --- detection regressions: must NOT over-match ---

    def test_chdir_option_with_non_commit_subcommand_is_not_a_commit(self):
        """git -C <path> status is NOT a commit (the subcommand is status, not commit)."""
        assert not self._filter().is_git_commit_command("git -C /tmp/r status")

    def test_plain_forms_unchanged(self):
        """Plain detection is unchanged by the global-option support."""
        f = self._filter()
        assert f.is_git_commit_command('git commit -m "x"')
        assert not f.is_git_commit_command("git status")
        assert not f.is_git_commit_command("git push")
        assert not f.is_git_commit_command("ls -la")

    # --- extraction through a global-option invocation ---

    def test_extracts_message_with_chdir_option(self):
        """The -m message is extracted from a git -C … commit invocation."""
        assert self._filter().extract_commit_message('git -C /tmp/r commit -m "hello"') == "hello"

    def test_extracts_multiple_m_with_global_config(self):
        """Multiple -m flags still combine when global options precede commit."""
        msg = self._filter().extract_commit_message('git -c core.editor=true commit -m "a" -m "b"')
        assert msg == "a\n\nb"

    # --- delivery classification ---

    def test_global_option_inline_is_scannable(self):
        assert self._filter().classify_message_delivery('git -C /tmp/r commit -m "x"') == "scannable"

    def test_global_option_file_is_unscannable(self):
        """git -C … commit -F file delivers from a file -> unscannable (was missed -> 'none')."""
        assert self._filter().classify_message_delivery("git -C /tmp/r commit -F msg.txt") == "unscannable"

    # --- end-to-end: the bypass is closed ---

    def test_global_option_trailer_is_caught(self):
        """THE #82 fix: git -C … commit -m "…trailer" is now scanned and blocked."""
        cmd = 'git -C /tmp/r commit -m "feat: x\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed

    def test_global_option_file_warns(self):
        """git -C … commit -F file triggers the #76 unscannable decision (default warn)."""
        result = self._filter().filter_commit_message("git -C /tmp/r commit -F msg.txt")
        assert result.message_delivery == "unscannable"
        assert result.unscannable_decision == "warn"

    # --- file-flag regression: plain form still detected ---

    def test_plain_file_flag_still_unscannable(self):
        assert self._filter().classify_message_delivery("git commit -F msg.txt") == "unscannable"

    # --- synthesis (#82 detector x #77 extractor): global option AND long flag together ---
    # Neither #82 nor #81 exercised this combination alone; it only works because the merged
    # _extract_via_bashlex feeds #82's global-option detection into #81's --message loop.

    def test_global_option_with_long_flag_extracts(self):
        """git -C <path> commit --message="x" needs BOTH global-option detection and long-flag
        extraction; the merge of #82 + #81 must keep them composed."""
        assert self._filter().extract_commit_message('git -C /tmp/r commit --message="hello world"') == "hello world"

    def test_global_option_with_long_flag_trailer_is_caught(self):
        """git -C <path> commit --message="…trailer" is scanned and blocked (composed fix)."""
        cmd = 'git -C /tmp/r commit --message="feat: x\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed


class TestLongMessageFlag:
    """Issue #77: ``git commit --message`` / ``--message=`` deliver the message in argv, but
    the extractor only recognized ``-m`` - so advertising trailers supplied via the long flag
    slipped through (fail-open). The message bytes ARE in the command, so this is a plain
    extraction gap (distinct from #76, where content lives in a file/stdin). Both extraction
    paths and command reconstruction must recognize the long flag.

    Scope note: abbreviated long flags (``--mess``, ``--messa``) are git-valid unambiguous
    prefixes of ``--message`` but are NOT covered - no agent emits abbreviated flags and this
    is a fail-open cosmetic filter, not a security boundary. See ``test_abbreviated_long_flag_
    is_known_residual_gap`` which documents the residual.
    """

    # Real Claude co-author trailer pattern, mirroring data/commit_filter_rules.yaml so these
    # tests exercise the production rule rather than a toy stand-in.
    CLAUDE_TRAILER_RULES = {
        "advertising": {
            "enabled": True,
            "patterns": [
                {
                    "pattern": "\\n*Co-Authored-By:.*(?:Claude|@anthropic\\.com).*\\n*",
                    "description": "Claude co-author trailer",
                    "replacement": "\n",
                },
                {
                    "pattern": "\\n*🤖.*Generated with.*\\n*",
                    "description": "robot-emoji generation notice",
                    "replacement": "\n",
                },
            ],
        }
    }

    @staticmethod
    def _filter(rules=None):
        return CommitMessageFilter({"enabled": True, "rules": rules or {}})

    # --- extraction: separate-word long flag (--message "msg") ---

    def test_extracts_long_flag_separate_double_quoted(self):
        """--message "msg" (space-separated, double-quoted) is extracted like -m."""
        msg = self._filter().extract_commit_message('git commit --message "hello world"')
        assert msg == "hello world"

    def test_extracts_long_flag_separate_single_quoted(self):
        """--message 'msg' (space-separated, single-quoted) is extracted."""
        msg = self._filter().extract_commit_message("git commit --message 'hello world'")
        assert msg == "hello world"

    def test_extracts_long_flag_separate_with_literal_newlines(self):
        """--message "L1\\nL2" converts literal \\n to real newlines like -m does."""
        msg = self._filter().extract_commit_message('git commit --message "Line 1\\nLine 2"')
        assert msg == "Line 1\nLine 2"

    # --- extraction: attached long flag (--message=msg) ---

    def test_extracts_long_flag_attached_double_quoted(self):
        """--message="msg" (attached, =) strips the flag prefix and the quotes."""
        msg = self._filter().extract_commit_message('git commit --message="hello world"')
        assert msg == "hello world"

    def test_extracts_long_flag_attached_single_quoted(self):
        """--message='msg' (attached, single-quoted) is extracted."""
        msg = self._filter().extract_commit_message("git commit --message='hello world'")
        assert msg == "hello world"

    def test_extracts_long_flag_attached_unquoted(self):
        """--message=word (attached, no quotes - single shell token) is extracted."""
        msg = self._filter().extract_commit_message("git commit --message=fix")
        assert msg == "fix"

    def test_extracts_long_flag_attached_with_literal_newlines(self):
        """--message="L1\\nL2" must preserve \\n via raw-position slicing (not bashlex .word,
        which drops the backslash). This is the load-bearing case for multi-line trailers."""
        msg = self._filter().extract_commit_message('git commit --message="Line 1\\nLine 2"')
        assert msg == "Line 1\nLine 2"

    # --- extraction: mixed short + long flags accumulate in order ---

    def test_mixed_short_then_long_combined(self):
        """git commit -m "a" --message "b" combines both into one message."""
        msg = self._filter().extract_commit_message('git commit -m "first" --message "second"')
        assert msg == "first\n\nsecond"

    def test_mixed_long_then_short_combined(self):
        """git commit --message "a" -m "b" combines both in argv order."""
        msg = self._filter().extract_commit_message('git commit --message "first" -m "second"')
        assert msg == "first\n\nsecond"

    def test_mixed_attached_long_and_short_combined(self):
        """--message="a" mixed with -m "b" - all segments scanned."""
        msg = self._filter().extract_commit_message('git commit --message="first" -m "second"')
        assert msg == "first\n\nsecond"

    # --- classification: long-flag messages are scannable (content is in argv) ---

    def test_long_flag_separate_is_scannable(self):
        """--message "x" content is literally in argv -> scannable."""
        assert self._filter().classify_message_delivery('git commit --message "fix: a bug"') == "scannable"

    def test_long_flag_attached_is_scannable(self):
        """--message="x" content is literally in argv -> scannable."""
        assert self._filter().classify_message_delivery('git commit --message="fix: a bug"') == "scannable"

    def test_long_flag_with_incidental_substitution_is_scannable(self):
        """--message="Deploy $(date)" - the literal $(...) text is in argv -> scannable
        (consistent with the -m invariant; pre-exec substitution detection is #79, not here)."""
        assert self._filter().classify_message_delivery('git commit --message="Deploy $(date)"') == "scannable"

    # --- end-to-end: the trailer that prompted #77 no longer slips ---

    def test_attached_long_flag_trailer_is_caught(self):
        """THE #77 fix: --message="...Co-Authored-By: Claude..." is now blocked (patterns_removed)."""
        cmd = 'git commit --message="feat: thing\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed  # hook denies on this

    def test_separate_long_flag_trailer_is_caught(self):
        """--message "...🤖 Generated with..." (space-separated) is now blocked."""
        cmd = 'git commit --message "feat: thing\\n\\n🤖 Generated with Claude Code"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed

    def test_clean_long_flag_message_is_not_flagged(self):
        """A clean --message commit is scannable, unmodified, and never flagged."""
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message('git commit --message="feat: clean"')
        assert result.message_delivery == "scannable"
        assert not result.patterns_removed
        assert not result.was_modified

    # --- reconstruct_command: the long flag must be rewritten, not left dirty ---

    def test_reconstructs_separate_long_flag(self):
        """reconstruct_command rewrites --message "dirty" with the cleaned message."""
        out = self._filter().reconstruct_command('git commit --message "dirty message"', "cleaned")
        assert "cleaned" in out

    def test_reconstructs_attached_long_flag(self):
        """reconstruct_command rewrites --message="dirty" with the cleaned message."""
        out = self._filter().reconstruct_command('git commit --message="dirty message"', "cleaned")
        assert "cleaned" in out

    def test_reconstruct_long_flag_drops_original_dirty_text(self):
        """Latent-bug guard: reconstruct used to return the ORIGINAL command verbatim when no
        -m was present, leaking the dirty text. The removed content must NOT survive."""
        out = self._filter().reconstruct_command('git commit --message "REMOVE_ME keep"', "keep")
        assert "REMOVE_ME" not in out
        assert "keep" in out

    # --- regression: short -m behavior is byte-for-byte unchanged by the shared fragment ---

    def test_short_flag_extraction_unchanged(self):
        """Refactor guard: plain -m "x" still extracts exactly "x"."""
        assert self._filter().extract_commit_message('git commit -m "x"') == "x"

    def test_short_flag_equals_not_treated_as_attached_message(self):
        """Refactor guard: -m=foo must NOT be newly captured (the shared fragment keeps -m
        strict with \\s+, so attached-short forms behave exactly as before: not extracted)."""
        assert self._filter().extract_commit_message("git commit -m=foo") is None

    # --- regex fallback path (bashlex bypassed) ---
    # extract_commit_message tries bashlex first and returns before the regex fallback for any
    # well-formed command, so the new --message handling in _extract_via_regex is NOT reached by
    # the other tests. These target the fallback directly (and via heredocs, which make bashlex
    # raise) so a regression in the shared _MSG_FLAG fragment cannot pass CI silently.

    def test_regex_fallback_extracts_quoted_long_flag(self):
        """_extract_via_regex handles --message "msg" (Pattern 2)."""
        assert self._filter()._extract_via_regex('git commit --message "hi there"') == "hi there"

    def test_regex_fallback_extracts_attached_long_flag(self):
        """_extract_via_regex handles --message="msg" (Pattern 2 with =)."""
        assert self._filter()._extract_via_regex('git commit --message="hi there"') == "hi there"

    def test_regex_fallback_extracts_unquoted_attached_long_flag(self):
        """_extract_via_regex handles --message=word (Pattern 4 - the new branch, guarded ONLY
        here since the bashlex path otherwise masks it through the public API)."""
        assert self._filter()._extract_via_regex("git commit --message=fix") == "fix"

    def test_regex_fallback_collects_multiple_unquoted_long_flags(self):
        """CodeRabbit #81: Pattern 4 must collect ALL unquoted --message= tokens (parity with the
        quoted Pattern 2), not just the first — else a single-token ad in a later flag slips the
        regex fallback (e.g. --message=ok --message=claude.com/claude-code)."""
        assert self._filter()._extract_via_regex("git commit --message=first --message=second") == "first\n\nsecond"

    def test_regex_fallback_mixed_quoted_and_unquoted_long_flags(self):
        """CodeRabbit #81 (r4): a quoted --message must NOT short-circuit the fallback and drop a
        later UNQUOTED --message= token — both are kept, in argv order."""
        assert self._filter()._extract_via_regex('git commit --message="clean" --message=adtoken') == "clean\n\nadtoken"

    def test_regex_fallback_unquoted_then_quoted_long_flags(self):
        """Order preserved the other way too: unquoted before quoted keeps both, in order."""
        assert self._filter()._extract_via_regex('git commit --message=adtoken --message="clean"') == "adtoken\n\nclean"

    def test_regex_fallback_mixed_preserves_ad_token_so_cleaner_catches_it(self):
        """CodeRabbit #81 (r4) named example: `--message="ok" --message=claude.com/claude-code`.
        The quoted flag must not short-circuit and drop the later UNQUOTED single-token ad URL —
        the fallback keeps BOTH, so the cleaner still strips the ad (the bypass is closed end to
        end, not merely at extraction)."""
        rules = {
            "advertising": {
                "enabled": True,
                "patterns": [{"pattern": r"claude\.com/claude-code", "description": "ad url", "replacement": ""}],
            }
        }
        f = self._filter(rules=rules)
        extracted = f._extract_via_regex('git commit --message="ok" --message=claude.com/claude-code')
        assert extracted == "ok\n\nclaude.com/claude-code"  # both tokens preserved through the fallback
        _, removed, _ = f.clean_message(extracted)
        assert removed  # the preserved ad token is detected by the cleaner

    def test_regex_fallback_extracts_empty_long_flag(self):
        """_extract_via_regex returns '' for --message="" (Pattern 3)."""
        assert self._filter()._extract_via_regex('git commit --message=""') == ""

    def test_heredoc_long_flag_drives_regex_fallback(self):
        """A --message heredoc makes bashlex raise, so the public API must extract via the regex
        fallback (Pattern 1) - the realistic load-bearing form for this path."""
        heredoc_cmd = """git commit --message "$(cat <<'EOF'
Multi-line
message
EOF
)\""""
        assert self._filter().extract_commit_message(heredoc_cmd) == "Multi-line\nmessage"

    def test_heredoc_long_flag_trailer_is_caught(self):
        """End-to-end through the regex fallback: a --message heredoc carrying a Claude trailer
        is still blocked (patterns_removed). Proves #77 closes for the heredoc long-flag form."""
        heredoc_cmd = """git commit --message "$(cat <<'EOF'
feat: thing

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)\""""
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(heredoc_cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed

    # --- compound commands (git commit --message after &&/;) (CodeRabbit #81) ---
    # The -m path has compound coverage (TestMessageExtraction); these give the long flag parity
    # so a classifier/extraction regression on a compound segment cannot pass CI.

    def test_compound_attached_long_flag_trailer_is_caught(self):
        """git add . && git commit --message="...trailer" is scanned and blocked, and the
        `git add . &&` prefix survives reconstruction (only the trailer is removed)."""
        cmd = 'git add . && git commit --message="feat: thing\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed
        assert result.was_modified
        assert "git add . &&" in result.cleaned_command  # compound prefix preserved
        assert "Co-Authored" not in result.cleaned_command  # trailer stripped

    def test_compound_separate_long_flag_trailer_is_caught(self):
        """git add . && git commit --message "...trailer" (space-separated) is scanned and
        blocked, and the `git add . &&` prefix survives reconstruction."""
        cmd = 'git add . && git commit --message "feat: thing\\n\\n🤖 Generated with Claude Code"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed
        assert result.was_modified
        assert "git add . &&" in result.cleaned_command  # compound prefix preserved
        assert "Generated with" not in result.cleaned_command  # trailer stripped

    def test_clean_compound_long_flag_message_is_not_flagged(self):
        """A clean --message in a compound command is scannable, unmodified, not flagged."""
        cmd = 'git add . && git commit --message="feat: clean compound"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert not result.patterns_removed
        assert not result.was_modified

    # --- security edge cases: escaped quotes / backslashes / multiple long flags (CodeRabbit #81) ---
    # Parity with the -m edge cases in TestBashlexEdgeCases. Escaped-quote handling is imperfect
    # for both flags, so (like test_nested_escaped_quotes) these assert loosely on substrings.

    def test_long_flag_separate_escaped_quotes(self):
        """--message "with \\"quotes\\"" extracts a non-None message containing the inner text."""
        msg = self._filter().extract_commit_message(r'git commit --message "Message with \"escaped\" quotes"')
        assert msg is not None
        assert "escaped" in msg

    def test_long_flag_attached_escaped_quotes(self):
        """--message="with \\"quotes\\"" extracts a non-None message containing the inner text."""
        msg = self._filter().extract_commit_message(r'git commit --message="Message with \"escaped\" quotes"')
        assert msg is not None
        assert "escaped" in msg

    def test_long_flag_attached_backslashes(self):
        """--message="Path: C:\\\\Users\\\\test" preserves backslashes exactly (not corrupted)."""
        msg = self._filter().extract_commit_message(r'git commit --message="Path: C:\\Users\\test"')
        assert msg == r"Path: C:\\Users\\test"

    def test_multiple_long_flags_combined(self):
        """Two --message flags combine into paragraphs, like multiple -m."""
        msg = self._filter().extract_commit_message('git commit --message="first" --message="second"')
        assert msg == "first\n\nsecond"

    def test_multiple_long_flags_trailer_in_second_is_caught(self):
        """Extraction-bypass guard: a trailer in the SECOND --message is scanned/blocked, and the
        clean FIRST paragraph survives (only the trailer paragraph is removed)."""
        cmd = 'git commit --message="feat: clean" --message="Co-Authored-By: Claude <noreply@anthropic.com>"'
        result = self._filter(rules=self.CLAUDE_TRAILER_RULES).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed
        assert result.cleaned_message == "feat: clean"  # clean paragraph preserved
        assert "Co-Authored" not in result.cleaned_message  # trailer removed

    # --- documented residual (NOT a fix; pins current behavior so a future change is deliberate) ---

    def test_abbreviated_long_flag_is_known_residual_gap(self):
        """--mess (a git-valid unambiguous prefix of --message) is intentionally NOT extracted.
        Documented residual: out of scope for #77, not worth gold-plating a fail-open cosmetic
        filter. If this ever changes, it should be a deliberate decision, not an accident."""
        assert self._filter().extract_commit_message('git commit --mess "abbrev"') is None


class TestHeredocStdinExtraction:
    """Issue #87: a commit message delivered via a stdin heredoc (git commit -F- <<EOF) has its
    bytes in the command string, so it is SCANNABLE — not unscannable. A real file (-F path), a
    pipe (cat f | git commit -F-), or interactive stdin (no heredoc) stays unscannable."""

    @staticmethod
    def _filter(rules=None):
        return CommitMessageFilter({"enabled": True, "rules": rules or {}})

    @staticmethod
    def _ad_rules():
        return {
            "advertising": {
                "enabled": True,
                "patterns": [{"pattern": "Generated with Claude Code", "description": "ad", "replacement": ""}],
            }
        }

    def test_unquoted_heredoc_is_scannable(self):
        cmd = "git commit -F- <<EOF\nfeat: x\nEOF"
        assert self._filter().classify_message_delivery(cmd) == "scannable"

    def test_quoted_heredoc_is_scannable(self):
        # bashlex cannot parse <<'EOF'; the regex body-extractor must.
        cmd = "git commit -F- <<'EOF'\nfeat: x\nEOF"
        assert self._filter().classify_message_delivery(cmd) == "scannable"

    def test_unquoted_heredoc_advertising_blocked(self):
        cmd = "git commit -F- <<EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        result = self._filter(self._ad_rules()).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed

    def test_quoted_heredoc_advertising_blocked(self):
        cmd = "git commit -F- <<'EOF'\nfeat: x\n\nGenerated with Claude Code\nEOF"
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_clean_heredoc_not_flagged(self):
        cmd = "git commit -F- <<'EOF'\nfeat: totally clean\nEOF"
        result = self._filter(self._ad_rules()).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert not result.patterns_removed
        assert result.unscannable_decision is None

    def test_dash_strip_and_custom_delimiter(self):
        cmd = "git commit -F- <<-MSG\n\tfeat: x\n\tGenerated with Claude Code\n\tMSG"
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_separate_dash_form(self):
        cmd = "git commit -F - <<EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_compound_with_heredoc(self):
        cmd = "git add -A && git commit -F- <<EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_real_file_stays_unscannable(self):
        assert self._filter().classify_message_delivery("git commit -F /tmp/msg.txt") == "unscannable"

    def test_piped_stdin_stays_unscannable(self):
        # bytes live in a prior pipe segment, not a heredoc in the command
        assert self._filter().classify_message_delivery("cat /tmp/ad.txt | git commit -F-") == "unscannable"

    def test_bare_stdin_no_heredoc_unscannable(self):
        assert self._filter().classify_message_delivery("git commit -F -") == "unscannable"

    def test_inline_m_unaffected(self):
        assert self._filter().classify_message_delivery('git commit -m "feat: clean"') == "scannable"

    def test_double_quoted_delimiter(self):
        cmd = 'git commit -F- <<"EOF"\nfeat: x\n\nGenerated with Claude Code\nEOF'
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_space_before_delimiter(self):
        cmd = "git commit -F- << EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        assert self._filter(self._ad_rules()).filter_commit_message(cmd).patterns_removed

    def test_dev_stdin_target_scannable(self):
        cmd = "git commit -F /dev/stdin <<EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        result = self._filter(self._ad_rules()).filter_commit_message(cmd)
        assert result.message_delivery == "scannable"
        assert result.patterns_removed

    def test_preceding_clean_heredoc_does_not_mask_commit_ad(self):
        # Two heredocs: clean leading one + the real commit carrying an ad. Must NOT be scanned
        # as clean-scannable (that would let the ad through) — fall back to unscannable.
        cmd = "cat <<DATA\nsome clean data\nDATA\ngit commit -F- <<EOF\nfeat: x\n\nGenerated with Claude Code\nEOF"
        result = self._filter(self._ad_rules()).filter_commit_message(cmd)
        assert result.message_delivery == "unscannable"
        assert not result.patterns_removed

    def test_preceding_dirty_heredoc_does_not_block_clean_commit(self):
        # Two heredocs: a leading file heredoc that contains the token + a CLEAN commit.
        # Must NOT be blocked — fall back to unscannable.
        cmd = (
            "tee notes.txt <<NOTES\nGenerated with Claude Code\nNOTES\n"
            "git add notes.txt && git commit -F- <<MSG\ndocs: add notes\nMSG"
        )
        result = self._filter(self._ad_rules()).filter_commit_message(cmd)
        assert not result.patterns_removed
        assert result.message_delivery == "unscannable"

    def test_multiple_heredocs_stay_unscannable(self):
        # >1 heredoc: binding is ambiguous, so refuse to guess and stay unscannable (also covers
        # the O(n^2) body-regex ReDoS input shape, which is exactly many `<<` openers).
        cmd = "git commit -F- <<A\na\nA\ncat <<B\nb\nB"
        assert self._filter().classify_message_delivery(cmd) == "unscannable"


class TestPatternCaseWhitespace:
    """Issue #85: shipped advertising patterns must match case-insensitively and tolerate
    variable inter-word whitespace, while user custom_patterns keep case-sensitive semantics.
    Tests run against the REAL bundled rules (load_filter_config())."""

    @staticmethod
    def _filter():
        return CommitMessageFilter(load_filter_config())

    def _blocks(self, body):
        cmd = f'git commit -m "feat: x\\n\\n{body}"'
        return bool(self._filter().filter_commit_message(cmd).patterns_removed)

    def test_lowercase_blocked(self):
        assert self._blocks("generated with claude code")

    def test_mixed_case_blocked(self):
        assert self._blocks("GeNeRaTeD WiTh ClAuDe CoDe")

    def test_double_spaces_blocked(self):
        assert self._blocks("Generated  with  Claude  Code")

    def test_tab_separated_blocked(self):
        assert self._blocks("Generated\twith\tClaude\tCode")

    def test_canonical_still_blocked(self):
        # No-regression anchor: exact canonical trailer must still be caught.
        assert self._blocks("Generated with Claude Code")

    def test_canonical_full_trailer_still_blocked(self):
        body = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
        assert self._blocks(body)

    def test_lowercase_coauthored_blocked(self):
        assert self._blocks("co-authored-by: claude <noreply@anthropic.com>")

    def test_clean_message_not_blocked(self):
        # No false positive: a legitimate message containing the word "generated" elsewhere.
        cmd = 'git commit -m "feat: regenerated the cache index"'
        assert not self._filter().filter_commit_message(cmd).patterns_removed

    def test_custom_patterns_remain_case_sensitive(self):
        # The YAML edit must not flip user custom_patterns to case-insensitive.
        cfg = {
            "enabled": True,
            "rules": {},
            "custom_patterns": [{"pattern": "SECRET", "description": "c", "replacement": ""}],
        }
        filt = CommitMessageFilter(cfg)
        _cleaned, patterns, _ = filt.clean_message("has secret lowercase")
        assert not patterns  # lowercase 'secret' must NOT match the case-sensitive custom pattern


class TestMulticaAttribution:
    """LAB-405: strip the Multica agent co-author trailer (adspam) exactly like the
    Claude/Anthropic one, while preserving functional `Multica: LAB-xxx` annotations
    that drive PR auto-linking. Tests run against the REAL bundled rules."""

    @staticmethod
    def _filter():
        return CommitMessageFilter(load_filter_config())

    def _result(self, body):
        cmd = f'git commit -m "feat: x\\n\\n{body}"'
        return self._filter().filter_commit_message(cmd)

    def test_reference_trailer_stripped(self):
        # Exact casing/shape verified against cachekit-io/cachekit-py#218.
        result = self._result("Co-authored-by: multica-agent <github@multica.ai>")
        assert result.was_modified
        assert "multica" not in result.cleaned_message.lower()

    def test_uppercase_trailer_stripped(self):
        result = self._result("Co-Authored-By: Multica-Agent <GitHub@Multica.AI>")
        assert result.was_modified
        assert "multica" not in result.cleaned_message.lower()

    def test_whitespace_tolerant_trailer_stripped(self):
        result = self._result("co-authored-by:   multica-agent   <github@multica.ai>")
        assert result.was_modified
        assert "multica" not in result.cleaned_message.lower()

    def test_sidebar_annotation_preserved(self):
        # `· Multica: LAB-xxx` is the functional PR auto-link identifier — NEVER strip it.
        result = self._result("Closes #170 · Multica: LAB-108")
        assert not result.patterns_removed
        assert not result.was_modified

    def test_bare_sidebar_annotation_preserved(self):
        result = self._result("Multica: LAB-108")
        assert not result.patterns_removed
        assert not result.was_modified

    def test_prose_mention_not_stripped(self):
        # No over-strip: only the co-author trailer shape matches, not the word itself.
        result = self._result("Document the multica CLI and Multica workspace setup")
        assert not result.patterns_removed
        assert not result.was_modified

    def test_trailer_stripped_but_annotation_survives_in_same_message(self):
        # The two can coexist in one body: adspam goes, the sidebar identifier stays.
        body = "Closes #170 · Multica: LAB-108\\n\\nCo-authored-by: multica-agent <github@multica.ai>"
        result = self._result(body)
        assert result.was_modified
        assert "Co-authored-by" not in result.cleaned_message
        assert "Multica: LAB-108" in result.cleaned_message


class TestParseMemoization:
    """#91 — bashlex.parse must run at most once per command per filter call."""

    def _filter(self):
        # Minimal real filter: advertising category enabled so the scannable path is exercised.
        return CommitMessageFilter(
            {
                "enabled": True,
                "rules": {
                    "advertising": {
                        "enabled": True,
                        "patterns": [
                            {
                                "pattern": r"\n*Generated with .*",
                                "description": "ad",
                                "replacement": "",
                            }
                        ],
                    }
                },
            }
        )

    def test_filter_parses_once_no_heredoc(self):
        """The #91 repro: `git commit -a -a -a ...` (no message, no heredoc) parsed once."""
        import bashlex  # noqa: PLC0415

        cmd = "git commit " + " ".join(["-a"] * 50)
        filt = self._filter()
        with patch("schlock.integrations.commit_filter.bashlex.parse", wraps=bashlex.parse) as spy:
            filt.filter_commit_message(cmd)
        assert spy.call_count == 1, f"expected 1 parse, got {spy.call_count}"

    def test_scannable_message_parses_once_and_result_unchanged(self):
        """A scannable `-m` commit: parsed once AND the cleaned result matches a fresh run."""
        import bashlex  # noqa: PLC0415

        cmd = 'git commit -m "Add feature\\n\\nGenerated with Claude Code"'

        baseline = self._filter().filter_commit_message(cmd)  # fresh instance, no spy

        filt = self._filter()
        with patch("schlock.integrations.commit_filter.bashlex.parse", wraps=bashlex.parse) as spy:
            result = filt.filter_commit_message(cmd)

        assert spy.call_count == 1, f"expected 1 parse, got {spy.call_count}"
        assert result.was_modified is True
        assert result.cleaned_message == baseline.cleaned_message
        assert result.message_delivery == baseline.message_delivery == "scannable"

    def test_classify_message_delivery_parses_once(self):
        """classify_message_delivery is a public entry point; it too must parse once."""
        import bashlex  # noqa: PLC0415

        cmd = "git commit " + " ".join(["-a"] * 50)
        filt = self._filter()
        with patch("schlock.integrations.commit_filter.bashlex.parse", wraps=bashlex.parse) as spy:
            filt.classify_message_delivery(cmd)
        assert spy.call_count == 1, f"expected 1 parse, got {spy.call_count}"

    def test_parse_failure_memoized_once_and_fails_open(self):
        """A quoted-heredoc commit makes bashlex raise; the raise is cached (called once),
        and filtering still fails open (returns the original command unmodified)."""
        import bashlex  # noqa: PLC0415

        # bashlex cannot parse <<'EOF' (quoted delimiter) -> every parse attempt raises.
        cmd = "git commit -m \"$(cat <<'EOF'\nhello\nEOF\n)\""
        filt = self._filter()
        with patch("schlock.integrations.commit_filter.bashlex.parse", wraps=bashlex.parse) as spy:
            result = filt.filter_commit_message(cmd)
        assert spy.call_count == 1, f"expected 1 parse, got {spy.call_count}"
        # Fail-open: the regex fallback handles extraction; the command is not broken.
        assert result.error is None
        assert result.cleaned_command  # non-empty, command preserved/handled

    def test_repeated_identical_command_cached_across_calls(self):
        """The per-instance memo persists across calls: a repeated identical command re-parses 0 times."""
        import bashlex  # noqa: PLC0415

        cmd = "git commit " + " ".join(["-a"] * 10)
        filt = self._filter()
        filt.filter_commit_message(cmd)  # warm the cache (parses once)
        with patch("schlock.integrations.commit_filter.bashlex.parse", wraps=bashlex.parse) as spy:
            filt.filter_commit_message(cmd)  # second identical call: fully served from cache
        assert spy.call_count == 0, f"expected 0 parses on repeat, got {spy.call_count}"

    def test_parse_cache_is_bounded_by_max(self):
        """The parse cache never exceeds _PARSE_CACHE_MAX entries (bounded memory / LRU eviction)."""
        from schlock.integrations.commit_filter import _PARSE_CACHE_MAX  # noqa: PLC0415

        filt = self._filter()
        for i in range(_PARSE_CACHE_MAX + 50):
            filt._parse(f"git commit -m msg{i}")  # each distinct command is a distinct cache entry
        assert len(filt._parse_cache) == _PARSE_CACHE_MAX
