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

    def test_fails_open_on_extraction_failure(self):
        """Returns original command when extraction fails."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})

        cmd = "git commit --amend"  # No -m flag
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd
        assert result.error is not None

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

    def test_handles_extraction_failure_gracefully(self):
        """Handles extraction failure without breaking."""
        filter_instance = CommitMessageFilter({"enabled": True, "rules": {}})

        # Command with no extractable message
        cmd = "git commit --amend"
        result = filter_instance.filter_commit_message(cmd)

        assert not result.was_modified
        assert result.cleaned_command == cmd  # Original
        assert result.error is not None  # Error logged

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
