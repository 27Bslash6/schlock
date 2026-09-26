"""The uncommitted-changes probe fires on the command bash runs, not on one spelling of it (LAB-5493).

The probe decided whether to run with a raw substring test, so any git global option between
`git` and `reset` (`-C .`, `--no-pager`, `-c k=v`, ...) skipped it and a dirty-tree hard reset fell
from BLOCKED to the rule pass's HIGH, which the permissive preset allows. The trigger now also keys
on the `git_hard_reset` rule match, which already skips those options, so the class is closed
without a list of options.

Tree state is set explicitly by a spy on `subprocess.run` that answers `git status --porcelain`
and counts the calls; nothing is inherited from the checkout the suite runs in. Every verdict is
pinned absolutely, never "same as the control".
"""

from unittest.mock import MagicMock, patch

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command

UNCOMMITTED = "BLOCKED: Uncommitted changes detected! git reset --hard will destroy them."

# The ticket's table: rows 2-11 missed the probe on main.
ROWS = [
    "git reset --hard HEAD~1",
    "git -C . reset --hard HEAD~1",
    "git  reset --hard HEAD~1",
    '"git" reset --hard HEAD~1',
    "git {fd}>out reset --hard HEAD~1",
    "git -c core.x=y reset --hard HEAD~1",
    "git --work-tree=. reset --hard HEAD~1",
    "git --git-dir=.git/ reset --hard HEAD~1",
    "git --work-tree . reset --hard HEAD~1",
    "git --no-pager reset --hard HEAD~1",
    "git -P reset --hard HEAD~1",
]

# AC-8: options named nowhere else, so a fix that lists options instead of keying on the rule fails.
UNLISTED_OPTIONS = [
    "git --paginate reset --hard HEAD~1",
    "git --exec-path=/usr/lib/git-core reset --hard HEAD~1",
    "git --no-replace-objects reset --hard HEAD~1",
    "git --config-env=core.x=HOME reset --hard HEAD~1",
]

# Caught on main; must stay caught.
CONTROLS = [
    "command git reset --hard HEAD~1",
    "echo hi; git reset --hard HEAD~1",
    'git reset "--hard" HEAD~1',
    "git --git-dir=.git reset --hard HEAD~1",
]

# The `git_hard_reset` rule requires `reset\s+--hard`, so only the substring leg sees these.
SUBSTRING_ONLY = [
    "git reset -q --hard HEAD~1",
    "git reset HEAD~1 --hard",
]

NOT_A_HARD_RESET = [
    "git reset --soft HEAD~1",
    'git log --grep "reset --hard"',
    "ls -la",
]


@pytest.fixture(autouse=True)
def _no_shellcheck():
    clear_caches()
    with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
        yield
    clear_caches()


class _Tree:
    """Answers `git status --porcelain` as a dirty or clean tree and counts the calls."""

    def __init__(self, dirty: bool):
        self.stdout = "?? untracked.txt\n" if dirty else ""
        self.status_calls = 0

    def __call__(self, argv, *args, **kwargs):
        assert argv[:2] == ["git", "status"], f"unexpected subprocess: {argv!r}"
        self.status_calls += 1
        return MagicMock(returncode=0, stdout=self.stdout)


def _validate(command, rules, *, dirty):
    tree = _Tree(dirty)
    clear_caches()
    with patch("subprocess.run", side_effect=tree):
        result = validate_command(command, config_path=rules)
    return result, tree.status_calls


@pytest.mark.parametrize("command", ROWS + UNLISTED_OPTIONS + CONTROLS)
class TestRuleMatchedHardReset:
    """AC-1, AC-2, AC-3, AC-8: every spelling the rule matches gets the probe, exactly once."""

    def test_dirty_tree_is_blocked(self, command, safety_rules_path):
        result, calls = _validate(command, safety_rules_path, dirty=True)
        assert (result.risk_level, result.allowed, result.message) == (RiskLevel.BLOCKED, False, UNCOMMITTED)
        assert calls == 1

    def test_clean_tree_is_the_rule_verdict(self, command, safety_rules_path):
        result, calls = _validate(command, safety_rules_path, dirty=False)
        assert result.risk_level == RiskLevel.HIGH
        assert "git_hard_reset" in result.matched_rules
        assert calls == 1


@pytest.mark.parametrize("command", SUBSTRING_ONLY)
class TestSubstringOnlyHardReset:
    """AC-2, AC-3: the substring leg stays; the rule does not see these."""

    def test_dirty_tree_is_blocked(self, command, safety_rules_path):
        result, calls = _validate(command, safety_rules_path, dirty=True)
        assert (result.risk_level, result.message) == (RiskLevel.BLOCKED, UNCOMMITTED)
        assert calls == 1

    def test_clean_tree_is_safe(self, command, safety_rules_path):
        result, calls = _validate(command, safety_rules_path, dirty=False)
        assert result.risk_level == RiskLevel.SAFE
        assert calls == 1


@pytest.mark.parametrize("dirty", [True, False], ids=["dirty", "clean"])
@pytest.mark.parametrize("command", NOT_A_HARD_RESET)
def test_no_probe_without_a_hard_reset(command, dirty, safety_rules_path):
    """AC-2, AC-3: these never pay for `git status`."""
    result, calls = _validate(command, safety_rules_path, dirty=dirty)
    assert result.risk_level == RiskLevel.SAFE
    assert calls == 0


def test_cached_clean_verdict_does_not_answer_for_a_dirty_tree(safety_rules_path):
    """The probe runs after the cache lookup: a HIGH cached while clean must not outlive the tree state."""
    command = "git -C . reset --hard HEAD~1"
    clear_caches()
    with patch("subprocess.run", side_effect=_Tree(dirty=False)):
        assert validate_command(command, config_path=safety_rules_path).risk_level == RiskLevel.HIGH
    dirty = _Tree(dirty=True)
    with patch("subprocess.run", side_effect=dirty):
        result = validate_command(command, config_path=safety_rules_path)
    assert (result.risk_level, result.message, dirty.status_calls) == (RiskLevel.BLOCKED, UNCOMMITTED, 1)
    # The denial itself is not cached: a later clean tree gets the rule verdict back.
    with patch("subprocess.run", side_effect=_Tree(dirty=False)):
        assert validate_command(command, config_path=safety_rules_path).risk_level == RiskLevel.HIGH
