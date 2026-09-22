r"""The rm rules read every spelling of the recursive flag, and unlink is a delete.

`recursive_delete` was `\brm\s+-r`, so the recursion hid behind any flag in front
of it (`-fr`, `-f -r`, `-vfr`), behind the BSD spelling `-R` that macOS `man rm`
lists first, and behind `--recursive`. `system_destruction` and
`hidden_glob_destruction` carried the same lowercase-only literal group, so
`rm -R ~` and `rm -Rf .*` were SAFE while their `-r` twins were BLOCKED, and
`system_destruction` also required `-f`, which only silences prompts. `unlink`
had no general rule.

Every assertion is an absolute expected verdict with the rule named, never parity
with a control, and ShellCheck is forced off: SC2114/SC2115 rate most of these on
a machine that has ShellCheck installed, which is how the gap stayed hidden.
"""

import pytest

from schlock.core import validator
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import clear_caches, validate_command


@pytest.fixture(autouse=True)
def _no_shellcheck(monkeypatch):
    """Pin verdicts to the rule engine alone."""
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


def verdict(command: str, rules_path: str) -> tuple[RiskLevel, list[str]]:
    result = validate_command(command, config_path=rules_path)
    return result.risk_level, result.matched_rules


class TestRecursiveDeleteSpellings:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -R foo",
            "rm -Rf foo",
            "rm -fR foo",
            "rm -vRf foo",
            "rm --recursive foo",
            "rm --r foo",  # getopt_long accepts any unambiguous prefix
            # recursion behind another flag, lowercase included
            "rm -fr foo",
            "rm -fr /tmp/x",
            "rm -f -r foo",
            "rm -vfr foo",
            "rm -f  -r foo",
            "rm -v -f -r foo",
            # GNU rm permutes arguments: a flag after the operand still recurses
            "rm foo -r",
            "rm foo -R",
            "rm foo bar --recursive",
            # controls
            "rm -r foo",
            "rm -rf foo",
        ],
    )
    def test_every_recursive_spelling_is_high(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert (risk, "recursive_delete" in rules) == (RiskLevel.HIGH, True), (risk, rules)

    @pytest.mark.parametrize(
        "command",
        [
            "rm --force foo",  # `r` inside a long option is not the flag
            "rm --interactive=never foo",
            "rm --preserve-root foo",
            "rm -f my-r-file",  # a hyphen inside an operand is not a flag
            "rm -f foo.tar",
            "rm -f foo",
            "rm -I foo",
            "rm -d foo",
        ],
    )
    def test_a_flag_or_operand_without_recursion_is_not_recursive(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert "recursive_delete" not in rules, rules
        assert risk < RiskLevel.HIGH, (risk, rules)

    def test_a_filename_after_double_dash_takes_the_higher_rating(self, safety_rules_path):
        """`rm -- -r` deletes a file named `-r`; the regex cannot see argv, so it prompts."""
        risk, rules = verdict("rm -- -r", safety_rules_path)
        assert (risk, "recursive_delete" in rules) == (RiskLevel.HIGH, True), (risk, rules)


class TestSystemDestructionSpellings:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -R /",
            "rm -Rf /",
            "rm --recursive /",
            "rm -R /*",
            "rm -R $HOME",
            "rm -R ~",
            "rm --recursive ~",
            "rm -Rf ~",
            # -r with no -f on a system target
            "rm -r /",
            "rm -r ~",
            "rm -r $HOME",
            # the target with a trailing slash or a contents glob
            "rm -rf ~/",
            "rm -rf $HOME/",
            "rm -rf ~/*",
            "rm -rf $HOME/*",
            # target first
            "rm / -R",
            "rm ~ --recursive",
            "rm /* -Rf",
            # controls
            "rm -rf /",
            "rm -fr $HOME",
            "rm / -rf",
        ],
    )
    def test_every_recursive_spelling_on_a_system_target_is_blocked(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert (risk, "system_destruction" in rules) == (RiskLevel.BLOCKED, True), (risk, rules)

    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf ~/.cache",
            "rm -rf $HOME/.cache",
            "rm -rf ~/*.log",
            "rm -rf ~user",
            "rm -rf /tmp/test",
            "rm -rf ./node_modules",
            "rm --force /",  # not recursive: a directory is not removed
            "rm -f ~",
        ],
    )
    def test_a_specific_or_non_recursive_target_is_not_blocked(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert "system_destruction" not in rules, rules
        assert risk < RiskLevel.BLOCKED, (risk, rules)


class TestHiddenGlobSpellings:
    @pytest.mark.parametrize(
        "command",
        [
            "rm -Rf .*",
            "rm -R .*",
            "rm -fR foo .*",
            "rm -vRf foo .*",
            "rm --recursive .*",
            "rm .* foo -R",
            "rm -r foo .*",  # -f was required before
            # controls
            "rm -rf .*",
            "rm .*",
        ],
    )
    def test_every_recursive_spelling_with_a_dot_star_glob_is_blocked(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert (risk, "hidden_glob_destruction" in rules) == (RiskLevel.BLOCKED, True), (risk, rules)


class TestUnlink:
    @pytest.mark.parametrize(
        "command",
        ["unlink x", "unlink -- -file", "/usr/bin/unlink x", "env unlink x", "unlink ' -f'"],
    )
    def test_unlink_is_a_delete(self, safety_rules_path, command):
        assert verdict(command, safety_rules_path) == (RiskLevel.MEDIUM, ["unlink_delete"])

    def test_bare_unlink_deletes_nothing(self, safety_rules_path):
        risk, rules = verdict("unlink", safety_rules_path)
        assert (risk, rules) == (RiskLevel.SAFE, [])

    @pytest.mark.parametrize(
        "command",
        ["unlink .claude/hooks/schlock-config.yaml", "unlink ~/.config/schlock/config.yaml"],
    )
    def test_self_protection_still_wins_over_the_general_rule(self, safety_rules_path, command):
        assert verdict(command, safety_rules_path)[0] == RiskLevel.BLOCKED

        # and at the rule layer alone, where both rules match the same text
        match = RuleEngine(safety_rules_path).match_command(command)
        assert (match.risk_level, match.rule.name if match.rule else None) == (RiskLevel.BLOCKED, "schlock_config_delete")


class TestRegexLayer:
    """Each site reads the fragment on its own; a verdict alone cannot tell them apart."""

    @pytest.mark.parametrize(
        ("rule", "text"),
        [
            ("recursive_delete", "rm -R x"),
            ("recursive_delete", "rm --recursive x"),
            ("recursive_delete", "rm -fr x"),
            ("recursive_delete", "rm x -r"),
            ("system_destruction", "rm -R /"),
            ("system_destruction", "rm -r ~/"),
            ("system_destruction", "rm ~ -R"),
            ("hidden_glob_destruction", "rm -Rf .*"),
            ("hidden_glob_destruction", "rm -R foo .*"),
            ("hidden_glob_destruction", "rm .* foo -R"),
            ("unlink_delete", "unlink x"),
        ],
    )
    def test_pattern_matches(self, safety_rules_path, rule, text):
        engine = RuleEngine(safety_rules_path)
        assert any(p.search(text) for p in engine.compiled_patterns[rule]), f"{rule} missed {text!r}"

    @pytest.mark.parametrize(
        ("rule", "text"),
        [
            ("recursive_delete", "rm --force x"),
            ("recursive_delete", "rm my-r-file"),
            ("recursive_delete", "rm x; foo -r"),  # the span stops at a separator
            ("recursive_delete", "rm x\n-r y"),  # and at a newline
            ("system_destruction", "rm -R ~/.cache"),
            ("system_destruction", "rm --force /"),
            ("hidden_glob_destruction", "rm --force .* x"),
            ("unlink_delete", "unlink"),
        ],
    )
    def test_pattern_does_not_match(self, safety_rules_path, rule, text):
        engine = RuleEngine(safety_rules_path)
        hit = [p.pattern for p in engine.compiled_patterns[rule] if p.search(text)]
        assert not hit, f"{rule} matched {text!r}: {hit}"
