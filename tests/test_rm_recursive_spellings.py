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
The flag word is spelt several ways on purpose (`$'-rf'`, `{-rf,}`): bash hands rm
the bare `-rf` from each, and a lookbehind that demanded a blank before the dash
let them through.
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
            "rm -IR foo",  # -I (prompt once) is uppercase too
            "rm --recursive foo",
            "rm --r foo",  # getopt_long accepts any unambiguous prefix
            # recursion behind another flag, lowercase included
            "rm -fr foo",
            "rm -fr /tmp/x",
            "rm -f -r foo",
            "rm -vfr foo",
            "rm -f  -r foo",
            "rm -v -f -r foo",
            # the flag word quoted or brace-expanded: bash hands rm a bare -rf
            "rm $'-rf' foo",
            "rm {-rf,} foo",
            # GNU rm permutes arguments: a flag after the operand still recurses
            "rm foo -r",
            "rm foo -R",
            "rm foo bar --recursive",
            "rm " + "a" * 250 + " -r",  # within the 300-char span
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
            "rm -vfr /",  # two letters before the r
            # -r with no -f on a system target
            "rm -r /",
            "rm -r ~",
            "rm -r $HOME",
            # the target spelt with a trailing slash, a contents glob, or braces
            "rm -rf ~/",
            "rm -rf $HOME/",
            "rm -rf ~/*",
            "rm -rf $HOME/*",
            "rm -rf ${HOME}",
            'rm -rf "${HOME}"',
            "rm -R ${HOME}/",
            "rm -rf /*/",
            # the flag word quoted or brace-expanded
            "rm $'-rf' ~",
            "rm {-rf,} ~",
            "rm / $'-rf'",
            # target first, and target behind other options (GNU rm permutes)
            "rm / -R",
            "rm ~ --recursive",
            "rm /* -Rf",
            "rm / -vfr",
            "rm -f ~ -r",
            "rm -v / -rf",
            "rm -i $HOME -R",
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
            "rm -rf ${HOME}/.cache",
            "rm -rf ~/*.log",
            "rm -rf ~user",
            "rm -rf /tmp/test",
            "rm -rf /*/x",
            "rm -rf ./node_modules",
            "rm -v a/ -rf",  # `/` inside an operand is not the root
            "rm --force /",  # not recursive: a directory is not removed
            "rm / --force",
            "rm -f ~",
            "rm -rf build\ncd ~",  # two commands; the span stops at the newline
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
            "rm -vfr .*",
            "rm --recursive .*",
            "rm $'-rf' .*",
            "rm .* foo -R",
            "rm .* -vfr",
            "rm .* --recursive",
            "rm -r foo .*",  # -f was required before
            # controls
            "rm -rf .*",
            "rm .*",
        ],
    )
    def test_every_recursive_spelling_with_a_dot_star_glob_is_blocked(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert (risk, "hidden_glob_destruction" in rules) == (RiskLevel.BLOCKED, True), (risk, rules)

    @pytest.mark.parametrize("command", ["rm --force .* x", "rm .* --force"])
    def test_a_long_option_with_r_inside_is_not_the_flag(self, safety_rules_path, command):
        risk, rules = verdict(command, safety_rules_path)
        assert "hidden_glob_destruction" not in rules, rules
        assert risk < RiskLevel.BLOCKED, (risk, rules)


class TestUnlink:
    @pytest.mark.parametrize(
        "command",
        ["unlink x", "unlink -- -file", "/usr/bin/unlink x", "env unlink x", "unlink ' -f'"],
    )
    def test_unlink_is_a_delete(self, safety_rules_path, command):
        assert verdict(command, safety_rules_path) == (RiskLevel.MEDIUM, ["unlink_delete"])

    @pytest.mark.parametrize("command", ["unlink", "unlink "])
    def test_bare_unlink_deletes_nothing(self, safety_rules_path, command):
        assert verdict(command, safety_rules_path) == (RiskLevel.SAFE, [])

    @pytest.mark.parametrize(
        "command",
        ["unlink .claude/hooks/schlock-config.yaml", "unlink ~/.config/schlock/config.yaml"],
    )
    def test_self_protection_still_wins_over_the_general_rule(self, safety_rules_path, command):
        # The validator's hardcoded self-protection check answers first ...
        assert verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, ["self_protection:config_write"])

        # ... and at the rule layer alone, where both YAML rules match the same text, the BLOCKED one wins.
        match = RuleEngine(safety_rules_path).match_command(command)
        assert (match.risk_level, match.rule.name if match.rule else None) == (RiskLevel.BLOCKED, "schlock_config_delete")


class TestSeparatorClass:
    """The recursive_delete span stops at `;` and at a newline.

    Regex layer only: the validator splits segments on both before any rule runs,
    so a verdict cannot tell a span that crossed the separator from one that did not.
    """

    @pytest.mark.parametrize("text", ["rm x; foo -r", "rm x\n-r y"])
    def test_span_does_not_cross_a_separator(self, safety_rules_path, text):
        engine = RuleEngine(safety_rules_path)
        hit = [p.pattern for p in engine.compiled_patterns["recursive_delete"] if p.search(text)]
        assert not hit, f"recursive_delete crossed the separator in {text!r}: {hit}"
