r"""A truncating redirect needs no blank beside its operator.

bash parses `true >f`, `true>f` and `true 2>f` exactly as `true > f` and `true 2> f`:
each opens `f` for writing and empties it. The `file_truncation` patterns required a
blank after the operator, so every glued spelling rated SAFE while its spaced twin
rated HIGH. Values are pinned absolutely as (risk_level, matched_rules). ShellCheck is
off: it reads the raw command and has no say in this rule.
"""

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_caches()
    yield
    clear_caches()


def _verdict(command, rules):
    result = validate_command(command, config_path=rules, _shellcheck=False)
    return result.risk_level, result.matched_rules


TRUNCATION = (RiskLevel.HIGH, ["file_truncation"])
SAFE = (RiskLevel.SAFE, [])


@pytest.mark.parametrize(
    "command",
    [
        "true >f",
        "true>f",
        "true >|f",
        '"true" >f',
        ": >f",
        ":>f",
        ">f",
        "echo -n >f",
        "echo -n>f",
        "printf '' >f",
        "printf ''>f",
        "true >f 2>&1",
    ],
)
def test_glued_truncation_is_a_truncation(command, safety_rules_path):
    assert _verdict(command, safety_rules_path) == TRUNCATION


@pytest.mark.parametrize(
    "command",
    [
        "true 2>f",
        "true 1>f",
        "true 3>f",
        "true {fd}>f",
        "true &>f",
        "true 2>|f",
        ": 2>f",
        "echo -n 2>f",
        "true 2>~/.aws/credentials",
        # A leading `{fd}>out` opens `out` for writing before the command runs.
        "{fd}>out chmod 777 ./x",
    ],
)
def test_glued_descriptor_truncation_is_a_truncation(command, safety_rules_path):
    assert _verdict(command, safety_rules_path) == TRUNCATION


@pytest.mark.parametrize(
    "command",
    [
        # The null device, glued or spaced.
        "true >/dev/null",
        "true > /dev/null",
        ":>/dev/null",
        ": > /dev/null",
        ">/dev/null",
        "> /dev/null",
        "true 2>/dev/null",
        "true >  /dev/null",
        "true 2>  /dev/null",
        # Appending is not truncating: the glued target must not be the second `>`.
        "true >>f",
        ":>>f",
        "true 2>>f",
        "true >>/dev/null",
        # Duplicating or closing a descriptor opens no file.
        "true 2>&1",
        "true >&2",
        "true >&-",
        "true 2>&-",
        # A process substitution is a pipe, not a file.
        "true >(cat)",
        ": >(cat)",
        # `30` and `00` belong to the argument; `:` there is not the null command.
        "echo 10:30>out.txt",
        "echo 12:00>log",
        # Quoted examples are data.
        "echo ':>f'",
        "echo 'true >f'",
    ],
)
def test_glued_non_truncation_stays_safe(command, safety_rules_path):
    assert _verdict(command, safety_rules_path) == SAFE


def test_glued_example_in_a_commit_message_is_data(safety_rules_path):
    assert _verdict("git commit -m 'true >f'", safety_rules_path) == (RiskLevel.LOW, ["git_commit"])


@pytest.mark.parametrize(
    "command",
    [
        # A quoted target that starts with a blank and a metacharacter is still a target.
        "\"true\" > ' ;' important.db",
        '"true" > "\\n;" important.db',
        # Glued to a quoted producer, a quoted blank-led target is visible only in the raw text.
        "\"true\">' /dev/null' important.db",
        "'true'>' /dev/null' important.db",
        "'echo' -n>' /dev/null' important.db",
    ],
)
def test_quoted_blank_led_target_stays_a_truncation(command, safety_rules_path):
    assert _verdict(command, safety_rules_path) == TRUNCATION
