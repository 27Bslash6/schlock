r"""`base64_shell_execution`'s here-string pattern, bounded so it cannot be stalled.

Written `(bash|sh|zsh).*<<<.*\$\(base64\s+(-d|--decode)`, the two unbounded runs
made a match attempt scale with the PRODUCT of shell-name density and `<<<`
density: a command just under the size limit took ~300s to scan, on a matcher
that runs before every bash call. Bounding both runs to `.{0,200}` matches the
same strings and costs milliseconds.

The scaling pin sweeps every compiled pattern in the ruleset rather than this one,
because a revert can land anywhere, and it runs at the regex layer because
validating a 64KB command also pays a pre-existing linear parse cost of ~1.9s that
would swamp the signal. Four shapes, because the cost has two axes and a shape
that is dense in only one of them measures nothing: `sh `-dense finds a pattern
that rescans on every start, `<<<`-dense finds one that rescans per anchor, and
only the interleaved shape stresses both at once.

Split out of tests/test_redos_protection.py to avoid colliding with three open PRs
editing that file; fold it back in once they land.
"""

import time

import pytest

from schlock.core import validator as validator_module
from schlock.core.rules import RuleEngine
from schlock.core.validator import RiskLevel, validate_command

_BUDGET = 64 * 1024  # MAX_COMMAND_SIZE; every shape below sits just under it

SHAPES = {
    # Dense shell names, no `<<<` at all: each start scans its whole run and fails.
    "name_dense": "sh " * (_BUDGET // 3),
    # Dense `<<<`, one shell name: each anchor gets its own scan of the tail.
    "anchor_dense": "bash " + "<<<a" * ((_BUDGET - 5) // 4),
    # Both axes dense. This is the shape the other two cannot see, and the only
    # one that reproduces the product term the unbounded form was paying.
    "interleaved": "sh <<<a" * (_BUDGET // 7),
    # The reported shape: one `<<<` per segment, 4375 segments.
    "segmented": "".join(f"bash <<< a{i};" for i in range(4375)),
}
# None of them contain `base64`, so `search()` never exits early - they measure
# the full failed attempt, which is the case an attacker gets to choose.


class TestHereStringBase64StaysBlocked:
    """Bounding the runs must not narrow what they match."""

    @pytest.fixture(autouse=True)
    def _no_shellcheck(self, monkeypatch):
        """ShellCheck is optional, so it must not be what produces these verdicts."""
        monkeypatch.setattr(validator_module, "is_shellcheck_available", lambda: False)

    @pytest.mark.parametrize(
        "command",
        [
            'bash <<< "$(base64 -d x)"',
            'zsh <<< "$(base64 --decode x)"',
            # A here-string's content is SHELL TEXT: `;`, `&&` and `|` inside it are
            # payload, not structure. Bounding the runs with a separator class reads
            # these as three commands and stops at the first separator.
            'bash <<< "set -e; $(base64 -d x)"',
            'bash <<< "cd /tmp && $(base64 -d x)"',
            'bash <<< "true | $(base64 -d x)"',
            # Redirections between the shell word and the here-string. `&` here is
            # part of `&>` and `2>&1`, not a control operator.
            'bash &>/dev/null <<< "$(base64 -d x)"',
            'bash >/dev/null 2>&1 <<< "$(base64 -d x)"',
            'bash 2</dev/null <<< "$(base64 -d x)"',
            # A separator inside a quoted flag value is data too.
            "bash --rcfile 'a;b' <<< \"$(base64 -d x)\"",
        ],
    )
    def test_decode_onto_a_shells_stdin_is_blocked(self, command, safety_rules_path):
        result = validate_command(command, config_path=safety_rules_path)

        assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
        assert "base64_shell_execution" in result.matched_rules, result.matched_rules


@pytest.mark.parametrize("shape", list(SHAPES.values()), ids=list(SHAPES))
def test_no_rule_pattern_is_superlinear_in_here_string_density(shape, safety_rules_path):
    """Every compiled pattern against a 64KB adversarial command, under one second.

    Measured at ~0.3s for the whole ruleset on the worst of these shapes. The
    unbounded form cost ~300s on `segmented` alone, so this fails by three orders
    of magnitude on a revert rather than by a hair on a slow runner.
    """
    engine = RuleEngine(safety_rules_path)

    start = time.perf_counter()
    for patterns in engine.compiled_patterns.values():
        for pattern in patterns:
            pattern.search(shape)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"rule patterns took {elapsed:.3f}s on {len(shape)} bytes"
