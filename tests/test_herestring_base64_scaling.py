r"""Pins for `base64_shell_execution`'s here-string pattern (data/rules/05_code_execution.yaml).

The YAML note carries the WHY. This module pins its claims: the pattern is linear in
command size, it matches exactly the strings the cubic `.*` form matched (checked
exhaustively, span included, because string-literal suppression reads the span), and
no padding under the size limit clears it.

One verdict moves, and deliberately. The match now starts at the shell name nearest
the `<<<`; the `.*` form started at the FIRST shell-name substring on the line and
let its span leak into any quoted string after it. So `ssh host 'sh <<< "$(base64 -d
x)"'` was BLOCKED on main only because `ssh` contains `sh`, while `ssh host 'rm -rf
/'` and `ssh host 'bash <<< "rm -rf /"'` were SAFE. The same leak caught a payload
quoted behind a local launcher outside the wrapper set (`uv run sh -c '...'`); that is
SAFE now too, and closing it belongs in the re-entry machinery, not this regex - see
the YAML note and LAB-4699.

Timing sweeps every compiled pattern in the ruleset, because a revert can land
anywhere, and runs at the regex layer because validating a 64KB command also pays a
pre-existing linear parse cost of ~1s that would swamp the signal. Each shape fails a
distinct wrong-stop variant: name-dense alone catches a first run that stops at `<<<`;
anchor-dense alone catches a second run that stops at a shell name; interleaved
catches both `.*` reverts; segmented is the ticket's reported command.
"""

import itertools
import re
import time

import pytest

from schlock.core import validator as validator_module
from schlock.core.rules import RuleEngine
from schlock.core.validator import RiskLevel, validate_command
from schlock.integrations.commit_filter import MAX_COMMAND_SIZE

# The form the pattern replaces. The reference for "matches the same strings".
_UNBOUNDED = re.compile(r"(bash|sh|zsh).*<<<.*\$\(base64\s+(-d|--decode)", re.MULTILINE)

SHAPES = {
    "name_dense": "sh " * (MAX_COMMAND_SIZE // 3),
    "anchor_dense": "bash " + "<<<a" * ((MAX_COMMAND_SIZE - 5) // 4),
    "interleaved": "sh <<<a" * (MAX_COMMAND_SIZE // 7),
    "segmented": "".join(f"bash <<< a{i};" for i in range(4375)),
}
# None of them contain `base64`, so `search()` never exits early - they measure
# the full failed attempt, which is the case an attacker gets to choose.


@pytest.fixture(autouse=True)
def no_shellcheck(monkeypatch):
    """ShellCheck is optional, so it must not be what produces these verdicts."""
    monkeypatch.setattr(validator_module, "is_shellcheck_available", lambda: False)


def _here_string_pattern(rules_path):
    (pattern,) = [p for p in RuleEngine(rules_path).compiled_patterns["base64_shell_execution"] if "<<<" in p.pattern]
    return pattern


@pytest.mark.parametrize(
    "command",
    [
        'bash <<< "$(base64 -d x)"',
        'zsh <<< "$(base64 --decode x)"',
        # A here-string's content is SHELL TEXT: `;`, `&&` and `|` inside it are
        # payload, not structure. A separator class after `<<<` stops at the first.
        'bash <<< "set -e; cd /tmp && true | $(base64 -d x)"',
        # Redirections between the shell word and the here-string. `&` here is part
        # of `&>` and `2>&1`, not a control operator; `<` is not a `<<<`.
        'bash &>/dev/null 2>&1 <<< "$(base64 -d x)"',
        'bash 2</dev/null <<< "$(base64 -d x)"',
        # A separator inside a quoted flag value is data too.
        "bash --rcfile 'a;b' <<< \"$(base64 -d x)\"",
        # Neutral padding one past the old `.{0,200}` bound, on either side of `<<<`.
        # Spaces before the redirect are lexical whitespace; spaces inside the quoted
        # here-string prefix stdin while the substitution still runs.
        "bash " + " " * 201 + '<<< "$(base64 -d x)"',
        'bash <<< "' + " " * 201 + '$(base64 -d x)"',
        # A shell name and a further `<<<` between the shell and the decode: the
        # deterministic runs stop at those tokens and must still find the match.
        'bash <<< "sh $(base64 -d x)"',
        "bash <<< a <<< $(base64 -d x)",
    ],
)
def test_decode_onto_a_shells_stdin_is_blocked(command, safety_rules_path):
    result = validate_command(command, config_path=safety_rules_path)

    assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
    assert "base64_shell_execution" in result.matched_rules, result.matched_rules


@pytest.mark.parametrize(
    "command",
    [
        # Text: the whole span sits inside one quoted string, so suppression holds.
        "echo 'bash <<< \"$(base64 -d x)\"'",
        # Remote delegation, deliberately uncovered. BLOCKED on main by the `.*` span
        # leaking from the `sh` in `ssh`; every other quoted ssh payload was SAFE.
        "ssh host 'sh <<< \"$(base64 -d x)\"'",
    ],
)
def test_quoted_here_string_text_is_judged_by_the_quote(command, safety_rules_path):
    result = validate_command(command, config_path=safety_rules_path)

    assert result.risk_level == RiskLevel.SAFE, f"{command!r} -> {result.risk_level.name}"
    assert result.matched_rules == [], result.matched_rules


@pytest.mark.parametrize(
    "command",
    [
        "bash " + " " * (MAX_COMMAND_SIZE - 40) + '<<< "$(base64 -d x)"',
        'bash <<< "' + " " * (MAX_COMMAND_SIZE - 40) + '$(base64 -d x)"',
    ],
    ids=["before_redirect", "inside_here_string"],
)
def test_padding_up_to_the_size_limit_still_matches(command, safety_rules_path):
    """No single-line padding under MAX_COMMAND_SIZE clears the pattern. Asserted at the
    regex layer: the end-to-end parse of 64KB costs ~1s and proves nothing extra here."""
    assert _here_string_pattern(safety_rules_path).search(command)


def test_matches_exactly_what_the_unbounded_form_matched(safety_rules_path):
    """Truthiness AND span, exhaustively over every string of up to five tokens.

    The alphabet is what the pattern can react to: the three shell names, the
    redirect and a lone `<`, a decode in both spellings and a base64 call that is
    not a decode, filler, and a newline (`.` stops at one, `\\s+` does not). Quotes,
    blanks and separators are filler to the regex and are covered by `x`.

    Span containment is checked in one direction: wherever the old span sat wholly
    inside a quote the new one does too, so the deterministic form can never turn a
    suppressed match into a block. It says nothing about the reverse; that is the
    moved `ssh` verdict pinned end-to-end above.
    """
    live = _here_string_pattern(safety_rules_path)
    tokens = ["bash", "sh", "zsh", "<<<", "<", "$(base64 -d", "$(base64 --decode", "$(base64 x", "x", "\n"]

    for length in range(1, 6):
        for combo in itertools.product(tokens, repeat=length):
            text = "".join(combo)
            old, new = _UNBOUNDED.search(text), live.search(text)
            if old is None or new is None:
                assert old is new, f"{text!r}: unbounded={old} live={new}"
                continue
            assert old.start() <= new.start() and new.end() <= old.end(), f"{text!r}: {old.span()} vs {new.span()}"


@pytest.mark.parametrize("shape", list(SHAPES.values()), ids=list(SHAPES))
def test_every_rule_pattern_finishes_64kb_under_a_second(shape, safety_rules_path):
    """Every compiled pattern against a 64KB adversarial command, one second total.

    Measured at ~0.15s for the whole ruleset on the worst of these shapes, of which
    this rule is ~10ms. The unbounded form cost ~300s on `segmented` alone, so this
    fails by three orders of magnitude on a revert rather than by a hair on a slow
    runner. The assertion names the slowest rule so a red run does not mean bisecting
    every pattern by hand.
    """
    engine = RuleEngine(safety_rules_path)

    timings = {}
    for rule, patterns in engine.compiled_patterns.items():
        start = time.perf_counter()
        for pattern in patterns:
            pattern.search(shape)
        timings[rule] = time.perf_counter() - start
    total = sum(timings.values())
    slowest = max(timings, key=timings.__getitem__)

    assert total < 1.0, f"{total:.3f}s on {len(shape)} bytes; slowest rule {slowest} at {timings[slowest]:.3f}s"
