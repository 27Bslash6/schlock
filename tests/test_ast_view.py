"""Tests for the AstView typed-JSON adapter (LAB-409 T2b).

Scope is the mapping layer only: typed-JSON from `schlock-parse` (T2a's
`NativeBridge`) into duck-typed nodes both walker families can read. The
contract under test (spec §1, §3.2):

- the mvdan→bashlex mapping table is DATA and covers all 12 bashlex kinds;
- any typed-JSON node type, WordPart, or numeric op without an explicit
  mapping RAISES (→ fallback tier) — silent skips are a silent under-block;
- the parsed byte-span must cover the full input (a prefix parse that drops a
  trailing `; rm -rf /` is a failure, not a success).

Walker-output parity across the corpus is T2c; unescape/offsets are T3.
"""

import json

import pytest

from schlock.core.ast_view import (
    _CLAUSE_CHILDREN,
    BASHLEX_KINDS,
    BINARY_OPS,
    EXPR_OPERANDS,
    MVDAN_NODE_MAP,
    AstView,
    UnmappedNodeError,
    build_ast_view,
)
from schlock.core.native_bridge import NativeBridge, NativeBridgeError, resolve_binary
from schlock.core.parser import BashCommandParser
from schlock.core.substitution import SubstitutionType, SubstitutionValidator


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


def view(command: str) -> "list[AstView]":
    """Parse `command` through the live binary and map it to AstView nodes."""
    return NativeBridge().parse(command)


class TestMappingTableIsData:
    """The mvdan→bashlex mapping is an explicit table, not scattered ifs."""

    def test_all_twelve_kinds_covered(self):
        produced = {kind for kind, _child in MVDAN_NODE_MAP.values()}
        for _op_text, container, separator in BINARY_OPS.values():
            produced.add(container)
            produced.add(separator)
        assert produced == BASHLEX_KINDS
        assert len(BASHLEX_KINDS) == 12

    def test_clause_handlers_agree_with_the_node_map(self):
        # The two tables hold the same contract from opposite ends, and drift
        # produces a MISLEADING error: a key only in _CLAUSE_CHILDREN raises
        # "malformed typed-JSON structure: KeyError" and blames the binary for a
        # table bug. Pin them together (LAB-912 panel finding).
        for node_type in _CLAUSE_CHILDREN:
            assert MVDAN_NODE_MAP[node_type] == ("compound", "list"), node_type

    def test_expression_operand_table_has_no_empty_rows(self):
        # An empty tuple would make _expr_words return [] instead of raising —
        # the silent-drop the fail-closed contract forbids. `Word` is the leaf and
        # is handled before the lookup, so it must not appear here.
        assert "Word" not in EXPR_OPERANDS
        assert all(EXPR_OPERANDS.values())

    def test_pipe_is_not_pipeline(self):
        # `|`/`|&` build a `pipeline` whose separator kind is `pipe`;
        # `&&`/`||` build a `list` whose separator kind is `operator`.
        assert BINARY_OPS[13] == ("|", "pipeline", "pipe")
        assert BINARY_OPS[14] == ("|&", "pipeline", "pipe")
        assert BINARY_OPS[11] == ("&&", "list", "operator")
        assert BINARY_OPS[12] == ("||", "list", "operator")


@needs_binary
class TestSimpleCommand:
    def test_words_and_positions(self):
        nodes = view("echo hello")
        assert len(nodes) == 1
        cmd = nodes[0]
        assert cmd.kind == "command"
        assert cmd.pos == (0, 10)
        assert [p.kind for p in cmd.parts] == ["word", "word"]
        assert [p.word for p in cmd.parts] == ["echo", "hello"]
        assert cmd.parts[1].pos == (5, 10)

    def test_command_node_has_no_word_attr(self):
        # Walkers dispatch on hasattr(node, "word") — a command node must not
        # leak one, or extract_commands would misread the tree.
        (cmd,) = view("echo hello")
        assert not hasattr(cmd, "word")
        assert not hasattr(cmd, "list")

    def test_assignment_and_redirect_prefix_in_source_order(self):
        (cmd,) = view("X=1 cmd 2>&1")
        kinds = [p.kind for p in cmd.parts]
        assert kinds == ["assignment", "word", "redirect"]
        assign = cmd.parts[0]
        assert assign.word == "X=1"
        assert assign.pos == (0, 3)
        redirect = cmd.parts[2]
        assert redirect.type == ">&"
        assert redirect.input == 2
        assert redirect.output == 1  # fd target is an int, like bashlex

    def test_append_assignment(self):
        (cmd,) = view("X+=1 cmd")
        assert cmd.parts[0].word == "X+=1"


@needs_binary
class TestAcceptanceCommandSubstitution:
    """The ticket's acceptance case: echo $(a && b)."""

    def test_inner_list_and_operator_exposed(self):
        (cmd,) = view("echo $(a && b)")
        assert cmd.kind == "command"
        sub_word = cmd.parts[1]
        assert sub_word.kind == "word"
        assert sub_word.word == "$(a && b)"
        assert sub_word.pos == (5, 14)

        (cs,) = sub_word.parts
        assert cs.kind == "commandsubstitution"
        assert cs.pos == (5, 14)

        inner = cs.command
        assert inner.kind == "list"
        assert [p.kind for p in inner.parts] == ["command", "operator", "command"]
        operator = inner.parts[1]
        assert operator.op == "&&"
        assert operator.pos == (9, 11)
        assert inner.parts[0].parts[0].word == "a"
        assert inner.parts[2].parts[0].word == "b"

    def test_substitution_validator_reads_the_view(self):
        # The second walker family (SubstitutionValidator) must duck-type the
        # view unchanged: .command on the substitution node, .op on operators,
        # .word on words (spec §3.2 — no changes to walker call sites).
        validator = SubstitutionValidator(parser=None, rule_engine=None)
        subs = validator.extract_substitutions(view("echo $(a && b)"))
        assert len(subs) == 1
        assert subs[0].substitution_type is SubstitutionType.COMMAND
        assert subs[0].base_command == "a"
        assert subs[0].inner_command == "a && b"

    def test_backquote_substitution(self):
        (cmd,) = view("echo `a`")
        (cs,) = cmd.parts[1].parts
        assert cs.kind == "commandsubstitution"
        assert cs.command.kind == "command"


@needs_binary
class TestPipeVersusPipeline:
    def test_pipeline_with_pipe_separator(self):
        (node,) = view("a | b")
        assert node.kind == "pipeline"
        assert [p.kind for p in node.parts] == ["command", "pipe", "command"]
        assert node.parts[1].pipe == "|"
        assert node.parts[1].pos == (2, 3)

    def test_stderr_pipe(self):
        (node,) = view("a |& b")
        assert node.parts[1].pipe == "|&"

    def test_pipeline_chain_is_flat(self):
        (node,) = view("a | b | c")
        assert node.kind == "pipeline"
        assert [p.kind for p in node.parts] == ["command", "pipe", "command", "pipe", "command"]

    def test_andor_chain_is_flat(self):
        (node,) = view("a && b || c")
        assert node.kind == "list"
        assert [getattr(p, "op", p.kind) for p in node.parts] == ["command", "&&", "command", "||", "command"]

    def test_pipeline_nested_in_list(self):
        (node,) = view("a && b | c")
        assert node.kind == "list"
        assert [p.kind for p in node.parts] == ["command", "operator", "pipeline"]


@needs_binary
class TestListSeparators:
    def test_semicolon(self):
        (node,) = view("a; b")
        assert node.kind == "list"
        assert node.parts[1].kind == "operator"
        assert node.parts[1].op == ";"
        assert node.parts[1].pos == (1, 2)

    def test_ampersand(self):
        (node,) = view("a & b")
        assert node.parts[1].op == "&"

    def test_trailing_background_operator(self):
        (node,) = view("a &")
        assert node.kind == "list"
        assert [p.kind for p in node.parts] == ["command", "operator"]
        assert node.parts[1].op == "&"

    def test_newline_separated_statements_are_separate_nodes(self):
        nodes = view("a\nb")
        assert [n.kind for n in nodes] == ["command", "command"]


@needs_binary
class TestCompound:
    def test_subshell(self):
        (node,) = view("(a)")
        assert node.kind == "compound"
        assert node.pos == (0, 3)
        assert node.list[0].kind == "command"

    def test_brace_group(self):
        (node,) = view("{ a; }")
        assert node.kind == "compound"
        inner = node.list[0]
        assert inner.kind == "list"
        assert [p.kind for p in inner.parts] == ["command", "operator"]


@needs_binary
class TestWordsAndParameters:
    def test_parameter_expansion(self):
        (cmd,) = view("echo $HOME")
        word = cmd.parts[1]
        assert word.word == "$HOME"
        param = word.parts[0]
        assert param.kind == "parameter"
        assert param.value == "HOME"
        assert param.pos == (5, 10)

    def test_braced_parameter(self):
        (cmd,) = view("echo ${HOME}")
        assert cmd.parts[1].word == "${HOME}"
        assert cmd.parts[1].parts[0].value == "HOME"

    def test_single_quotes_stripped_span_kept(self):
        (cmd,) = view("echo 'hi there'")
        word = cmd.parts[1]
        assert word.word == "hi there"
        assert word.pos == (5, 15)  # quote-inclusive span, like bashlex

    def test_double_quotes_preserve_expansions_in_text(self):
        (cmd,) = view('echo "hi $HOME"')
        word = cmd.parts[1]
        assert word.word == "hi $HOME"
        assert word.parts[0].kind == "parameter"


@needs_binary
class TestProcessSubstitution:
    def test_input_substitution(self):
        (cmd,) = view("diff <(a) f")
        word = cmd.parts[1]
        assert word.word == "<(a)"
        ps = word.parts[0]
        assert ps.kind == "processsubstitution"
        assert ps.command.kind == "command"
        assert ps.command.parts[0].word == "a"

    def test_output_substitution(self):
        (cmd,) = view("tee >(a)")
        assert cmd.parts[1].parts[0].kind == "processsubstitution"


@needs_binary
class TestRedirects:
    def test_output_redirect(self):
        (cmd,) = view("a > f")
        redirect = cmd.parts[1]
        assert redirect.kind == "redirect"
        assert redirect.type == ">"
        assert redirect.input is None
        assert redirect.output.kind == "word"
        assert redirect.output.word == "f"

    def test_heredoc(self):
        (cmd,) = view("cat <<EOF\nhi\nEOF")
        redirect = cmd.parts[1]
        assert redirect.type == "<<"
        assert redirect.output.word == "EOF"
        heredoc = redirect.heredoc
        assert heredoc.kind == "heredoc"
        assert heredoc.pos == (10, 16)
        assert heredoc.value == "hi\nEOF"

    def test_plain_redirect_has_no_heredoc_attr(self):
        (cmd,) = view("a > f")
        assert not hasattr(cmd.parts[1], "heredoc")


@needs_binary
class TestPanelFindings:
    """Regressions from the LAB-911 expert-panel review (all under-block class)."""

    def test_command_span_includes_trailing_redirect(self):
        # Panel CRIT: mvdan hangs Redirs off the Stmt, so a command node pos
        # taken from CallExpr alone excludes the redirect — and the sliced
        # segment text drops a dangerous redirect target (e.g. /dev/sda).
        command = "echo x > /dev/sda && ls"
        (node,) = view(command)
        segments = BashCommandParser().extract_command_segments(command, [node])
        assert segments == ["echo x > /dev/sda", "ls"]

    def test_redirect_prefix_extends_command_span_left(self):
        (cmd,) = view("2>&1 cmd")
        assert cmd.pos == (0, 8)

    def test_backslash_escape_in_word_raises(self):
        # Panel CRIT: bashlex unescapes `r\m` to `rm`; passing the raw escaped
        # text through would defeat every rule keyed on the command name.
        # Until T3 implements the per-WordPart unescape, escapes must raise
        # (→ bashlex tier, which unescapes correctly today).
        with pytest.raises(UnmappedNodeError, match="escape"):
            view("rm\\ -rf\\ /")
        with pytest.raises(UnmappedNodeError, match="escape"):
            view("r\\m -rf /")

    def test_backslash_in_single_quotes_is_literal_and_allowed(self):
        # Single quotes disable escape processing in bash, so a backslash
        # there is plain text — no divergence from bashlex, no raise.
        (cmd,) = view("echo 'a\\b'")
        assert cmd.parts[1].word == "a\\b"

    def test_non_ascii_input_raises(self):
        # Panel CRIT: mvdan emits BYTE offsets; the walkers char-index the
        # string, and a mis-sliced segment is silently DROPPED by their
        # bounds guard. Until T3 lands byte→char conversion, any non-ASCII
        # input must raise (→ bashlex tier).
        with pytest.raises(UnmappedNodeError, match="ASCII"):
            view("X=café; rm -rf /")

    def test_structurally_malformed_json_raises_bridge_error(self):
        # Panel MAJ: a KeyError escaping build_ast_view would bypass T5's
        # NativeBridgeError → bashlex routing and hard-DENY with no context.
        no_op_binary = {
            "Type": "File",
            "Pos": {"Offset": 0},
            "End": {"Offset": 6},
            "Stmts": [
                {
                    "Pos": {"Offset": 0},
                    "End": {"Offset": 6},
                    "Cmd": {"Type": "BinaryCmd", "Pos": {"Offset": 0}, "End": {"Offset": 6}},
                }
            ],
        }
        with pytest.raises(NativeBridgeError, match="malformed"):
            build_ast_view("a && b", no_op_binary)

    def test_missing_pos_raises_bridge_error(self):
        with pytest.raises(NativeBridgeError):
            build_ast_view("a", {"Type": "File", "End": {"Offset": 1}, "Stmts": [{}]})

    def test_nodes_carry_the_tabled_child_attribute(self):
        # Panel MAJ: the mapping table must DRIVE the converter, not decorate
        # it. Every produced node whose kind is in the table must carry the
        # tabled child attribute (pipeline shares `parts` via BINARY_OPS).
        child_by_kind = {kind: child for kind, child in MVDAN_NODE_MAP.values() if child is not None}
        child_by_kind["pipeline"] = "parts"
        samples = ["echo $(a && b) > f", "X=$(a) diff <(b) f | c", "(a; b)", "echo ${HOME}"]

        def walk(node):
            assert node.kind in BASHLEX_KINDS or node.kind == "heredoc"
            child_attr = child_by_kind.get(node.kind)
            if child_attr is not None:
                assert hasattr(node, child_attr), f"{node.kind} node missing .{child_attr}"
            for attr in ("parts", "list", "command", "output", "heredoc"):
                child = getattr(node, attr, None)
                for item in child if isinstance(child, list) else [child]:
                    if isinstance(item, AstView):
                        walk(item)

        for sample in samples:
            for node in view(sample):
                walk(node)


class TestUnmappedRaises:
    """Anything without an explicit mapping must raise → fallback tier.

    A tolerant "skip unknown node" is a silent under-block and is forbidden
    by contract (spec §3.2, §11 finding 1).
    """

    @staticmethod
    def _file(stmts, end):
        return {
            "Type": "File",
            "Pos": {"Offset": 0},
            "End": {"Offset": end},
            "Stmts": stmts,
        }

    def test_synthetic_unmapped_command_type_raises(self):
        frob = {"Type": "FrobExpr", "Pos": {"Offset": 0}, "End": {"Offset": 1}}
        payload = self._file([{"Pos": {"Offset": 0}, "End": {"Offset": 1}, "Cmd": frob}], end=1)
        with pytest.raises(UnmappedNodeError, match="FrobExpr"):
            build_ast_view("a", payload)

    def test_synthetic_unmapped_word_part_raises(self):
        frob_part = {"Type": "FrobPart", "Pos": {"Offset": 0}, "End": {"Offset": 1}}
        word = {"Pos": {"Offset": 0}, "End": {"Offset": 1}, "Parts": [frob_part]}
        cmd = {"Type": "CallExpr", "Pos": {"Offset": 0}, "End": {"Offset": 1}, "Args": [word]}
        payload = self._file([{"Pos": {"Offset": 0}, "End": {"Offset": 1}, "Cmd": cmd}], end=1)
        with pytest.raises(UnmappedNodeError, match="FrobPart"):
            build_ast_view("a", payload)

    def test_synthetic_unmapped_binary_op_raises(self):
        stmt = lambda off: {  # noqa: E731
            "Pos": {"Offset": off},
            "End": {"Offset": off + 1},
            "Cmd": {
                "Type": "CallExpr",
                "Pos": {"Offset": off},
                "End": {"Offset": off + 1},
                "Args": [
                    {
                        "Pos": {"Offset": off},
                        "End": {"Offset": off + 1},
                        "Parts": [{"Type": "Lit", "Pos": {"Offset": off}, "End": {"Offset": off + 1}, "Value": "a"}],
                    }
                ],
            },
        }
        binary = {
            "Type": "BinaryCmd",
            "Pos": {"Offset": 0},
            "End": {"Offset": 6},
            "Op": 99,
            "OpPos": {"Offset": 2},
            "X": stmt(0),
            "Y": stmt(5),
        }
        payload = self._file([{"Pos": {"Offset": 0}, "End": {"Offset": 6}, "Cmd": binary}], end=6)
        with pytest.raises(UnmappedNodeError, match="99"):
            build_ast_view("a ?? b", payload)

    def test_unmapped_error_routes_to_fallback(self):
        # UnmappedNodeError must be a NativeBridgeError so T5's state machine
        # sends it to the bashlex tier, not to a hard deny.
        assert issubclass(UnmappedNodeError, NativeBridgeError)

    @needs_binary
    def test_arithmetic_command_unmapped(self):
        # `(( … ))` stays unmapped by choice, not by omission: bashlex parses it
        # but calls the arithmetic body a COMMAND named after the expression, so
        # a superset-preserving mapping would have to copy that misparse. It is
        # not one of the 7 bashlex-failing constructs, so the fallback tier costs
        # nothing here. See _clause_expression and tests/test_walker_parity.py.
        with pytest.raises(UnmappedNodeError, match="ArithmCmd"):
            view("(( x++ ))")

    @needs_binary
    def test_coprocess_raises(self):
        # `coproc` runs the command behind its own pipes — a shape bashlex has no
        # node for. It arrives as a CoprocClause COMMAND, so the clause table is
        # what rejects it (`Stmt.Coprocess` is the mksh `|&` spelling, which this
        # bash-mode CLI never emits).
        with pytest.raises(UnmappedNodeError, match="CoprocClause"):
            view("coproc a { sleep 1; }")

    @needs_binary
    def test_negated_statement_raises(self):
        # Dropping `!` would defeat substitution.py's deliberate fail-closed on a
        # negated pipeline (`_is_valid_pipeline_topology`). See convert_stmt.
        with pytest.raises(UnmappedNodeError, match="Negated"):
            view("! a")

    @needs_binary
    def test_ansi_c_quoting_raises(self):
        # $'\x72\x6d' decoding is T3's oracle territory; until then the
        # fallback tier keeps today's (bashlex) behavior.
        with pytest.raises(UnmappedNodeError):
            view("echo $'\\x72'")


@needs_binary
class TestFullSpanAssertion:
    """Spec §3.1: a prefix parse is a FAILURE, never a clean success."""

    def test_prefix_parse_raises(self):
        # Simulate a short read: JSON for a prefix, command with a tail.
        prefix_json = NativeBridge().parse_json("echo hi")
        with pytest.raises(NativeBridgeError, match="span"):
            build_ast_view("echo hi; rm -rf /", prefix_json)

    def test_trailing_whitespace_tolerated(self):
        nodes = view("a ")
        assert nodes[0].kind == "command"

    def test_comment_tail_raises(self):
        # Comments are parsed OFF in the CLI (spec §3.1), so a trailing
        # comment reads as uncovered input → fallback tier (over-conservative
        # by design: bashlex parses comments fine).
        with pytest.raises(NativeBridgeError, match="span"):
            view("a # comment")


@needs_binary
class TestParserWalkerIntegration:
    """The first walker family (BashCommandParser) reads the view unchanged."""

    def test_extract_command_segments(self):
        parser = BashCommandParser()
        command = "ls | rm -rf / && echo done"
        segments = parser.extract_command_segments(command, view(command))
        assert segments == ["ls", "rm -rf /", "echo done"]

    def test_extract_commands_with_args(self):
        extracted = BashCommandParser().extract_commands_with_args(view("X=1 nc -e /bin/bash host"))
        assert extracted == [("nc", ["-e", "/bin/bash", "host"])]


class TestJsonEntryPoint:
    def test_accepts_json_text(self):
        # build_ast_view accepts the raw text NativeBridge.parse_json returns.
        payload = {
            "Type": "File",
            "Pos": {"Offset": 0},
            "End": {"Offset": 1},
            "Stmts": [
                {
                    "Pos": {"Offset": 0},
                    "End": {"Offset": 1},
                    "Cmd": {
                        "Type": "CallExpr",
                        "Pos": {"Offset": 0},
                        "End": {"Offset": 1},
                        "Args": [
                            {
                                "Pos": {"Offset": 0},
                                "End": {"Offset": 1},
                                "Parts": [{"Type": "Lit", "Pos": {"Offset": 0}, "End": {"Offset": 1}, "Value": "a"}],
                            }
                        ],
                    },
                }
            ],
        }
        (cmd,) = build_ast_view("a", json.dumps(payload))
        assert cmd.kind == "command"
        assert cmd.parts[0].word == "a"
