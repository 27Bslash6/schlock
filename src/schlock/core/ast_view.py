"""AstView: bashlex-shaped node views over `schlock-parse` typed-JSON.

Slice T2b of the native-parser migration (spec §1, §3.2): turn the raw
typed-JSON that T2a's `NativeBridge` reads from the mvdan/sh CLI into
duck-typed nodes that BOTH existing AST-walker families can read unchanged —
`BashCommandParser`'s visitors (`.kind`/`.parts`/`.word`/`.pos`/`.heredoc`)
and `SubstitutionValidator`'s independent walk (`.command`/`.op`/`.value`).
The walkers' call sites are the contract; nothing here changes them.

Two rules carry the security weight:

1. **Unmapped means RAISE, never skip.** The fallback chain (spec §6) fires on
   failures, not on semantic weakness — a typed-JSON node type, WordPart, or
   numeric op that this module silently dropped would hand the walkers a
   valid-looking but weaker AST, i.e. a silent under-block (spec §11 finding
   1). Every dispatch below goes through an explicit table; a miss raises
   `UnmappedNodeError` (→ bashlex tier). Position/format metadata (`Position`,
   `OpPos`, `Backquotes`, brace/paren offsets) is ignored by design; anything
   carrying SEMANTIC payload must be mapped or raise.
2. **A prefix parse is a failure.** The parsed byte-span must cover the whole
   input up to trailing whitespace (spec §3.1) — accepting a prefix would drop
   a trailing `; rm -rf /` on the floor. Comments are parsed OFF in the CLI,
   so a trailing `# comment` also trips this check; that over-conservatively
   routes commented commands to the bashlex tier, which parses them fine.

T2c widened the table to the constructs bashlex models as `compound` nodes
(`if`/`for`/`while`/`select`/`case`/functions) plus the three it cannot parse at
all (`[[ ]]`, `$(( ))`, array assignments), each pinned by a walker-output parity
test in `tests/test_walker_parity.py`. Widening is NOT free just because a
construct parses: `!` and `(( ))` both look trivially mappable and both
measurably weakened the walkers when tried — the reason lives at each raise site
(`convert_stmt`, `_clause_test`), which is where the next person will look.

Remaining ceilings, ALL fail-closed by raising into the fallback tier: backslash
escapes in word text, ANSI-C `$'…'` and non-ASCII input (T3 owns the per-WordPart
unescape and byte→char conversion — passing raw escapes or byte offsets through
would silently weaken the walkers, LAB-911 panel CRITs); plus `!`, `coproc`,
`(( ))`, indexed/naked assignments, redirects on a compound statement, and a
trailing `# comment` (comments are parsed off, so one reads as a prefix parse).
"""

import json
from typing import Any, Optional, Union

from schlock.core.native_bridge import NativeBridgeError

# ---------------------------------------------------------------------------
# Mapping tables — DATA, the T2 deliverable (spec §3.2). The 12-kind bashlex
# vocabulary the walkers switch on (spec §1):
BASHLEX_KINDS = frozenset(
    {
        "command",
        "pipeline",
        "pipe",
        "list",
        "compound",
        "redirect",
        "assignment",
        "word",
        "operator",
        "parameter",
        "commandsubstitution",
        "processsubstitution",
    }
)

#: mvdan node → (bashlex kind, child attribute the walkers read from it).
#: Interface nodes (`Command`, `WordPart`) carry a "Type" tag in typed-JSON;
#: `Word`/`Assign`/`Redir` are structural (untagged) and are reached only from
#: known slots (Args/Assigns/Redirs/Word), but belong in the table because the
#: table IS the kind contract. `File` materializes as a `list` only when its
#: statements are `;`/`&`-joined; `BinaryCmd` resolves through BINARY_OPS.
MVDAN_NODE_MAP: "dict[str, tuple[str, Optional[str]]]" = {
    "File": ("list", "parts"),
    "CallExpr": ("command", "parts"),
    "Subshell": ("compound", "list"),
    "Block": ("compound", "list"),
    "CmdSubst": ("commandsubstitution", "command"),
    "ProcSubst": ("processsubstitution", "command"),
    "ParamExp": ("parameter", None),
    "Word": ("word", "parts"),
    "Assign": ("assignment", "parts"),
    "Redir": ("redirect", "output"),
    # T2c clauses, all reusing `compound` because that is what bashlex models
    # `if`/`for`/`while`/`case`/function bodies as (its `reservedword` tokens
    # carry no danger and both walker families skip them), and because
    # `extract_command_segments` already recurses `.list` — so a `rm -rf /` in a
    # loop body surfaces as its own segment without a 13th kind. Handlers for
    # these live in _CLAUSE_CHILDREN.
    "IfClause": ("compound", "list"),
    "WhileClause": ("compound", "list"),
    "ForClause": ("compound", "list"),
    "CaseClause": ("compound", "list"),
    "FuncDecl": ("compound", "list"),
    "TestClause": ("compound", "list"),
    # Not a clause: `$(( … ))` is a WordPart whose children are its operand
    # words (see _word_part_children), and it borrows the same `compound` shape.
    "ArithmExp": ("compound", "list"),
}

#: BinaryCmd numeric op → (operator text, container kind, separator kind).
#: `pipe` ≠ `pipeline`: `a | b` is a `pipeline` node whose separator children
#: are `pipe` nodes, while `a && b` is a `list` with `operator` children.
#: Codes pinned empirically against the vendored schlock-parse (mvdan/sh v3);
#: an unlisted code raises, so an op vocabulary drift in a future binary
#: degrades to the bashlex tier instead of mis-shaping the tree.
BINARY_OPS: "dict[int, tuple[str, str, str]]" = {
    11: ("&&", "list", "operator"),
    12: ("||", "list", "operator"),
    13: ("|", "pipeline", "pipe"),
    14: ("|&", "pipeline", "pipe"),
}

#: Redir numeric op → bashlex redirect `type` string (same pinning rule).
REDIRECT_OPS: "dict[int, str]" = {
    63: ">",
    64: ">>",
    65: "<",
    66: "<>",
    67: "<&",
    68: ">&",
    69: ">|",
    71: "<<",
    72: "<<-",
    73: "<<<",
    74: "&>",
    76: "&>>",
}

#: ProcSubst numeric op → source spelling (direction is not encoded on the
#: bashlex node; SubstitutionValidator treats both as process substitution).
PROC_SUBST_OPS: "dict[int, str]" = {78: "<(", 80: ">("}

#: WordPart type → how its text contributes to bashlex-style `.word`:
#:   "value"  — the part's decoded Value (quotes stripped by the parser);
#:   "source" — the raw source slice, preserving `$VAR`/`$(...)`/`<(...)`
#:              spelling so substitution/parameter checks still fire
#:              (over-flattening these would under-block, spec §4a);
#:   "quoted" — recurse into the part's inner parts, framing quotes stripped.
WORD_PART_MAP: "dict[str, str]" = {
    "Lit": "value",
    "SglQuoted": "value",
    "DblQuoted": "quoted",
    "ParamExp": "source",
    "CmdSubst": "source",
    "ProcSubst": "source",
    "ArithmExp": "source",
}

#: Test/arithmetic expression node → the operand fields to recurse into (`Word`
#: is the leaf and is handled before this lookup, so no entry may be empty).
#: `[[ … ]]` and `$(( … ))` cannot invoke a command; the only execution either
#: carries is a word-level expansion (`$(…)`, backquotes, `${…}`), so the walkers
#: need the operand WORDS and nothing else. The numeric comparison/arithmetic op
#: is therefore deliberately NOT mapped — unlike a `BinaryCmd` op it selects a
#: comparison, never a command, so dropping it cannot shrink the danger surface.
#: An unlisted expression type still raises: a future mvdan node that DOES
#: introduce execution must not slip through as "just another operand".
EXPR_OPERANDS: "dict[str, tuple[str, ...]]" = {
    "UnaryTest": ("X",),
    "BinaryTest": ("X", "Y"),
    "ParenTest": ("X",),
    "UnaryArithm": ("X",),
    "BinaryArithm": ("X", "Y"),
    "ParenArithm": ("X",),
}

#: WordPart types that also materialize as structural children in a word's
#: `.parts` (bashlex nests these so walkers can find substitutions in words).
#: Derived, not hand-copied: exactly the source-text parts — a type added to
#: WORD_PART_MAP as "source" without a child node would hide its substitution
#: from the walkers (panel finding, LAB-911 review).
_STRUCTURAL_WORD_PARTS = frozenset(k for k, v in WORD_PART_MAP.items() if v == "source")

_HEREDOC_TYPES = frozenset({"<<", "<<-"})


class UnmappedNodeError(NativeBridgeError):
    """Typed-JSON carried a construct with no explicit mapping.

    Subclasses `NativeBridgeError` so the tier state machine (T5) routes it to
    the bashlex fallback — the one behavior that cannot under-block.
    """


class AstView:
    """A bashlex-shaped node: `.kind`, `.pos`, plus per-kind attributes.

    Attributes are plain instance attributes and ONLY set when the kind
    carries them — both walker families dispatch on `hasattr`, so a spurious
    `.word` on a command node or `.list` on a substitution node would corrupt
    their traversal.
    """

    def __init__(self, kind: str, pos: "tuple[int, int]", **attrs: Any):
        self.kind = kind
        self.pos = pos
        self.__dict__.update(attrs)

    def __getattr__(self, name: str) -> Any:
        # Reached only for attributes this kind does not carry; the explicit
        # raise keeps hasattr-dispatch honest while typing access as Any.
        raise AttributeError(name)

    def __repr__(self) -> str:
        extras = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items() if k not in ("kind", "pos"))
        return f"AstView(kind={self.kind!r}, pos={self.pos}{', ' if extras else ''}{extras})"


def _pos(node: dict) -> "tuple[int, int]":
    return (node["Pos"]["Offset"], node["End"]["Offset"])


def _node(mvdan_type: str, pos: "tuple[int, int]", child: Any = None, **attrs: Any) -> AstView:
    """Build an AstView THROUGH the mapping table.

    Every constructor site resolves its kind and child attribute from
    MVDAN_NODE_MAP, so the table drives the converter instead of decorating
    it — a table edit that the code disagrees with breaks tests instead of
    silently changing nothing (panel finding, LAB-911 review).
    """
    kind, child_attr = MVDAN_NODE_MAP[mvdan_type]
    if child_attr is not None:
        attrs[child_attr] = child
    return AstView(kind, pos, **attrs)


class _Converter:
    """One conversion pass over a single command's typed-JSON."""

    def __init__(self, command: str):
        # mvdan offsets are BYTE offsets; slicing happens on the encoded form.
        # Byte→char conversion for the walkers' `.pos` consumers is T3; a
        # multibyte slice that splits a code point raises (fail closed).
        self._src = command.encode("utf-8")

    def _slice(self, start: int, end: int) -> str:
        return self._src[start:end].decode("utf-8")

    # -- statements ---------------------------------------------------------

    def stmts_to_nodes(self, stmts: "list[dict]") -> "list[AstView]":
        """Map a Stmts array to top-level nodes, bashlex-style.

        `;`/`&`-joined statements collapse into one `list` node with
        synthesized `operator` children (mvdan encodes the separator as
        `Semicolon`/`Background` on the LEFT statement); newline-separated
        statements become separate nodes, matching bashlex.parse output.
        """
        nodes: list[AstView] = []
        group: list[tuple[AstView, Optional[AstView]]] = []
        for stmt in stmts:
            node = self.convert_stmt(stmt)
            operator = self._separator(stmt)
            group.append((node, operator))
            if operator is None:  # newline (or end of input) closes the group
                nodes.append(self._collapse_group(group))
                group = []
        if group:  # trailing `;`/`&` — bashlex still emits the operator node
            nodes.append(self._collapse_group(group))
        return nodes

    def _separator(self, stmt: dict) -> "Optional[AstView]":
        if "Semicolon" not in stmt:
            return None
        offset = stmt["Semicolon"]["Offset"]
        op = "&" if stmt.get("Background") else ";"
        return AstView("operator", (offset, offset + len(op)), op=op)

    def _collapse_group(self, group: "list[tuple[AstView, Optional[AstView]]]") -> AstView:
        if len(group) == 1 and group[0][1] is None:
            return group[0][0]
        parts: list[AstView] = []
        for node, operator in group:
            if node.kind == "list":
                # bashlex emits ONE FLAT list for `a; b && c` — [a, ;, b, &&, c] —
                # where mvdan nests the `&&`. Splice same-kind children so
                # substitution.py's topology checks see the alternation they were
                # written against; a nested `list` in a segment slot renders to
                # None and falsely blocks `$(pwd; ls && ls)`. Only `list`
                # flattens — bashlex keeps a `pipeline` nested.
                parts.extend(node.parts)
            else:
                parts.append(node)
            if operator is not None:
                parts.append(operator)
        return _node("File", (parts[0].pos[0], parts[-1].pos[1]), child=parts)

    def stmts_to_single_node(self, stmts: "list[dict]", context: str) -> AstView:
        """Map an inner Stmts array (substitutions) to exactly one node."""
        nodes = self.stmts_to_nodes(stmts)
        if len(nodes) != 1:
            # $()/<() empty or newline-split bodies have no single bashlex
            # shape; the fallback tier handles them (over-block, never under).
            raise UnmappedNodeError(f"{context} with {len(nodes)} statement groups has no mapped shape")
        return nodes[0]

    def convert_stmt(self, stmt: dict) -> AstView:
        if stmt.get("Negated"):
            # `!` looks harmless — it only inverts the exit status — and T2c
            # trialled mapping it, but the parity sweep caught a real loosening:
            # substitution.py's `_is_valid_pipeline_topology` deliberately fails
            # closed on `$(! a | b)` because bashlex's leading `reservedword`
            # makes the parts count even. Dropping the `!` hands that check a
            # clean pipeline of whitelisted readers and it ALLOWS what bashlex
            # BLOCKED. Not one of the 7 bashlex-failing constructs, so the
            # fallback tier covers it at no loss.
            #
            # (`coproc` is unmapped too, but it arrives as a `CoprocClause`
            # command and raises from the clause table — `Stmt.Coprocess` is the
            # mksh `|&` spelling, which this bash-mode CLI never emits.)
            raise UnmappedNodeError("unmapped statement modifier: Negated")
        cmd = stmt.get("Cmd")
        if cmd is None:
            raise UnmappedNodeError("statement without a command has no mapped shape")
        redirects = [self.convert_redirect(r) for r in stmt.get("Redirs", [])]
        if redirects and cmd.get("Type") != "CallExpr":
            # bashlex hangs redirects off compound/pipeline nodes differently;
            # that shape is unmapped until T2c pins it against the walkers.
            raise UnmappedNodeError(f"redirects on a {cmd.get('Type')} statement are not mapped")
        return self.convert_command(cmd, redirects)

    # -- commands -----------------------------------------------------------

    def convert_command(self, cmd: dict, redirects: "list[AstView]") -> AstView:
        node_type = cmd.get("Type") or ""
        if node_type == "CallExpr":
            return self._convert_call(cmd, redirects)
        if node_type == "BinaryCmd":
            return self._convert_binary(cmd)
        if node_type in ("Subshell", "Block"):
            return _node(node_type, _pos(cmd), child=self.stmts_to_nodes(cmd.get("Stmts", [])))
        clause = _CLAUSE_CHILDREN.get(node_type)
        if clause is None:
            raise UnmappedNodeError(f"unmapped typed-JSON node type: {node_type}")
        return _node(node_type, _pos(cmd), child=clause(self, cmd))

    def _convert_call(self, cmd: dict, redirects: "list[AstView]") -> AstView:
        parts = [self.convert_assign(a) for a in cmd.get("Assigns", [])]
        parts.extend(self.convert_word(w) for w in cmd.get("Args", []))
        parts.extend(redirects)
        parts.sort(key=lambda p: p.pos[0])  # bashlex keeps source order
        # mvdan hangs Redirs off the Stmt, so CallExpr's own span excludes
        # them — but extract_command_segments slices the segment text from the
        # command node's pos, and a span that stops short of `> /dev/sda`
        # silently drops the dangerous target (panel CRIT, LAB-911 review).
        # bashlex spans the whole command including redirects; reproduce that.
        start, end = _pos(cmd)
        if parts:
            start = min(start, parts[0].pos[0])
            end = max(end, *(p.pos[1] for p in parts))
        return _node("CallExpr", (start, end), child=parts)

    def _convert_binary(self, cmd: dict) -> AstView:
        op_code = cmd["Op"]
        if op_code not in BINARY_OPS:
            raise UnmappedNodeError(f"unmapped BinaryCmd op code: {op_code}")
        op_text, container_kind, separator_kind = BINARY_OPS[op_code]
        op_offset = cmd["OpPos"]["Offset"]
        separator_attr = {"operator": {"op": op_text}, "pipe": {"pipe": op_text}}[separator_kind]
        separator = AstView(separator_kind, (op_offset, op_offset + len(op_text)), **separator_attr)

        parts = [
            *self._binary_side(cmd["X"], container_kind),
            separator,
            *self._binary_side(cmd["Y"], container_kind),
        ]
        return AstView(container_kind, _pos(cmd), parts=parts)

    def _binary_side(self, stmt: dict, container_kind: str) -> "list[AstView]":
        """Convert one side of a BinaryCmd, flattening same-kind chains.

        mvdan nests `a && b || c` / `a | b | c` as binary trees; bashlex emits
        one flat node per chain, which is what the walkers iterate.
        """
        inner_cmd = stmt.get("Cmd") or {}
        plain = not any(stmt.get(k) for k in ("Negated", "Coprocess", "Background")) and not stmt.get("Redirs")
        if plain and inner_cmd.get("Type") == "BinaryCmd":
            inner_op = BINARY_OPS.get(inner_cmd.get("Op", -1))
            if inner_op is not None and inner_op[1] == container_kind:
                return self._convert_binary(inner_cmd).parts
        return [self.convert_stmt(stmt)]

    # -- clauses (T2c) ------------------------------------------------------
    # Each returns the children of a `compound` node's `.list`. Every branch of
    # a clause contributes: an `if` whose ELSE arm holds the `rm -rf /` is the
    # obvious under-block, but so is a `case` whose non-matching arm does — the
    # walkers validate every reachable command, not the one that happens to run.

    def _clause_if(self, cmd: dict) -> "list[AstView]":
        children = self.stmts_to_nodes(cmd.get("Cond", []))
        children.extend(self.stmts_to_nodes(cmd.get("Then", [])))
        else_clause = cmd.get("Else")
        if else_clause is not None:
            # typedjson leaves `Else` untagged because it is a concrete *IfClause
            # field, not an interface: an `elif` arm carries Cond+Then, a bare
            # `else` carries Then only. Recursing handles both.
            children.extend(self._clause_if(else_clause))
        return children

    def _clause_while(self, cmd: dict) -> "list[AstView]":
        # `until` is the same node with Until=true; inverting the loop's exit
        # test does not change which commands run.
        children = self.stmts_to_nodes(cmd.get("Cond", []))
        children.extend(self.stmts_to_nodes(cmd.get("Do", [])))
        return children

    def _clause_for(self, cmd: dict) -> "list[AstView]":
        loop = cmd.get("Loop") or {}
        loop_type = loop.get("Type")
        if loop_type == "WordIter":  # for x in a b — and `select`, same node
            children = [self.convert_word(w) for w in loop.get("Items", [])]
        elif loop_type == "CStyleLoop":  # for ((i=$(…); i<n; i++))
            children = [w for field in ("Init", "Cond", "Post") for w in self._expr_words(loop.get(field))]
        else:
            raise UnmappedNodeError(f"unmapped for-loop header: {loop_type}")
        children.extend(self.stmts_to_nodes(cmd.get("Do", [])))
        return children

    def _clause_case(self, cmd: dict) -> "list[AstView]":
        children = [self.convert_word(cmd["Word"])]
        for item in cmd.get("Items", []):
            children.extend(self.convert_word(p) for p in item.get("Patterns", []))
            children.extend(self.stmts_to_nodes(item.get("Stmts", [])))
        return children

    def _clause_func(self, cmd: dict) -> "list[AstView]":
        return [self.convert_stmt(cmd["Body"])]

    def _clause_test(self, cmd: dict) -> "list[AstView]":
        """`[[ … ]]` — one test-expression tree, operand words only.

        `ArithmCmd` (`(( x++ ))`) is deliberately NOT routed here and keeps
        raising: bashlex does parse it, but misreads the arithmetic body as a
        COMMAND named after the whole expression (`x++`), so a mapping would have
        to copy that misparse just to stay a superset of it. Not one of the 7
        bashlex-failing constructs, so the fallback tier covers it at no loss.
        (`$(( … ))` is an ArithmExp WORD PART, not a clause — see
        `_word_part_children`.)
        """
        return self._expr_words(cmd.get("X"))

    def _expr_words(self, expr: "Optional[dict]") -> "list[AstView]":
        """Collect the operand words of a test/arithmetic expression tree."""
        if not expr:
            return []
        expr_type = expr.get("Type", "")
        if expr_type == "Word":  # the leaf; checked first so no table row is empty
            return [self.convert_word(expr)]
        operands = EXPR_OPERANDS.get(expr_type)
        if operands is None:
            raise UnmappedNodeError(f"unmapped test/arithmetic expression node: {expr_type}")
        return [word for field in operands for word in self._expr_words(expr.get(field))]

    # -- words, assignments, redirects, word parts --------------------------

    def convert_word(self, word: dict) -> AstView:
        text, children = self._word_content(word)
        return _node("Word", _pos(word), child=children, word=text)

    def _word_content(self, word: dict) -> "tuple[str, list[AstView]]":
        parts = word.get("Parts")
        if not parts:
            raise UnmappedNodeError("word without parts has no mapped shape")
        text_chunks: list[str] = []
        children: list[AstView] = []
        for part in parts:
            text_chunks.append(self._word_part_text(part))
            children.extend(self._word_part_children(part))
        return "".join(text_chunks), children

    def _word_part_text(self, part: dict) -> str:
        part_type = part.get("Type", "")
        handler = WORD_PART_MAP.get(part_type)
        if handler is None:
            raise UnmappedNodeError(f"unmapped WordPart type: {part_type}")
        if handler == "value":
            if part_type == "SglQuoted" and part.get("Dollar"):
                # ANSI-C $'…' decoding is T3 oracle territory (bashlex's own
                # decode is buggy); route to the fallback tier until then.
                raise UnmappedNodeError("ANSI-C quoted string ($'...') is not mapped yet")
            value = part.get("Value", "")
            if part_type == "Lit" and "\\" in value:
                # bashlex unescapes Lit text (`r\m` → `rm`); passing the raw
                # escaped form through would defeat every rule keyed on the
                # unescaped command (panel CRIT, LAB-911 review). Until T3
                # lands the per-WordPart unescape, escapes raise → bashlex
                # tier, which unescapes correctly today. SglQuoted content is
                # exempt: bash keeps its backslashes literal, no divergence.
                raise UnmappedNodeError("backslash escape in word text is not mapped yet (T3 unescape)")
            return value
        if handler == "quoted":
            return "".join(self._word_part_text(p) for p in part.get("Parts", []))
        return self._slice(*_pos(part))  # "source"

    def _word_part_children(self, part: dict) -> "list[AstView]":
        part_type = part.get("Type")
        if part_type == "DblQuoted":
            children: list[AstView] = []
            for inner in part.get("Parts", []):
                children.extend(self._word_part_children(inner))
            return children
        if part_type not in _STRUCTURAL_WORD_PARTS:
            return []
        if part_type == "ParamExp":
            return [_node("ParamExp", _pos(part), value=part["Param"]["Value"]), *self._param_exp_words(part)]
        if part_type == "CmdSubst":
            inner = self.stmts_to_single_node(part.get("Stmts", []), "command substitution")
            return [_node("CmdSubst", _pos(part), child=inner)]
        if part_type == "ArithmExp":
            # `$(( $(rm -rf /) + 1 ))` executes inside the arithmetic; the
            # operand words carry that substitution to SubstitutionValidator.
            return [_node("ArithmExp", _pos(part), child=self._expr_words(part.get("X")))]
        # ProcSubst
        if part.get("Op") not in PROC_SUBST_OPS:
            raise UnmappedNodeError(f"unmapped ProcSubst op code: {part.get('Op')}")
        inner = self.stmts_to_single_node(part.get("Stmts", []), "process substitution")
        return [_node("ProcSubst", _pos(part), child=inner)]

    def _param_exp_words(self, part: dict) -> "list[AstView]":
        """Words a `${…}` expansion EVALUATES, spliced in beside the parameter node.

        `${z:-$(rm -rf /)}` runs that substitution; so do the replacement words of
        `${z/a/$(…)}`, the offsets of `${z:$(…):1}` and the subscript of
        `${a[$(…)]}`. A childless `parameter` node hid all four from
        SubstitutionValidator — invisible on the bashlex tier too, which sees none
        of them, so mapping them is a superset rather than parity (LAB-912 panel).

        Siblings, not a `.parts` attribute on the parameter node: that is how
        `DblQuoted` already flattens its children, and bashlex's `parameter` node
        carries no `.parts` for a walker to find them under.

        `Length`/`Excl`/`Short`/`Names` are bare flags with no word payload, and
        `Exp.Op` selects WHEN the word is evaluated (`:-` vs `:=` vs `:?`), never
        what runs — so neither can shrink the danger surface by going unmapped.
        """
        words: list[AstView] = []
        expansion = part.get("Exp") or {}
        if expansion.get("Word"):
            words.append(self.convert_word(expansion["Word"]))
        replacement = part.get("Repl") or {}
        for field in ("Orig", "With"):
            if replacement.get(field):
                words.append(self.convert_word(replacement[field]))
        substring = part.get("Slice") or {}
        for field in ("Offset", "Length"):
            words.extend(self._expr_words(substring.get(field)))
        words.extend(self._expr_words(part.get("Index")))
        return words

    def convert_assign(self, assign: dict) -> AstView:
        if "Index" in assign or assign.get("Naked"):
            # `a[$(rm -rf /)]=x` and `declare -x foo` need shapes no walker has
            # been shown yet; they stay fail-closed until a test pins them.
            raise UnmappedNodeError("indexed/naked assignment is not mapped yet")
        operator = "+=" if assign.get("Append") else "="
        if "Array" in assign:
            return self._convert_array_assign(assign, operator)
        value = assign.get("Value")
        if value is None:
            value_text, children = "", []
        else:
            value_text, children = self._word_content(value)
        word = assign["Name"]["Value"] + operator + value_text
        return _node("Assign", _pos(assign), child=children, word=word)

    def _convert_array_assign(self, assign: dict, operator: str) -> AstView:
        """`a=(1 2 3)` — bashlex cannot parse this, so there is no shape to match.

        `.word` keeps the SOURCE spelling of the array (the rule engine matches
        on text, and `a=($(curl x|sh))` must stay recognizable), while every
        element's word node hangs off `.parts` so a substitution inside an
        element still reaches SubstitutionValidator.
        """
        array = assign["Array"]
        elements: list[AstView] = []
        for elem in array.get("Elems", []):
            elements.extend(self._expr_words(elem.get("Index")))  # a=([i+1]=x)
            if elem.get("Value"):
                elements.append(self.convert_word(elem["Value"]))
        word = assign["Name"]["Value"] + operator + self._slice(*_pos(array))
        return _node("Assign", _pos(assign), child=elements, word=word)

    def convert_redirect(self, redir: dict) -> AstView:
        op_code = redir["Op"]
        if op_code not in REDIRECT_OPS:
            raise UnmappedNodeError(f"unmapped Redir op code: {op_code}")
        redirect_type = REDIRECT_OPS[op_code]

        fd = None
        n = redir.get("N")
        if n is not None:
            if not n.get("Value", "").isdigit():
                raise UnmappedNodeError("non-numeric redirect fd is not mapped")
            fd = int(n["Value"])

        target_word = redir.get("Word")
        if target_word is None:
            raise UnmappedNodeError("redirect without a target word is not mapped")
        output: Union[AstView, int] = self.convert_word(target_word)
        if redirect_type in (">&", "<&") and output.word.isdigit():
            output = int(output.word)  # bashlex represents fd targets as ints

        attrs: dict[str, Any] = {"input": fd, "type": redirect_type}
        if "Hdoc" in redir:
            if redirect_type not in _HEREDOC_TYPES:
                raise UnmappedNodeError(f"heredoc body on a {redirect_type!r} redirect is not mapped")
            hdoc_pos = _pos(redir["Hdoc"])
            # bashlex's heredoc value includes the terminator line; the source
            # slice reproduces that exactly (mvdan's End already covers it).
            attrs["heredoc"] = AstView("heredoc", hdoc_pos, value=self._slice(*hdoc_pos))
        return _node("Redir", _pos(redir), child=output, **attrs)


#: Clause node type → the `_Converter` method producing its `compound.list`.
#: A table, not an if-chain, so a type absent here RAISES. Its keys must all
#: carry a `("compound", "list")` row in MVDAN_NODE_MAP — the two would otherwise
#: drift into a KeyError that blames the binary for a table bug, so
#: `test_ast_view.py` pins them together.
_CLAUSE_CHILDREN = {
    "IfClause": _Converter._clause_if,
    "WhileClause": _Converter._clause_while,
    "ForClause": _Converter._clause_for,
    "CaseClause": _Converter._clause_case,
    "FuncDecl": _Converter._clause_func,
    "TestClause": _Converter._clause_test,
}


def build_ast_view(command: str, typed_json: "Union[str, bytes, dict]") -> "list[AstView]":
    """Map one command's typed-JSON AST to bashlex-shaped `AstView` nodes.

    Args:
        command: the exact source string the parser was given (needed for
            source-text word parts and the full-span assertion).
        typed_json: `NativeBridge.parse_json` output — JSON text or the
            already-decoded dict.

    Returns:
        Top-level nodes, shaped like `bashlex.parse()` output.

    Raises:
        UnmappedNodeError: a construct without an explicit mapping (→ fallback).
        NativeBridgeError: malformed JSON, or a parse that covered only a
            prefix of the input (spec §3.1 full-span assertion).
    """
    if isinstance(typed_json, (str, bytes)):
        try:
            typed_json = json.loads(typed_json)
        except ValueError as exc:
            raise NativeBridgeError(f"native parser emitted malformed JSON: {exc}")
    if not isinstance(typed_json, dict) or typed_json.get("Type") != "File":
        got = f"Type={typed_json.get('Type')!r}" if isinstance(typed_json, dict) else type(typed_json).__name__
        raise UnmappedNodeError(f"expected a File root, got: {got}")

    source = command.encode("utf-8")
    if len(source) != len(command):
        # mvdan emits BYTE offsets; the walkers char-index the string, and a
        # mis-sliced segment is silently DROPPED by their bounds guard — the
        # under-block direction (panel CRIT, LAB-911 review; spec §4b).
        # Until T3 lands the byte→char conversion, non-ASCII input raises →
        # bashlex tier, whose offsets are already char-based.
        raise UnmappedNodeError("non-ASCII input needs byte→char offset conversion (T3); routing to fallback")

    try:
        parsed_end = typed_json["End"]["Offset"]
        if source[parsed_end:].strip():
            raise NativeBridgeError(
                f"native parse span ({parsed_end} bytes) does not cover the full input ({len(source)} bytes); "
                "a prefix parse is treated as failure"
            )
        stmts = typed_json.get("Stmts") or []
        if not stmts:
            raise NativeBridgeError("native parse produced no statements")
        return _Converter(command).stmts_to_nodes(stmts)
    except NativeBridgeError:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeDecodeError, RecursionError) as exc:
        # Structural drift in the typed-JSON (a field the binary stopped
        # emitting) must reach T5's router as a NativeBridgeError → bashlex
        # tier, not escape as a bare KeyError that hard-DENIES with no
        # context (panel MAJ, LAB-911 review). RecursionError joins them for the
        # same reason: deeply nested clauses (`if …; then` × 300) blow the Python
        # stack in the converter while bashlex parses them, so it is a bridge
        # failure to route, not a verdict (LAB-912 panel).
        raise NativeBridgeError(f"malformed typed-JSON structure: {exc!r}") from exc
