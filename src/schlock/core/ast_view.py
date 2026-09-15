r"""AstView: bashlex-shaped node views over `schlock-parse` typed-JSON.

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

T3 (this slice) lands the per-`WordPart` `Lit` unescape and the byte→char offset
conversion, so backslash escapes (`rm\ -rf\ /` → `rm -rf /`) and non-ASCII input
are now decoded to bashlex-equivalent `.word`/`.pos`, not refused.

Remaining ceilings — ALL fail closed by raising into the fallback tier (→ deny
under native-only, → bashlex under auto), so every one is strictly superset-safe
(the native tier reveals at most as much as it can decode, never less than
bashlex): ANSI-C `$'…'` raises — mvdan's typed-JSON does NOT decode it, so
mapping its raw value would under-decode vs real bash; decoding it to reveal MORE
danger than bashlex's own buggy `$x72x6d` is a follow-up, not a parity fix.
Constructs outside the 12-kind vocabulary — `if`/`for`/`while`/`case`, `[[ ]]`,
arithmetic `$(( ))`, array assignments, negation — also raise until the table is
widened; their dangerous variants still BLOCK (fail-closed deny), the safe ones
route to bashlex.
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


def _unescape_lit(value: str) -> str:
    """Reproduce bashlex's `.word` backslash-unescape for a `Lit` part (spec §4a).

    mvdan keeps escapes structural: the `Lit` value for `rm\\ -rf\\ /` is the raw
    `rm\\ -rf\\ /`, whereas bashlex's `.word` is already `rm -rf /`. Passing the
    raw form through defeats every rule keyed on the decoded command (the `:268`
    under-block), so this closes the gap by decoding the same way bashlex does.

    bashlex applies one uniform rule outside single quotes — INCLUDING inside
    double quotes (verified: `"a\\bar"` → `abar`, `"a\\$b"` → `a$b`): a backslash
    escapes the next character (the backslash is dropped, the character kept),
    `\\<newline>` is line continuation (both dropped), and a trailing backslash
    with nothing after it stays literal. Single-quoted content never reaches
    here — bash keeps its backslashes literal, so `WORD_PART_MAP` maps `SglQuoted`
    straight to its value. Matching bashlex exactly (not "more correct than bash")
    is deliberate: the migration invariant is never turning a bashlex BLOCK into
    an ALLOW, and identical decoding makes the superset oracle's word comparison
    exact rather than merely one-directional.
    """
    if "\\" not in value:
        return value
    out: list[str] = []
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n:
            nxt = value[i + 1]
            if nxt != "\n":  # line continuation drops both; every other escape keeps the char
                out.append(nxt)
            i += 2
        else:  # a lone trailing backslash is literal
            out.append(ch)
            i += 1
    return "".join(out)


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
        # mvdan emits BYTE offsets; the walkers char-index the original string
        # (`command[start:end]`, `command[start] == '"'`), so every offset this
        # converter puts on a node MUST be a code-point offset or a multibyte
        # command mis-slices and the mangled segment matches no rule → ALLOW
        # (spec §4b, panel CRIT #3).
        self._command = command
        # Fast path: for an all-ASCII command every byte IS its own code point,
        # so `_char` is the identity and there is no map to build — this covers
        # the overwhelming majority of commands and keeps the hot path allocation
        # free. `_b2c` is built only when a multibyte code point actually shifts
        # the offsets: it maps each byte offset that BEGINS a code point (plus the
        # end-of-input offset) to that code point's index, and `_char` rejects any
        # offset landing mid-character (fail closed).
        if command.isascii():
            self._b2c: Optional[dict[int, int]] = None
        else:
            b2c: dict[int, int] = {}
            byte = 0
            for char_index, ch in enumerate(command):
                b2c[byte] = char_index
                byte += len(ch.encode("utf-8"))
            b2c[byte] = len(command)
            self._b2c = b2c

    def _char(self, byte_offset: int) -> int:
        if self._b2c is None:  # all-ASCII: byte offset == code-point offset
            return byte_offset
        try:
            return self._b2c[byte_offset]
        except KeyError:
            # A boundary inside a multibyte code point means mvdan and this map
            # disagree about the source; denying the native tier is safer than
            # emitting an offset the walkers would mis-slice.
            raise NativeBridgeError(f"native byte offset {byte_offset} does not fall on a character boundary")

    def _cpos(self, node: dict) -> "tuple[int, int]":
        """A node's span as (start, end) CODE-POINT offsets, from its byte offsets."""
        return (self._char(node["Pos"]["Offset"]), self._char(node["End"]["Offset"]))

    def _slice(self, start: int, end: int) -> str:
        # start/end are code-point offsets (from `_cpos`); slice the original
        # string, not the encoded bytes.
        return self._command[start:end]

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
        offset = self._char(stmt["Semicolon"]["Offset"])
        op = "&" if stmt.get("Background") else ";"
        return AstView("operator", (offset, offset + len(op)), op=op)

    def _collapse_group(self, group: "list[tuple[AstView, Optional[AstView]]]") -> AstView:
        if len(group) == 1 and group[0][1] is None:
            return group[0][0]
        parts: list[AstView] = []
        for node, operator in group:
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
        for modifier in ("Negated", "Coprocess"):
            if stmt.get(modifier):
                # Dropping `!`/`coproc` would silently change what executes.
                raise UnmappedNodeError(f"unmapped statement modifier: {modifier}")
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
        node_type = cmd.get("Type")
        if node_type == "CallExpr":
            return self._convert_call(cmd, redirects)
        if node_type == "BinaryCmd":
            return self._convert_binary(cmd)
        if node_type in ("Subshell", "Block"):
            return _node(node_type, self._cpos(cmd), child=self.stmts_to_nodes(cmd.get("Stmts", [])))
        raise UnmappedNodeError(f"unmapped typed-JSON node type: {node_type}")

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
        start, end = self._cpos(cmd)
        if parts:
            start = min(start, parts[0].pos[0])
            end = max(end, *(p.pos[1] for p in parts))
        return _node("CallExpr", (start, end), child=parts)

    def _convert_binary(self, cmd: dict) -> AstView:
        op_code = cmd["Op"]
        if op_code not in BINARY_OPS:
            raise UnmappedNodeError(f"unmapped BinaryCmd op code: {op_code}")
        op_text, container_kind, separator_kind = BINARY_OPS[op_code]
        op_offset = self._char(cmd["OpPos"]["Offset"])
        separator_attr = {"operator": {"op": op_text}, "pipe": {"pipe": op_text}}[separator_kind]
        separator = AstView(separator_kind, (op_offset, op_offset + len(op_text)), **separator_attr)

        parts = [
            *self._binary_side(cmd["X"], container_kind),
            separator,
            *self._binary_side(cmd["Y"], container_kind),
        ]
        return AstView(container_kind, self._cpos(cmd), parts=parts)

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

    # -- words, assignments, redirects, word parts --------------------------

    def convert_word(self, word: dict) -> AstView:
        text, children = self._word_content(word)
        return _node("Word", self._cpos(word), child=children, word=text)

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
                # ANSI-C $'…' — mvdan's typed-JSON does NOT decode it (verified:
                # `$'\x72\x6d'` → Value `\x72\x6d`, raw), so mapping it to that
                # raw value would let native decode LESS than real bash. Raising
                # keeps the native tier fail-closed (→ deny under native-only,
                # → bashlex under auto): strictly superset-safe, never an
                # under-block. Decoding $'…' to reveal MORE danger than bashlex's
                # own buggy `$x72x6d` is a genuine improvement, not a parity fix,
                # and belongs in its own ticket (see the module docstring).
                raise UnmappedNodeError("ANSI-C quoted string ($'...') is not mapped yet")
            value = part.get("Value", "")
            if part_type == "Lit":
                # bashlex unescapes Lit text (`r\m` → `rm`, `rm\ -rf\ /` →
                # `rm -rf /`); the raw escaped form defeats every rule keyed on
                # the decoded command (spec §4a, the `:268` under-block).
                return _unescape_lit(value)
            return value  # SglQuoted: bash keeps backslashes literal — verbatim
        if handler == "quoted":
            return "".join(self._word_part_text(p) for p in part.get("Parts", []))
        return self._slice(*self._cpos(part))  # "source"

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
            return [_node("ParamExp", self._cpos(part), value=part["Param"]["Value"])]
        if part_type == "CmdSubst":
            inner = self.stmts_to_single_node(part.get("Stmts", []), "command substitution")
            return [_node("CmdSubst", self._cpos(part), child=inner)]
        # ProcSubst
        if part.get("Op") not in PROC_SUBST_OPS:
            raise UnmappedNodeError(f"unmapped ProcSubst op code: {part.get('Op')}")
        inner = self.stmts_to_single_node(part.get("Stmts", []), "process substitution")
        return [_node("ProcSubst", self._cpos(part), child=inner)]

    def convert_assign(self, assign: dict) -> AstView:
        if "Array" in assign or "Index" in assign or assign.get("Naked"):
            # a=(1 2 3) and friends are among T2c's 7 newly-parseable
            # constructs; their bashlex-equivalent shape is pinned there.
            raise UnmappedNodeError("array/indexed/naked assignment is not mapped yet")
        operator = "+=" if assign.get("Append") else "="
        value = assign.get("Value")
        if value is None:
            value_text, children = "", []
        else:
            value_text, children = self._word_content(value)
        word = assign["Name"]["Value"] + operator + value_text
        return _node("Assign", self._cpos(assign), child=children, word=word)

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
            hdoc_pos = self._cpos(redir["Hdoc"])
            # bashlex's heredoc value includes the terminator line; the source
            # slice reproduces that exactly (mvdan's End already covers it).
            attrs["heredoc"] = AstView("heredoc", hdoc_pos, value=self._slice(*hdoc_pos))
        return _node("Redir", self._cpos(redir), child=output, **attrs)


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
        except (ValueError, RecursionError) as exc:
            # RecursionError: the C scanner overflows on deep nesting (`$(`×20000 is
            # ~10 MiB, inside the output bound). Bare, it would skip T5's routing.
            raise NativeBridgeError(f"native parser emitted malformed JSON: {exc}")
    if not isinstance(typed_json, dict) or typed_json.get("Type") != "File":
        got = f"Type={typed_json.get('Type')!r}" if isinstance(typed_json, dict) else type(typed_json).__name__
        raise UnmappedNodeError(f"expected a File root, got: {got}")

    # mvdan emits BYTE offsets and the full-span check below compares against the
    # BYTE length; `_Converter` translates every node offset to a code-point
    # offset for the walkers (spec §4b). Non-ASCII input is handled, not refused.
    source = command.encode("utf-8")
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
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeDecodeError) as exc:
        # Structural drift in the typed-JSON (a field the binary stopped
        # emitting) must reach T5's router as a NativeBridgeError → bashlex
        # tier, not escape as a bare KeyError that hard-DENIES with no
        # context (panel MAJ, LAB-911 review).
        raise NativeBridgeError(f"malformed typed-JSON structure: {exc!r}") from exc
