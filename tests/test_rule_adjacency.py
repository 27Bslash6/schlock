"""LAB-4209: rules must key on the operation, not on literal command adjacency.

Two shapes of the same defect:

1. `git_force_push` and friends required `push` to sit adjacent to `git`, so every
   git global option (`-C <dir>`, `-c <k=v>`, `--no-pager`, ...) displaced the
   subcommand and dropped the match.
2. The credential rules named nine readers (`cat|less|head|tail|more|strings|
   base64|xxd|od`), so `nl`, `tac`, `sort`, `cut`, `rev`, `sed`, `awk` and
   `hexdump` read the same secret unrated -- and a glob named no file at all.

Every assertion here is an ABSOLUTE expected verdict, never "the attack rates the
same as the control": before this change both sides were equally broken, so a
parity assertion would have passed with the hole wide open.

The over-reach classes below are not decoration. An earlier cut of this change
keyed the credential rules on the PATH, guarded by a list of heads that cannot
emit file contents. It passed every attack test and still had to be thrown away,
because BLOCKED is unrelaxable by every preset and the guard denied `vim ~/.npmrc`,
`test -f ~/.ssh/id_rsa` and `echo 'add ~/.ssh/id_rsa to the agent'`. Those cases
are pinned here so the idea cannot come back unmeasured.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from schlock.core import validator
from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command
from schlock.integrations.commit_filter import MAX_COMMAND_SIZE


@pytest.fixture(autouse=True)
def _no_shellcheck(monkeypatch):
    """Pin verdicts to the rule/AST engine alone.

    ShellCheck independently elevates some of these, which would let a regression
    hide on any machine that has it installed.
    """
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def clean_worktree():
    """Report a clean tree to the hard-reset guard.

    That guard (validator.py) shells out to `git status --porcelain` and escalates
    to BLOCKED on a dirty tree, which would mask the rule-driven verdict these
    tests are about. It is unchanged by this ticket and keyed on cwd.
    """
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    with patch("subprocess.run", return_value=result):
        yield


def verdict(command, rules_dir_path):
    clear_caches()
    return validate_command(command, config_path=rules_dir_path)


# --------------------------------------------------------------------------
# Shape 1 -- git global options must not displace the subcommand
# --------------------------------------------------------------------------

# One entry per distinct form git's own parser accepts, verified against the
# binary: `-C` and `-c` take a SEPARATE value word (`-C.` and `-cuser.name=x`
# are rejected by git itself), `--git-dir` takes either `=` or a separate word,
# and a value may be quoted.
GIT_GLOBALS = [
    "--no-pager",  # boolean, long
    "-P",  # boolean, short
    "-C .",  # short flag + separate value
    "-c user.name=x",  # short flag + separate key=value
    "--git-dir=.git",  # long flag, attached value
    "--work-tree .",  # long flag, separate value
    "-C 'my dir'",  # single-quoted value containing a space
    '-C "my dir"',  # double-quoted value containing a space
    "-c user.name='Jane Doe'",  # bare run + quoted run in ONE shell word
    '-c user.name="Jane Doe"',  # same, double-quoted
    "-C ~/'my dir'",  # bare prefix + quoted suffix
    "-C . -c user.name=x --no-pager",  # several, mixed
]


class TestGitGlobalFlagsDoNotDisplaceSubcommand:
    """AC-1 / AC-2: the verdict follows the operation, not the spelling."""

    @pytest.mark.parametrize("globals_", GIT_GLOBALS)
    def test_force_push_is_high(self, globals_, rules_dir_path):
        result = verdict(f"git {globals_} push --force", rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert "git_force_push" in result.matched_rules

    @pytest.mark.parametrize("globals_", GIT_GLOBALS)
    def test_short_force_push_is_high(self, globals_, rules_dir_path):
        result = verdict(f"git {globals_} push -f", rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert "git_force_push" in result.matched_rules

    @pytest.mark.parametrize("globals_", GIT_GLOBALS)
    def test_hard_reset_is_high(self, globals_, rules_dir_path, clean_worktree):
        result = verdict(f"git {globals_} reset --hard", rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert "git_hard_reset" in result.matched_rules

    @pytest.mark.parametrize("globals_", GIT_GLOBALS)
    @pytest.mark.parametrize("blanket", ["add -A", "add --all", "add ."])
    def test_blanket_staging_is_high(self, globals_, blanket, rules_dir_path):
        result = verdict(f"git {globals_} {blanket}", rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert "git_blanket_staging" in result.matched_rules

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("git push --force", "git_force_push"),
            ("git reset --hard", "git_hard_reset"),
            ("git add -A", "git_blanket_staging"),
        ],
    )
    def test_control_keeps_its_verdict(self, command, rule, rules_dir_path, clean_worktree):
        """The unflagged spellings keep the verdicts they had before this change."""
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert rule in result.matched_rules


class TestGitGlobalFlagsDoNotOverReach:
    """The flag group must not swallow a pathspec or turn safe git into a finding."""

    @pytest.mark.parametrize(
        "command",
        [
            "git -C . status",
            "git -C . log --oneline",
            "git -C . diff",
            "git -C . merge-base HEAD main",
            "git -C . checkout -b feature",
            # An explicit pathspec bounds the sweep, so it is not blanket staging.
            "git -C . add src/foo.py",
            "git -C . add -A src/",
            # Patch mode confirms every hunk.
            "git -C . add -p",
        ],
    )
    def test_safe_git_stays_safe(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.SAFE

    @pytest.mark.parametrize("globals_", ["-C .", "-c user.name=x", "--no-pager"])
    def test_force_with_lease_is_never_force_push(self, globals_, rules_dir_path):
        """--force-with-lease is the safe alternative; the lookahead must survive."""
        result = verdict(f"git {globals_} push --force-with-lease", rules_dir_path)
        assert "git_force_push" not in result.matched_rules
        assert result.risk_level <= RiskLevel.MEDIUM

    def test_dangerous_git_config_still_blocks(self, rules_dir_path):
        """`git -c core.pager=...` is judged in Python against the parsed argument
        list, not by these patterns. Absorbing global flags must not disturb it."""
        assert not verdict("git -c core.pager=cat log", rules_dir_path).allowed


# --------------------------------------------------------------------------
# Shape 2 -- credential rules must not depend on which reader is used
# --------------------------------------------------------------------------

# Each of these prints a file's bytes exactly as `cat` does, and none of them was
# on the rule's original nine-name list.
ALTERNATE_READERS = [
    "nl",
    "tac",
    "sort",
    "rev",
    "tr a-z A-Z",
    "cut -c1-999",
    "sed -n 1,999p",
    "awk '{print}'",
    "hexdump -C",
    "fold",
    "paste",
    "cat",  # the one name the old rule did cover -- the control
    "od -c",  # word-anchoring must not lose a reader that genuinely starts with od
]


class TestCredentialRulesCoverEveryReader:
    """AC-3 / AC-4: the reader's name stops deciding the verdict."""

    @pytest.mark.parametrize("reader", ALTERNATE_READERS)
    def test_ssh_private_key_is_blocked(self, reader, rules_dir_path):
        result = verdict(f"{reader} ~/.ssh/id_rsa", rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED
        assert not result.allowed

    @pytest.mark.parametrize("reader", ALTERNATE_READERS)
    def test_aws_credentials_is_blocked(self, reader, rules_dir_path):
        result = verdict(f"{reader} ~/.aws/credentials", rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED
        assert not result.allowed

    @pytest.mark.parametrize(
        "command",
        [
            # A glob names neither "credentials" nor "id_rsa".
            "cat ~/.aws/*",
            "cat ~/.aws/c*",
            "nl ~/.aws/*",
            "cat ~/.ssh/*",
            "cat ~/.ssh/id_*",
            "sort ~/.ssh/*",
            "nl ~/.kube/*",
            "cat ~/.docker/*",
        ],
    )
    def test_glob_into_a_credential_directory_is_blocked(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "path",
        [
            "~/.npmrc",
            "~/.netrc",
            "~/.git-credentials",
            "~/.pypirc",
            "~/.docker/config.json",
            "~/.kube/config",
            "~/.aws/config",
            "~/.ssh/id_ed25519",
            "~/.ssh/identity",
        ],
    )
    def test_every_secret_path_is_reader_agnostic(self, path, rules_dir_path):
        """Whatever `cat <path>` rates, `nl <path>` must rate the same."""
        assert verdict(f"nl {path}", rules_dir_path).risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize("path", ["~/.ssh/config", "~/.ssh/known_hosts", "~/.ssh/authorized_keys"])
    def test_integrity_paths_keep_their_original_reader_list(self, path, rules_dir_path):
        """Deliberately NOT widened. These three are not secrets, and a BLOCKED read
        rule over them outranks the HIGH rules that own writing them -- which is the
        real threat. `sort -o ~/.ssh/authorized_keys k` must stay an approvable HIGH,
        not an unrelaxable deny."""
        assert verdict(f"cat {path}", rules_dir_path).risk_level == RiskLevel.BLOCKED
        assert verdict(f"nl {path}", rules_dir_path).allowed

    @pytest.mark.parametrize("separator", [";", "&&", "||", "|"])
    def test_reader_after_a_separator_is_blocked(self, separator, rules_dir_path):
        assert verdict(f"true {separator} nl ~/.ssh/id_rsa", rules_dir_path).risk_level == RiskLevel.BLOCKED


class TestWrappedReadersAreStillCaught:
    """Matching anywhere in the segment, not just at its start, is load-bearing.

    An earlier cut anchored at the segment start and exempted wrapper heads, which
    made every one of these invisible.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "kubectl exec pod -- cat /root/.ssh/id_rsa",
            "kubectl exec pod -- nl /root/.ssh/id_rsa",
            "docker exec c sort /root/.ssh/id_rsa",
            "docker exec c nl /root/.aws/credentials",
            "docker run -v /root:/h alpine nl /h/.ssh/id_rsa",
            "npm exec -- nl /root/.ssh/id_rsa",
            "ssh host nl /root/.ssh/id_rsa",
            "sudo nl ~/.ssh/id_rsa",
        ],
    )
    def test_wrapped_reader_is_blocked(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED


class TestCredentialRulesDoNotOverReach:
    """AC-5: the measured false-positive cost, pinned so it cannot drift.

    Every command here is SAFE or allowed on main. BLOCKED is unrelaxable by every
    preset, so a regression in this class is not a prompt -- it is an everyday
    command that can no longer be run at all.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # The SSH toolchain itself -- blocking these makes a non-default key
            # unusable, with no preset able to relax it.
            "ssh -i ~/.ssh/id_rsa user@host",
            "ssh -o IdentityFile=~/.ssh/id_rsa host",
            "ssh-add ~/.ssh/id_rsa",
            "ssh-keygen -lf ~/.ssh/id_rsa.pub",
            "GIT_SSH_COMMAND='ssh -i ~/.ssh/id_rsa' git fetch",
            # Permissions and metadata emit no file contents.
            "chmod 600 ~/.ssh/id_rsa",
            "chown me ~/.ssh/id_rsa",
            "ls -la ~/.ssh/id_rsa",
            "ls -la ~/.ssh/",
            "ls ~/.aws/",
            "stat ~/.aws/credentials",
            "test -f ~/.ssh/id_rsa",
            "find ~ -name .npmrc",
            # Editors and env plumbing.
            "vim ~/.npmrc",
            "nano ~/.aws/config",
            "export KUBECONFIG=~/.kube/config",
            "export AWS_CONFIG_FILE=~/.aws/config",
            # Each config file's own consumer, and the wider ecosystem the
            # exempt-head approach could never enumerate.
            "kubectl --kubeconfig ~/.kube/config get pods",
            "k9s --kubeconfig ~/.kube/config",
            "docker --config ~/.docker/config.json ps",
            "npm --userconfig ~/.npmrc ci",
            "ansible-playbook --private-key ~/.ssh/id_rsa site.yml",
            # Publishing a public key is the most common ~/.ssh operation there is.
            "cat ~/.ssh/*.pub",
            # Neither path is a credential file.
            "cat ~/.aws/README",
        ],
    )
    def test_legitimate_traffic_stays_allowed(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).allowed, command

    @pytest.mark.parametrize(
        "command",
        [
            "echo 'add ~/.ssh/id_rsa to the agent'",
            'echo "put your key at ~/.aws/credentials"',
        ],
    )
    def test_a_path_named_inside_a_quoted_string_is_not_a_read(self, command, rules_dir_path):
        """The engine suppresses matches that fall entirely inside a string literal.

        A pattern anchored at the segment start has its match START outside the
        quote, so suppression can never apply to it -- which is how the rejected
        path-keyed cut came to deny plain `echo`. Keeping the match at the reader
        token is what preserves this.
        """
        assert verdict(command, rules_dir_path).allowed

    def test_chmod_is_no_longer_caught_by_the_od_alternation(self, rules_dir_path):
        """`chmod 600 <key>` was BLOCKED on main: the unanchored `od` branch matched
        the tail of `chmo-d`. Word-anchoring removes that, and world-readable modes
        stay covered by chmod_777."""
        assert verdict("chmod 600 ~/.ssh/id_rsa", rules_dir_path).allowed
        assert verdict("chmod 777 ~/.ssh/id_rsa", rules_dir_path).risk_level == RiskLevel.HIGH

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            # Writing these is the threat, and it is owned at HIGH so a user can
            # approve it. A BLOCKED read rule must not mask that.
            ("rm ~/.ssh/known_hosts", "ssh_known_hosts_manipulation"),
            ("echo key > ~/.ssh/authorized_keys", "dotfile_persistence"),
        ],
    )
    def test_writes_to_integrity_paths_keep_their_own_rule(self, command, rule, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH
        assert rule in result.matched_rules

    def test_write_via_arg_to_authorized_keys_stays_high(self, rules_dir_path):
        assert verdict("sort -o /root/.ssh/authorized_keys k", rules_dir_path).risk_level == RiskLevel.HIGH

    @pytest.mark.parametrize(
        "command",
        [
            # One command, two operands, and a line break INSIDE the first one.
            # The first operand need not exist -- `cat` reports its error and
            # still emits the second file -- so this reads a real private key.
            'cat "ordinary\nfile" ~/.ssh/id_ed25519',
            'head "ordinary\nfile" ~/.ssh/id_rsa',
            "cat 'ordinary\nfile' ~/.ssh/id_rsa",
            'cat "ordinary\nfile" ~/.kube/config',
            'nl "ordinary\nfile" ~/.aws/credentials',
            'cat "ordinary\nfile" ~/.ssh/authorized_keys',
            # A backslash-escaped quote must not end the quoted span early --
            # same bypass, different spelling, and it is why the span carries an
            # escape branch rather than a plain `"[^"]*"`.
            'cat "a\\"b" ~/.ssh/id_ed25519',
            'cat "a\'b" ~/.ssh/id_rsa',
            "cat 'a\"b' ~/.ssh/id_rsa",
            'cat "" ~/.ssh/id_ed25519',
            # A backslash OUTSIDE quotes is an escape too. These carry a quote AS
            # WELL, and that pairing is what makes them load-bearing: a quote
            # creates string literals, which disables the validator's
            # reconstruction rescue, so the span is the only thing left. The
            # unquoted spelling `cat a\\ b <key>` is caught by reconstruction
            # either way and therefore pins nothing here.
            'cat "x y" a\\ b ~/.ssh/id_ed25519',
            'cat "a\nb" c\\ d ~/.ssh/id_ed25519',
            "cat 'x y' a\\ b ~/.ssh/id_ed25519",
            'cat a\\ b "x y" ~/.ssh/id_ed25519',
        ],
    )
    def test_a_quoted_newline_is_operand_data_not_a_boundary(self, command, rules_dir_path):
        """The counterpart of test_a_reader_does_not_reach_a_path_on_the_next_line.

        Both sides of one distinction, so neither fix can silently undo the other.
        Excluding EVERY newline from the span was the first attempt at that test
        and it lost a denial `main` had: a line break inside a quoted word is
        operand DATA, and adding one such argument was the whole bypass. The span
        now crosses a newline only inside a quoted span.
        """
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(
        "command",
        [
            # `config` continuing with a LETTER OR DIGIT names a different file.
            # Only these three stems had a real collision, and the boundary is on
            # those three only -- see the rule comment for why that restraint is
            # the point rather than an oversight.
            "cat ~/.kube/configmaps.yaml",
            "cat ~/.aws/configure-notes.md",
            "nl ~/.docker/configfile",
            # A directory segment must actually follow the slash.
            "cat ~/.kube/configs.yaml",
        ],
    )
    def test_a_path_that_merely_starts_like_config_is_not_a_credential(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).allowed, command

    @pytest.mark.parametrize(
        "command",
        [
            # Two innocent lines. The reader is on the first, the credential path
            # on the second, and neither command reads a secret.
            "head -5 notes.txt\nexport KUBECONFIG=~/.kube/config",
            "head -5 notes.txt\nls ~/.kube/config",
            "sort data.csv\nvim ~/.npmrc",
            "tail -2 log.txt\nssh -i ~/.ssh/id_rsa host",
        ],
    )
    def test_a_reader_does_not_reach_a_path_on_the_next_line(self, command, rules_dir_path):
        """The reader-to-path span must not cross a newline.

        `[^;|&]*` is a negated class and crosses one; the `.{0,200}` it replaced
        could not, because `.` is newline-free and `re.MULTILINE` does not change
        that. Widening the reader list turned that into a hard deny on ordinary
        two-line scripts -- including `export KUBECONFIG`, which the class above
        tests is allowed on one line.
        """
        assert verdict(command, rules_dir_path).allowed, command

    @pytest.mark.parametrize(
        "command",
        [
            "printf API_KEYBOARD",
            "echo API_KEYBOARD",
            "echo 'set your API_KEY in .env'",
            "echo Set the AWS_SECRET in vault",
            "echo PASSWORD reset instructions",
            # A colon FAR from the name is prose; a colon immediately after it is
            # an assignment and still rates, exactly as it does on main. Trying to
            # separate those two by requiring a redirect cost six real denials and
            # was reverted -- see the rule comment.
            'echo "TOKEN rotation: quarterly"',
        ],
    )
    def test_a_credential_name_in_prose_is_not_a_credential(self, command, rules_dir_path):
        """Every one of these was a hard deny at BLOCKED, which no preset relaxes."""
        assert verdict(command, rules_dir_path).allowed, command


class TestAQuotedOperandIsStillAnOperand:
    """A credential path is routinely written INSIDE a quoted word, and the
    reader-to-path span has to be able to stop there.

    Its four branches all consume WHOLE words -- a quoted branch demands its
    closing quote -- so the run alone could only ever end BETWEEN words. One
    quote character round the operand therefore hid the path from every one of
    these rules: `cat "$HOME/.ssh/id_ed25519"` rated SAFE with no matched rule,
    while the identical unquoted read was BLOCKED.

    `main` denied all of these, because the `.{0,200}` these branches replaced
    crossed a quote without caring. That makes it LOST protection, not an
    unclosed hole, and it is why the span now carries an unterminated tail.
    """

    # Every credential path this file owns, in the spellings bash accepts
    # for the same read. `~` is NOT expanded inside quotes, so the quoted tilde
    # forms are inert in a real shell -- `$HOME` and an absolute path are the
    # spellings that actually reach the secret, and both are pinned here.
    QUOTED_READS = [
        'cat "$HOME/.ssh/id_ed25519"',
        "cat '/home/u/.ssh/id_ed25519'",
        'nl "$HOME/.ssh/id_rsa"',
        'cat "/home/u/.kube/config"',
        'cat "$HOME/.npmrc"',
        'cat "$HOME/.netrc"',
        "cat '$HOME/.git-credentials'",
        'jq . "$HOME/.docker/config.json"',
        'cat "$HOME/.ssh/config"',
        # The quote need not wrap the whole word. This one is SAFE at the PR
        # head, so it discriminates; three earlier attempts at this case did
        # not -- `cat ~/".ssh/id_ed25519"` is rescued by the validator's
        # reconstruction pass, `"$HOME"'/.ssh/id_rsa'` is owned by
        # `credential_exposure`, and `cat ~/".npmrc"` was already BLOCKED.
        "nl \"$HOME\"'/.kube/config'",
        # An escaped quote INSIDE the credential word. The tail carries the same
        # escape branch as the run above it for exactly this, and the asymmetry
        # would be a one-character bypass: a plain `"[^"]*` tail ends at the
        # ESCAPED quote and dies before the path. Note the paths -- `id_rsa` and
        # `.aws/credentials` are covered by sibling rules whatever the span does,
        # so they pin nothing here and only these spellings kill the mutant.
        'cat "$HOME/a\\"b/.ssh/id_ed25519"',
        'cat "x\\"y/.kube/config"',
        'head "a\\"b/.npmrc"',
        # The span still has to get PAST earlier operands to reach this one.
        # `id_ed25519`, NOT `id_rsa`: the legacy `credential_exposure` pattern
        # matches `id_rsa` with its own `.{0,200}` run, so an `id_rsa` case here
        # stays BLOCKED however badly the span is broken and pins nothing.
        'cat "a b" "$HOME/.ssh/id_ed25519"',
        "cat 'a b' \"$HOME/.ssh/id_ed25519\"",
        'cat a\\ b "$HOME/.ssh/id_ed25519"',
        'cat "a\nb" "$HOME/.ssh/id_ed25519"',
        'cat "a\\"b" "$HOME/.ssh/id_ed25519"',
        'cat -- "$HOME/.ssh/id_ed25519"',
    ]

    @pytest.mark.parametrize("command", QUOTED_READS)
    def test_a_quoted_credential_operand_is_blocked(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(
        "command",
        [
            # BALANCED quotes. These pin nothing on their own -- the run consumes
            # the quoted word whole and the tail never engages -- but they are the
            # control the cases below are read against. `ls` emits no contents.
            'cat "x" ; ls ~/.kube/config',
            "cat 'x' ; ls ~/.npmrc",
            'cat "x" && ls ~/.netrc',
            'cat "x" | ls ~/.pypirc',
            # UNPAIRED quotes, which is where the tail actually runs -- and an
            # apostrophe in ordinary prose is the everyday way to write one.
            # `it's` opens the tail; what stops it reaching a path further along
            # is that its interior excludes WHITESPACE, because a shell word has
            # none unquoted and staying inside one word is the tail's whole job.
            #
            # Two earlier cuts got this wrong in instructive ways. The first let
            # the interior cross anything, so these were hard denials at BLOCKED
            # on commands that read nothing. The second excluded only `;`, `|`,
            # `&` and a newline -- which covers the cases that happen to cross a
            # separator and MISSES `# it's the .npmrc problem`, which crosses
            # none. Both spellings are pinned here so neither cut can return.
            "head -5 notes.txt  # check what's here\nexport KUBECONFIG=~/.kube/config",
            "sed -n 1p a.txt # it's ok ; ls ~/.kube/config",
            "sort -u hosts.txt # we're deduping\nls -l ~/.kube/config",
            "echo hi # sort of odd, don't\nls ~/.npmrc",
            "cut -d= -f2 .env.example # don't edit\nexport KUBECONFIG=~/.kube/config",
            # No separator crossed at all -- only whitespace.
            "head -20 build.log  # it's the .npmrc problem",
            # TWO apostrophes, on DIFFERENT lines, pairing as one quoted span so
            # the RUN (not the tail) crosses the line break between them. The
            # run's single-quoted branch will not open on a quote inside a word,
            # which is what tells `we're` from `cat 'a b'`.
            "sort -u hosts.txt # we're deduping\n# don't edit ~/.kube/config",
            "head -20 build.log  # it's noisy\necho done  # don't forget ~/.npmrc",
            "cut -c1-80 log.txt # user's notes\n# isn't ~/.ssh/id_ed25519 the key",
            "nl README.md  # we don't commit ~/.npmrc",
            "cut -c1-80 log.txt  # user's ~/.kube/config is fine",
            'head -5 log.txt  # size is 5" wide ~/.npmrc',
        ],
    )
    def test_the_tail_stays_inside_one_shell_word(self, command, rules_dir_path):
        """A stray apostrophe must not turn a reader plus a later path into a deny."""
        assert verdict(command, rules_dir_path).allowed, command

    @pytest.mark.parametrize(
        "command",
        [
            # `&` inside `"..."` can never be a separator, and these are ordinary
            # directory names. Excluding it from the tail cost every one of them
            # a denial `main` had.
            'cat "$HOME/R&D/.kube/config"',
            'cat "$HOME/Dev&Ops/.npmrc"',
            'cat "$HOME/Q&A/.netrc"',
            # The tail is bounded as ReDoS insurance, not as a coverage limit.
            # At 200 this deep absolute path went unrated while `main` denied it.
            'cat "/' + "d" * 199 + '/.ssh/id_ed25519"',
        ],
    )
    def test_the_tail_reaches_a_realistic_path(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(
        "command",
        [
            # Reaching into a quoted operand also reaches a quoted `.pub`, and
            # the guard has to survive the trip: these are PUBLIC keys and were
            # hard denials on `main`, where the guard's `(?:\s|$)` never fired
            # because a quote sat where it wanted whitespace.
            'cat "~/.ssh/id_rsa.pub"',
            "cat '~/.ssh/id_rsa.pub'",
            'nl "$HOME/.ssh/id_ed25519.pub"',
            "base64 '/home/u/.ssh/id_ecdsa.pub'",
        ],
    )
    def test_a_quoted_public_key_is_allowed(self, command, rules_dir_path):
        """The guard ends at `["']?(?:\\s|$)` -- an optional quote that must
        STILL be followed by whitespace or end. Dropping the `(?:\\s|$)` and
        accepting a bare quote is what let `.pub''` disarm it mid-brace, which
        the test above pins."""
        assert verdict(command, rules_dir_path).allowed, command

    @pytest.mark.parametrize(
        "command",
        [
            # A `.pub` appended inside a brace expansion disarms the guard for a
            # DIFFERENT expanded word: this is `~/.ssh/id_rsa` plus `~/.ssh/.pub`,
            # and `cat` prints the private key. Pinned because an earlier cut of
            # this change let the guard end at a quote, which made the trailing
            # `''` satisfy it -- a lost denial `main` did not have.
            "cat \"x\" ~/.ssh/{id_rsa,.pub''}",
            "cat \"x\" ~/.ssh/{id_ed25519,.pub''}",
            'cat "x" ~/.ssh/{id_rsa,"y.pub"}',
            "cat \"x\" ~/.aws/{credentials,.pub''}",
        ],
    )
    def test_a_quoted_pub_in_a_brace_expansion_does_not_disarm_the_guard(self, command, rules_dir_path):
        """The leading quoted operand matters: it creates a string literal, which
        disables the validator's reconstruction rescue and leaves the pattern as
        the only cover."""
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command


class TestTheBoundaryDoesNotUnrateARealFile:
    """The other side of the boundary above, and the load-bearing one.

    A boundary tightened one notch too far fails SILENTLY: the rule keeps matching
    the canonical spelling nobody exfiltrates. Two notches were measured and
    rejected -- a whole-token `(?![^\\s;|&])` unrates every backup and
    per-environment copy, and applying `(?![A-Za-z0-9])` to names with no measured
    collision unrated `.ssh/authorized_keys2` and `.ssh/known_hosts2`, which are
    canonical OpenSSH files named in sshd_config's own default AuthorizedKeysFile.

    Each case asserts the RULE, not just the verdict: several of these paths are
    independently denied by a sibling rule, so a bare `not allowed` would pass with
    this rule's branch deleted.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # A separator continuation is the same secret under another name.
            "cat ~/.kube/config-prod",
            "cat ~/.kube/config.bak",
            # A pluralised directory holds the same secret as the file.
            "cat ~/.kube/configs/prod",
            "nl ~/.docker/configs/a.json",
            "nl ~/.npmrc_old",
            # The real Docker file IS the suffixed spelling.
            "cat ~/.docker/config.json",
            # Names that never had a measured collision keep no boundary at all.
            "cat ~/.ssh/authorized_keys2",
            "less ~/.ssh/known_hosts2",
            "cat ~/.npmrcnotes",
        ],
    )
    def test_a_suffixed_credential_path_still_blocks(self, command, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED, command
        assert "extended_credential_exposure" in result.matched_rules, command


class TestACredentialNameNeedsAPosition:
    """A credential name rates in exactly three positions, and each is measured.

    Dropping any one of them was tried and cost a real denial, so the branches are
    pinned separately rather than as one list.
    """

    @pytest.mark.parametrize(
        "command",
        ["echo ${PASSWORD}", "printf '%s' \"$API_KEY\"", "echo $MY_TOKEN_VALUE"],
    )
    def test_expanded(self, command, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert "extended_credential_exposure" in result.matched_rules, command

    @pytest.mark.parametrize(
        "command",
        [
            # Inside a double-quoted `$(...)` the substitution validator runs the inner
            # command against the rules before any top-level pattern is consulted
            # (LAB-4182), so the denial is attributed to environment_credential_extraction
            # matching `printenv <NAME>`.
            'echo "$(printenv GITHUB_TOKEN)"',
            'printf "%s" "$(printenv AWS_SECRET_ACCESS_KEY)"',
            'echo "Bearer $(printenv GITHUB_TOKEN)"',
        ],
    )
    def test_substituted(self, command, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level is RiskLevel.BLOCKED, command
        assert "environment_credential_extraction" in result.matched_rules, command

    @pytest.mark.parametrize(
        "command",
        [
            # Writing a plaintext secret to a file. hardcoded_secrets matches a
            # lowercase `key` only, so nothing else covers the uppercase name.
            'echo "API_KEY=abc123" > .env',
            'echo "API_KEY = abc123" > .env',
            'echo "AWS_SECRET_ACCESS_KEY: abc" >> config.yml',
            "printf 'PASSWORD: %s\\n' hunter2 > creds.yml",
            # JSON, the other way an agent writes a config file.
            'echo \'{"API_KEY":"sk-x"}\' > c.json',
            'echo \'{"API_KEY": "sk-x"}\' > c.json',
        ],
    )
    def test_assigned(self, command, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert "extended_credential_exposure" in result.matched_rules, command

    @pytest.mark.parametrize(
        "command",
        [
            # A redirect BEFORE the credential argument.
            'echo > c.yml "API_KEY: sk-x"',
            'printf > c.yml "API_KEY: sk-x"',
            # A separator inside the quoted VALUE, which is data, not structure.
            'echo "API_KEY: sk;x" > c.yml',
            'echo "API_KEY: sk|x" > c.yml',
            'echo "API_KEY: sk&x" > c.yml',
            # Bash's combined output redirect.
            'echo "API_KEY: sk-x" &> c.yml',
        ],
    )
    def test_assigned_however_the_redirect_is_spelled(self, command, rules_dir_path):
        """Source-text order is not redirect structure.

        Requiring a later `>` reachable without crossing `;|&` looked like it
        distinguished a write from prose. It does not: each of these writes a
        plaintext credential exactly as `echo "API_KEY: sk-x" > c.yml` does, and
        every one of them walked through that qualifier while the control stayed
        BLOCKED. A pattern cannot see a parsed redirect, so it must not pretend to.
        """
        result = verdict(command, rules_dir_path)
        assert "extended_credential_exposure" in result.matched_rules, command


@pytest.mark.slow
class TestUnanchoredSearchStaysLinear:
    """Per-word parsing being unambiguous does NOT make the search linear.

    The git patterns are unanchored by design, so `sudo git push --force` rates.
    That means `git` appearing inside an argument -- `-C git`, a directory
    literally called git -- starts another candidate match, and an unbounded
    option group greedily consumed the whole remaining suffix from every one of
    them: O(n) starts x O(n) scan. The earlier linearity checks all fed ONE start
    position, which is why they missed it. The option run is now bounded, so a
    failed search gives up after a fixed number of options.
    """

    # n is load-bearing. The regression is quadratic and the fix is linear, so the
    # gap between them grows with n while the spread between the machines running
    # this does not -- and until the gap wins, no constant can tell a slow runner
    # from a restored O(n^2). One dev box, 3.9, bounded vs the same rules with the
    # {0,16} option bound removed:
    #     n= 512   0.44s vs  1.22s   2.8x   <- under the ~3x CI/local spread
    #     n=1024   0.80s vs  3.80s   4.8x
    #     n=2048   1.36s vs 13.61s  10.0x
    # The absolute times are that box's; the ratios are the part that transfers.
    # 512 is why the old 1.0s budget could both false-fail a correct run (CI
    # measured 1.0013s) and let the unbounded mutant through.
    ADVERSARY = "git" + " -c user.name=x' y' -C git" * 2048 + " status"

    @pytest.mark.parametrize(
        "operation",
        ["push --force", "reset --hard", "add -A", "push -f", "rebase", "commit -m x"],
    )
    def test_many_candidate_starts_stay_fast(self, operation, rules_dir_path, clean_worktree):
        """Every rule carrying the option group, not just the one that found it."""
        command = self.ADVERSARY.replace(" status", " " + operation)
        # LAB-4363 refuses anything over MAX_COMMAND_SIZE before it reaches a rule,
        # and n=2048 sits at ~53 KB of a 64 KB ceiling. Raise n past it and this
        # would time a size refusal instead of a search, staying green whatever the
        # patterns did -- the silent-guard failure this whole class is about.
        assert len(command) < MAX_COMMAND_SIZE, f"adversary is {len(command)}B, past the pre-parse ceiling"
        start = time.perf_counter()
        verdict(command, rules_dir_path)
        # Verified by mutation, not by extrapolation: drop the {0,16} option bound
        # from data/rules/10_development_workflows.yaml and this must go red. Under
        # `pytest --cov` on 3.9, mutant 11.25-14.08s against bounded 1.45-1.60s.
        # Re-run that when you change this number -- per-call overhead is a fixed
        # ~0.36s on top of a term linear in n, so scaling either column in your head
        # gets it wrong in both directions.
        #
        # At the old n=512 the mutant passed, and so did both siblings:
        # test_cost_grows_linearly_not_quadratically clears its own ceiling by 1.5%
        # on it, so nothing here is a backstop for this case. CI runs this class on
        # both matrix legs -- the workflow passes no `-m` deselect -- and only a
        # local `-m "not slow"` skips it.
        assert time.perf_counter() - start < 10.0

    def test_cost_grows_linearly_not_quadratically(self, rules_dir_path):
        """A quadratic scan quadruples per doubling; a linear one doubles.

        Pinned loosely -- the point is the exponent, not the constant."""

        def elapsed(n):
            command = "git" + " -c user.name=x' y' -C git" * n + " status"
            start = time.perf_counter()
            verdict(command, rules_dir_path)
            return time.perf_counter() - start

        small = min(elapsed(256) for _ in range(3))
        large = min(elapsed(1024) for _ in range(3))
        # 4x the input: linear predicts ~4x, quadratic ~16x.
        assert large < small * 9, f"{small:.4f}s -> {large:.4f}s looks superlinear"

    def test_credential_prefix_cost_stays_polynomial(self, rules_dir_path):
        """`[^;|&]*` before an alternation is QUADRATIC on a path it never satisfies.

        That predates this change and measures the same at 608e4b8; adding the
        `config` boundary only moved prefix-shaped paths onto the same curve. So
        this pins the exponent that actually matters -- quadratic is the ceiling,
        exponential is the failure -- rather than claiming a linearity the pattern
        does not have.
        """

        def elapsed(n):
            command = "cat " + "~/.kube/configura" * n
            start = time.perf_counter()
            verdict(command, rules_dir_path)
            return time.perf_counter() - start

        small = min(elapsed(100) for _ in range(3))
        large = min(elapsed(400) for _ in range(3))
        # 4x the input: quadratic predicts ~16x. Anything near exponential blows
        # past this by orders of magnitude.
        assert large < small * 40, f"{small:.4f}s -> {large:.4f}s is worse than quadratic"


@pytest.mark.slow
class TestPatternsDoNotBacktrackCatastrophically:
    """The git flag group nests quantifiers, so its branches are kept disjoint.

    The rejected path-keyed cut carried an ambiguous alternation in a lookahead and
    reached 12 SECONDS on a 247-character benign command -- on a hook with a ~1ms
    budget that runs on every bash call. These inputs are the ones that found it.

    The credential alternation is covered here too. `[^;|&]*` followed by an
    alternation is QUADRATIC on any path the alternation never satisfies, and
    adding the `(?![A-Za-z0-9])` boundary moved prefix-shaped paths onto that
    curve: measured 28ms at 6.4 KB, against 31ms for a path that never matched on
    either side -- the same curve, not a new one, and 0.02ms at a realistic 68
    characters. A test that only exercised the git group could not see this.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "git " + "-a " * 60 + "nomatch",
            "git " + "-a v " * 40 + "nomatch",
            "git " + "-c a=b " * 40 + "nomatch",
            "git " + '-c a="x y" ' * 30 + "nomatch",
            "git " + "-" * 200 + " push",
            'A="x B=y" ' * 24 + "echo hi",
            "nl " + "x" * 400 + " ~/.ssh/nomatch",
            " " * 300 + "nl ~/.ssh/nomatch",
            # A `config` stem that starts to match and never closes, at every one
            # of 200 positions. Instant before the boundary existed.
            "cat " + "~/.aws/configura" * 200,
            "nl " + "~/.kube/configm" * 200,
            # The same shape for the credential-name alternation.
            "echo " + "API_KEYBOARD_" * 200,
        ],
    )
    def test_pathological_input_terminates(self, command, rules_dir_path):
        start = time.perf_counter()
        verdict(command, rules_dir_path)
        # Exponential backtracking takes seconds to forever; a linear scan of a few
        # hundred characters is sub-millisecond. One second is slack, not a target.
        assert time.perf_counter() - start < 1.0


class TestSuppressedMatchCannotHideALaterRead:
    """An inert quoted decoy must not silence the rule.

    `match_command` searched each pattern once; when that first match fell inside
    a string literal the skip abandoned the whole pattern, so a real match later
    in the SAME segment was never looked for. Consolidating several per-path
    patterns into one made a decoy enough to silence the rule outright. The
    semicolons below sit inside ordinary quoted arguments, not separators, so
    each of these is one segment and one search.
    """

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("env -u 'cat ~/.ssh/identity;' head ~/.ssh/id_ed25519", "ssh_key_exfiltration"),
            ("env -u 'nl ~/.npmrc;' cat ~/.netrc", "extended_credential_exposure"),
            ("echo 'nl ~/.aws/credentials' && nl ~/.ssh/id_rsa", "ssh_key_exfiltration"),
        ],
    )
    def test_decoy_does_not_suppress_the_real_read(self, command, rule, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED
        assert rule in result.matched_rules

    def test_a_decoy_alone_is_still_suppressed(self, rules_dir_path):
        """The scan must not un-suppress quoted text -- only look past it."""
        assert verdict("env -u 'cat ~/.ssh/identity;' true", rules_dir_path).allowed


class TestReaderNameVersusReaderUse:
    """Known, accepted false positives, and the evasions that fixing them would buy.

    `nl` is a plausible username and a plausible literal argument, so these three
    are rated as reads. Guarding them with a lookbehind on the preceding token was
    implemented and reverted: an attacker controls that token too, so every such
    guard is a one-token bypass. These assertions record the trade deliberately --
    if a future change makes them allowed, check it did not also unrate the
    evasions pinned below.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "ssh -l nl -i ~/.ssh/id_ed25519 host",
            "chown nl ~/.ssh/id_ed25519",
            "printf '%s' nl ~/.aws/credentials",
        ],
    )
    def test_reader_name_as_a_data_word_is_rated(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command",
        [
            "foo 'x' cat ~/.ssh/id_rsa",  # a quote guard would unrate this
            "env -i cat ~/.ssh/id_rsa",  # a short-flag guard would unrate this
        ],
    )
    def test_the_evasions_those_guards_would_buy_stay_blocked(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command",
        [
            "nl ~/.ssh/id_ed25519.pub",  # a public key is not a secret
            "tee ~/.kube/config < config.yaml",  # writes the file, does not read it
        ],
    )
    def test_public_keys_and_write_operands_are_not_reads(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).allowed

    @pytest.mark.parametrize(
        "command",
        [
            # `split` and `csplit` LOOK like writers and are not: the operand is
            # the INPUT file, copied into shards an attacker then reads.
            "split -b 1m ~/.ssh/id_rsa /tmp/k",
            "csplit -f /tmp/p ~/.ssh/id_ed25519 5",
            "split -l 100 ~/.aws/credentials",
        ],
    )
    def test_shard_writers_still_read_their_operand(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED


class TestKeyNamesAndPublicKeys:
    """Key files are not named uniformly, and a public key is not a secret.

    An earlier cut used `\\b` to force the `id_` stem to its maximal length. `_` is
    a word character, so no prefix could ever satisfy the boundary and the branch
    died outright for every name that continues past the stem -- including
    `id_ed25519_sk`, an ssh-keygen default, and the standard multi-account names.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/id_ed25519_sk",
            "~/.ssh/id_ed25519_work",
            "~/.ssh/id_rsa_github",
            "~/.ssh/id_ecdsa_old",
            "~/.ssh/id_dsa_backup",
            "~/.ssh/identity",
            "~/.ssh/identity_work",
        ],
    )
    def test_every_private_key_spelling_is_blocked(self, path, rules_dir_path):
        assert verdict(f"nl {path}", rules_dir_path).risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize("reader", ["cat", "nl", "head", "base64"])
    @pytest.mark.parametrize("path", ["~/.ssh/id_rsa.pub", "~/.ssh/id_ed25519.pub"])
    def test_public_keys_are_allowed_for_every_reader(self, reader, path, rules_dir_path):
        """Reader-dependent verdicts on the same file are the defect this ticket
        exists to remove, so the legacy cat-only rule gets the same exclusion."""
        assert verdict(f"{reader} {path}", rules_dir_path).allowed

    @pytest.mark.parametrize(
        "command",
        [
            # Appending a `.pub` must not disarm the guard for the whole word.
            "cat ~/.ssh/{*,*.pub}",
            "cat ~/.ssh/{id_rsa,x.pub}",
            "nl ~/.ssh/{id_ed25519,readme.pub}",
        ],
    )
    def test_a_pub_suffix_elsewhere_in_the_word_does_not_disarm_the_guard(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED

    def test_a_glob_that_only_matches_public_keys_is_allowed(self, rules_dir_path):
        assert verdict("cat ~/.ssh/*.pub", rules_dir_path).allowed


class TestDecoyPaddingIsScannedExactly:
    """The scan past a suppressed match is EXACT -- it never gives up early.

    A bound here looks like cheap insurance and is not. An earlier cut capped the
    rescan and reported the last SUPPRESSED match on exhaustion, reasoning that
    padding should buy a denial. It denies benign text instead: a quoted doc
    listing many install lines. It also under-blocked while `validate_command`
    ran its cross-segment scan only when no segment matched; that scan now runs
    whatever the segments matched, so a bogus segment match no longer hides the
    BLOCKED. Returning None on exhaustion is no better -- then padding silences
    the rule.

    Pinned below at 40 repeats, past where the cap sat. The over-block test is
    what pins the last-suppressed-match bound; nothing here pins a bound that
    returns None, because the fork bomb matches on its first iteration.
    Found by adversarial review of this branch (LAB-4321 / PR #170, whose
    rules.py this file's engine change is byte-identical to).
    """

    def test_padding_does_not_hide_a_cross_segment_block(self, rules_dir_path):
        """The under-block, and the serious one: a fork bomb behind the padding.

        `_segment_nodes` fragments `:(){ :|:& };:` into inert `:` segments, so the
        whole-command scan is the ONLY thing that can see it. That scan runs
        whatever the segments matched, so this is the end-to-end contract rather
        than the guard on the bound.
        """
        padded = "echo '" + ("pip install -r requirements.txt " * 40) + "' && :(){ :|:& };:"
        assert not verdict(padded, rules_dir_path).allowed

    def test_padding_does_not_deny_inert_text(self, rules_dir_path):
        """The over-block: a quoted doc listing many install lines is not a command."""
        assert verdict("echo '" + ("sudo apt-get install -y pkg " * 40) + "'", rules_dir_path).allowed

    def test_a_modest_number_of_decoys_still_finds_the_real_read(self, rules_dir_path):
        command = "echo '" + ("od ~/.ssh/id_rsa " * 4) + "' ; nl ~/.ssh/id_ed25519"
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED
        assert "ssh_key_exfiltration" in result.matched_rules
