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


class TestPatternsDoNotBacktrackCatastrophically:
    """The git flag group nests quantifiers, so its branches are kept disjoint.

    The rejected path-keyed cut carried an ambiguous alternation in a lookahead and
    reached 12 SECONDS on a 247-character benign command -- on a hook with a ~1ms
    budget that runs on every bash call. These inputs are the ones that found it.
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


class TestDecoyPaddingFailsClosed:
    """Scanning past a suppressed match is bounded, and the bound denies.

    Without a bound, padding a quoted literal with decoy matches scales the cost
    of a hook that runs on every command. Exhausting the budget reports the last
    suppressed match rather than letting the padding buy an unrated command.
    """

    def test_heavily_padded_literal_is_not_silently_allowed(self, rules_dir_path):
        command = "echo '" + ("od ~/.ssh/id_rsa " * 200) + "' ; true"
        assert not verdict(command, rules_dir_path).allowed

    def test_a_modest_number_of_decoys_still_finds_the_real_read(self, rules_dir_path):
        command = "echo '" + ("od ~/.ssh/id_rsa " * 4) + "' ; nl ~/.ssh/id_ed25519"
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED
        assert "ssh_key_exfiltration" in result.matched_rules
