r"""Reader-to-path runs stay linear in the number of reader words.

A pattern such as `(cat|less)\s+[^;|&]*\.pgpass` is tried again at every `cat` in
the command, and an unbounded run scanned to the end of the command from each one:
O(n) starts times O(n) scan. Padding of `cat x ` or `cat $(x) ` puts a start every
few bytes, so the cost grew with the square of the command's length. The runs are
bounded now; the YAML note on database_credential_theft in
data/rules/03_credential_theft.yaml carries the why.

The timing sweep takes every rule from the engine rather than a list, so a revert
or a new unbounded run anchored on `cat` fails wherever it lands. It sees only runs
the two padding units exercise: a run anchored on another word, or an inner run
behind a literal neither unit contains, never executes. The static check pins
every run in the rules bounded here, whatever anchors it. Both run at the regex
layer: validating a large command also pays a linear parse cost that would blur
the signal.
"""

import re
import time
from pathlib import Path

import pytest

from schlock.core.rules import RuleEngine
from schlock.core.validator import RiskLevel, validate_command

RULES_DIR = Path(__file__).parent.parent / "data" / "rules"
PATTERNS = RuleEngine(str(RULES_DIR)).compiled_patterns

UNITS = {"cat_x": "cat x ", "cat_substitution": "cat $(x) "}

# Still unbounded. Strict, so the day they are bounded this goes red and the
# exemption has to be deleted rather than left to hide a later regression.
TRACKED_SEPARATELY = {"extended_credential_exposure", "ssh_key_exfiltration"}

# The runs' bound, and the smallest input where every bounded start pays all of it.
BOUND = 200
SMALL = 10 * BOUND

# A linear rule costs ~4x on 4x the input and an unbounded run ~16x. The slack
# absorbs timer noise on rules that finish in microseconds, and sits well under
# what one restored unbounded run costs at 4 * SMALL.
RATIO = 5
NOISE = 0.001

# A reader run and its quantifier, e.g. `[^;|&]{0,200}`.
RUN = re.compile(r"\[\^;\|&\](\*|\+|\{\d*,\d*\})")

# The one run with a wider bound: aws_credential_theft's lookahead for the session
# name, where a bound fails toward denying. See data/rules/12_cloud_security.yaml.
SESSION_NAME_LOOKAHEAD = r"(?!\s+[^;|&]{0,1000}--role-session-name)"


def _cost(patterns, text):
    # CPU time, not wall time. On a busy runner a measurement longer than a
    # scheduler slice gets preempted and a shorter one does not, which inflates
    # the ratio of two wall-clock readings. Measured: one run in three failed.
    start = time.process_time()
    for pattern in patterns:
        pattern.search(text)
    return time.process_time() - start


def _rule_params():
    for rule in PATTERNS:
        if rule in TRACKED_SEPARATELY:
            reason = "reader span tracked separately; delete this exemption once it is bounded"
            yield pytest.param(rule, marks=pytest.mark.xfail(strict=True, reason=reason))
        else:
            yield rule


@pytest.mark.slow
@pytest.mark.parametrize("unit", list(UNITS.values()), ids=list(UNITS))
@pytest.mark.parametrize("rule", list(_rule_params()))
def test_cost_is_linear_in_reader_density(rule, unit):
    """4x the padding may cost about 4x the time, never the 16x of an unbounded run.

    Neither unit contains a credential path, so `search()` never exits early: this
    measures the full failed attempt, which is the case padding gets to choose. The
    minimum of several runs discards scheduler noise, which only ever adds time.
    """
    patterns = PATTERNS[rule]
    small_text = unit * (SMALL // len(unit))
    large_text = small_text * 4

    small = min(_cost(patterns, small_text) for _ in range(5))
    large = min(_cost(patterns, large_text) for _ in range(3))

    assert large <= RATIO * small + NOISE, f"{rule}: {small * 1000:.2f}ms -> {large * 1000:.2f}ms on 4x the input"


# The path starts exactly BOUND characters after the blank that ends the reader
# word, the far edge of the run. Each spelling is one no earlier rule claims, so
# matched_rules names the rule under test rather than a sibling that also denies it.
# `(rule, reader, lead, rest)`: the run spans the padding, one blank and `lead`.
WITHIN_BOUND = [
    ("database_credential_theft", "cat", "~/", ".pgpass"),
    ("git_credential_theft", "cat", "~/", ".config/gh/hosts.yml"),
    ("ssh_agent_abuse", "cat", "$", "SSH_AUTH_SOCK"),
    ("macos_keychain_theft", "cat", "~/", "Library/Keychains/login.keychain-db"),
    ("linux_keyring_theft", "cat", "~/", ".local/share/keyrings/login.keyring"),
    # Its reader-and-redirect spellings are all claimed first by protect_system_files.
    ("dns_hijacking", "nmcli", "con mod eth0 ipv4.", "dns 1.1.1.1"),
    ("aws_credential_theft", "cp", "", "~/.aws/credentials /tmp/"),
    ("gcp_credential_theft", "cat", "~/.config/gcloud/", "application_default_credentials.json"),
    ("azure_credential_theft", "cat", "~/", ".azure/accessTokens.json"),
    ("browser_credential_theft", "cp", "~/", ".config/google-chrome/Default/Cookies /tmp/"),
    ("browser_local_storage_theft", "cat", "~/.config/", "google-chrome/Default/leveldb/000003.log"),
    ("electron_app_token_theft", "cat", "~/.config/", "Slack/storage/x"),
    ("cloud_cache_theft", "cat", "~/", ".kube/cache/discovery/x"),
    ("package_manager_token_theft", "cat", "~/", ".cargo/credentials"),
]


@pytest.mark.parametrize("rule", [row[0] for row in WITHIN_BOUND])
def test_every_run_carries_the_bound(rule):
    """Each run in these rules is `{0,BOUND}`: not unbounded, not wider, not narrower.

    The timing sweep cannot see a run it never executes, and a wider bound stays
    linear, so it passes there too. This reads the bound off the pattern instead.
    """
    sources = [pattern.pattern.replace(SESSION_NAME_LOOKAHEAD, "") for pattern in PATTERNS[rule]]
    runs = [run for source in sources for run in RUN.findall(source)]

    assert runs, f"{rule}: no reader run found"
    assert set(runs) == {f"{{0,{BOUND}}}"}, f"{rule}: {sorted(set(runs))}"


def test_session_name_lookahead_keeps_its_wider_bound():
    assert any(SESSION_NAME_LOOKAHEAD in pattern.pattern for pattern in PATTERNS["aws_credential_theft"])


# assume-role with MFA, an external id, a duration and tags: the session name sits
# about 300 characters past the verb, beyond the reader bound and inside its own.
ASSUME_ROLE = (
    "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/platform/deploy/ci-release-engineering"
    " --serial-number arn:aws:iam::123456789012:mfa/release-engineer --token-code 123456"
    " --external-id 7f3c9a2e-4b1d-4e8a-9c6f-2d5b8e1a0c34 --duration-seconds 3600"
    " --tags Key=team,Value=platform Key=owner,Value=release-engineering"
)


@pytest.mark.usefixtures("no_shellcheck")
def test_session_name_past_the_reader_bound_is_still_seen(safety_rules_path):
    result = validate_command(f"{ASSUME_ROLE} --role-session-name release", config_path=safety_rules_path)

    assert "aws_credential_theft" not in result.matched_rules, result.matched_rules


@pytest.mark.usefixtures("no_shellcheck")
def test_session_name_past_the_lookahead_bound_reads_as_missing(safety_rules_path):
    tags = " ".join(f"Key=k{i},Value=v{i}" for i in range(80))
    command = f"{ASSUME_ROLE} {tags} --role-session-name release"
    assert command.index("--role-session-name") - len("aws sts assume-role ") > 1000

    result = validate_command(command, config_path=safety_rules_path)

    assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
    assert "aws_credential_theft" in result.matched_rules, result.matched_rules


@pytest.mark.usefixtures("no_shellcheck")
@pytest.mark.parametrize(("rule", "reader", "lead", "rest"), WITHIN_BOUND, ids=[row[0] for row in WITHIN_BOUND])
def test_path_at_the_edge_of_the_bound_still_rates(rule, reader, lead, rest, safety_rules_path):
    command = f"{reader} {'a' * (BOUND - len(lead) - 1)} {lead}{rest}"

    result = validate_command(command, config_path=safety_rules_path)

    assert result.risk_level == RiskLevel.BLOCKED, f"{command!r} -> {result.risk_level.name}"
    assert rule in result.matched_rules, result.matched_rules
