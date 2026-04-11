"""Tests for kubectl contextual safety in command substitutions.

kubectl commands have a wide spectrum of safety — read-only operations like
`kubectl get pods` are safe in substitutions, while state-modifying operations
like `kubectl exec`, `kubectl delete`, `kubectl apply` are not.

This test suite verifies that the contextual whitelist correctly:
1. Allows safe read-only kubectl subcommands in $() and <()
2. Blocks dangerous state-modifying subcommands
3. Preserves YAML rule defense-in-depth (secrets theft, RBAC manipulation)
4. Handles namespace/context flags without false positives
5. Blocks pipelines, chains, and other structural bypasses
6. Correctly parses multi-level subcommands (config view vs config set)
"""

import pytest

from schlock.core.parser import BashCommandParser
from schlock.core.rules import RiskLevel
from schlock.core.substitution import (
    CONTEXTUAL_SUBSTITUTION_COMMANDS,
    DANGEROUS_SUBSTITUTION_COMMANDS,
    SAFE_SUBSTITUTION_COMMANDS,
    SubstitutionValidator,
    _find_kubectl_subcommand,
)
from schlock.core.validator import load_rules, validate_command


@pytest.fixture
def parser():
    return BashCommandParser()


@pytest.fixture
def rule_engine():
    return load_rules()


@pytest.fixture
def validator(parser, rule_engine):
    return SubstitutionValidator(parser, rule_engine)


# ============================================================
# Constants
# ============================================================


class TestContextualWhitelistConstants:
    """Test CONTEXTUAL_SUBSTITUTION_COMMANDS constant."""

    def test_is_frozenset(self):
        assert isinstance(CONTEXTUAL_SUBSTITUTION_COMMANDS, frozenset)

    def test_kubectl_in_contextual_set(self):
        assert "kubectl" in CONTEXTUAL_SUBSTITUTION_COMMANDS

    def test_not_overlapping_with_safe_or_dangerous(self):
        """Contextual commands must not be in the safe or dangerous sets."""
        overlap_safe = CONTEXTUAL_SUBSTITUTION_COMMANDS & SAFE_SUBSTITUTION_COMMANDS
        overlap_dangerous = CONTEXTUAL_SUBSTITUTION_COMMANDS & DANGEROUS_SUBSTITUTION_COMMANDS
        assert len(overlap_safe) == 0, f"Overlap with safe: {overlap_safe}"
        assert len(overlap_dangerous) == 0, f"Overlap with dangerous: {overlap_dangerous}"


# ============================================================
# Safe kubectl in substitutions — should be ALLOWED
# ============================================================


class TestSafeKubectlSubstitutionAllowed:
    """Safe read-only kubectl subcommands should pass in $() context."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Basic read-only operations
            ('echo "$(kubectl get pods)"', "get pods"),
            ('echo "$(kubectl get pods -o name)"', "get pods with output format"),
            ('echo "$(kubectl get deployments -n kube-system)"', "get deployments with namespace"),
            ('echo "$(kubectl get svc --all-namespaces)"', "get services all namespaces"),
            ('echo "$(kubectl get nodes -o wide)"', "get nodes wide output"),
            # Describe (non-secret resources)
            ('echo "$(kubectl describe pod myapp)"', "describe pod"),
            ('echo "$(kubectl describe deployment nginx)"', "describe deployment"),
            ('echo "$(kubectl describe node worker-1)"', "describe node"),
            # Logs
            ('echo "$(kubectl logs deployment/app)"', "logs from deployment"),
            ('echo "$(kubectl logs pod/myapp --tail=100)"', "logs with tail"),
            ('echo "$(kubectl logs -n prod pod/api -c sidecar)"', "logs with namespace and container"),
            # Cluster info
            ('echo "$(kubectl version --client)"', "version client"),
            ('echo "$(kubectl version --short)"', "version short"),
            ('echo "$(kubectl api-resources)"', "api-resources"),
            ('echo "$(kubectl api-versions)"', "api-versions"),
            ('echo "$(kubectl cluster-info)"', "cluster-info"),
            # Top (resource metrics)
            ('echo "$(kubectl top pods)"', "top pods"),
            ('echo "$(kubectl top nodes)"', "top nodes"),
            # Config (read-only operations)
            ('echo "$(kubectl config view)"', "config view"),
            ('echo "$(kubectl config current-context)"', "config current-context"),
            ('echo "$(kubectl config get-contexts)"', "config get-contexts"),
            ('echo "$(kubectl config get-clusters)"', "config get-clusters"),
            # Auth (read-only operations)
            ('echo "$(kubectl auth can-i get pods)"', "auth can-i"),
            ('echo "$(kubectl auth whoami)"', "auth whoami"),
            # Explain
            ('echo "$(kubectl explain pods)"', "explain resource"),
            ('echo "$(kubectl explain deployment.spec)"', "explain field"),
            # Wait (read-only polling)
            ('echo "$(kubectl wait --for=condition=ready pod/myapp)"', "wait for condition"),
            # Diff (dry-run comparison)
            ('echo "$(kubectl diff -f manifest.yaml)"', "diff against manifest"),
            # Events
            ('echo "$(kubectl events)"', "list events"),
            ('echo "$(kubectl events --for pod/myapp)"', "events for resource"),
            # Kustomize (template generation, no apply)
            ('echo "$(kubectl kustomize overlays/prod)"', "kustomize generate"),
        ],
    )
    def test_safe_kubectl_substitution_allowed(self, command, description):
        """Safe read-only kubectl subcommands should be allowed in substitution."""
        result = validate_command(command)
        assert result.allowed, f"REGRESSION: kubectl {description} blocked in substitution: {result.message}"
        assert result.risk_level == RiskLevel.SAFE

    @pytest.mark.parametrize(
        "command,description",
        [
            # Namespace flag parsing — must not confuse namespace with subcommand
            ('echo "$(kubectl -n prod get pods)"', "-n before subcommand"),
            ('echo "$(kubectl --namespace prod get pods)"', "--namespace before subcommand"),
            ('echo "$(kubectl --namespace=prod get pods)"', "--namespace=value before subcommand"),
            ('echo "$(kubectl --context staging get pods)"', "--context before subcommand"),
            ('echo "$(kubectl --context=staging get pods)"', "--context=value before subcommand"),
            ('echo "$(kubectl --kubeconfig /tmp/k.conf get pods)"', "--kubeconfig before subcommand"),
            ('echo "$(kubectl -n prod --context staging get deployments)"', "multiple global flags"),
        ],
    )
    def test_kubectl_with_global_flags_allowed(self, command, description):
        """kubectl with global flags before subcommand should correctly identify subcommand."""
        result = validate_command(command)
        assert result.allowed, f"False positive: {description} was blocked: {result.message}"
        assert result.risk_level == RiskLevel.SAFE


# ============================================================
# Dangerous kubectl in substitutions — should be BLOCKED
# ============================================================


class TestDangerousKubectlSubstitutionBlocked:
    """Dangerous state-modifying kubectl subcommands must be blocked in $() context."""

    @pytest.mark.parametrize(
        "command,description",
        [
            # Code execution
            ('echo "$(kubectl exec -it pod -- bash)"', "exec interactive shell"),
            ('echo "$(kubectl exec pod -- cat /etc/shadow)"', "exec non-interactive command"),
            ('echo "$(kubectl run test --image=alpine -- sh)"', "run creates pod"),
            ('echo "$(kubectl attach pod/myapp -it)"', "attach to container"),
            ('echo "$(kubectl debug node/worker-1 --image=ubuntu)"', "debug node access"),
            # Resource modification
            ('echo "$(kubectl apply -f manifest.yaml)"', "apply creates/updates resources"),
            ('echo "$(kubectl create deployment nginx --image=nginx)"', "create resource"),
            ('echo "$(kubectl delete pod myapp)"', "delete resource"),
            ('echo "$(kubectl edit deployment nginx)"', "edit resource"),
            ('echo "$(kubectl patch svc myapp -p \'{"spec":{"type":"LoadBalancer"}}\')"', "patch resource"),
            ('echo "$(kubectl replace -f manifest.yaml)"', "replace resource"),
            ('echo "$(kubectl set image deployment/app app=nginx:1.25)"', "set resource properties"),
            ('echo "$(kubectl scale deployment/app --replicas=10)"', "scale resource"),
            ('echo "$(kubectl autoscale deployment/app --max=20)"', "autoscale resource"),
            # Data exfiltration
            ('echo "$(kubectl cp mypod:/etc/passwd ./passwd)"', "cp from pod"),
            # Network exposure
            ('echo "$(kubectl port-forward svc/db 5432:5432)"', "port-forward tunnel"),
            ('echo "$(kubectl proxy)"', "API proxy"),
            ('echo "$(kubectl expose deployment/app --port=80)"', "expose creates service"),
            # Node operations
            ('echo "$(kubectl drain node/worker-1)"', "drain node"),
            ('echo "$(kubectl cordon node/worker-1)"', "cordon node"),
            ('echo "$(kubectl uncordon node/worker-1)"', "uncordon node"),
            ('echo "$(kubectl taint node worker-1 key=value:NoSchedule)"', "taint node"),
            # Metadata modification
            ('echo "$(kubectl label pod myapp env=prod)"', "label resource"),
            ('echo "$(kubectl annotate pod myapp desc=test)"', "annotate resource"),
            # Rollout management
            ('echo "$(kubectl rollout restart deployment/app)"', "rollout restart"),
            ('echo "$(kubectl rollout undo deployment/app)"', "rollout undo"),
            # Plugin (arbitrary code execution)
            ('echo "$(kubectl plugin list)"', "plugin operations"),
        ],
    )
    def test_dangerous_kubectl_substitution_blocked(self, command, description):
        """Dangerous kubectl subcommands must be blocked in substitution context."""
        result = validate_command(command)
        assert not result.allowed, f"SECURITY: kubectl {description} was NOT blocked in substitution!"
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED)


class TestKubectlSecretAccessBlockedInSubstitution:
    """Secrets access must be blocked even though get/describe are 'safe' subcommands.

    The YAML rules (kubectl_secrets_theft) provide defense-in-depth here.
    The contextual whitelist runs YAML rules, so these should still be caught.
    """

    @pytest.mark.parametrize(
        "command,description",
        [
            ('echo "$(kubectl get secrets -o json)"', "get secrets as JSON"),
            ('echo "$(kubectl get secret db-creds -o yaml)"', "get secret as YAML"),
            ('echo "$(kubectl describe secret db-creds)"', "describe secret"),
            ("echo \"$(kubectl get secret api-key -o jsonpath='{.data.token}')\"", "extract secret data"),
        ],
    )
    def test_kubectl_secrets_blocked_in_substitution(self, command, description):
        """kubectl secrets access must be BLOCKED in substitution via YAML rules."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: kubectl {description} was NOT blocked in substitution!"
        assert result.risk_level == RiskLevel.BLOCKED


class TestKubectlRBACBlockedInSubstitution:
    """RBAC manipulation must be blocked in substitution via YAML rules."""

    @pytest.mark.parametrize(
        "command,description",
        [
            (
                'echo "$(kubectl create clusterrolebinding admin --clusterrole=cluster-admin)"',
                "create cluster-admin binding",
            ),
            ('echo "$(kubectl edit clusterrole admin)"', "edit cluster role"),
        ],
    )
    def test_kubectl_rbac_blocked_in_substitution(self, command, description):
        """kubectl RBAC manipulation must be blocked in substitution."""
        result = validate_command(command)
        assert not result.allowed, f"CRITICAL: kubectl {description} was NOT blocked in substitution!"
        assert result.risk_level == RiskLevel.BLOCKED


# ============================================================
# Multi-level subcommand checks
# ============================================================


class TestKubectlConfigSubcommands:
    """kubectl config has both safe and dangerous sub-subcommands."""

    @pytest.mark.parametrize(
        "command",
        [
            'echo "$(kubectl config view)"',
            'echo "$(kubectl config current-context)"',
            'echo "$(kubectl config get-contexts)"',
            'echo "$(kubectl config get-clusters)"',
            'echo "$(kubectl config get-users)"',
        ],
    )
    def test_safe_config_subcommands_allowed(self, command):
        """Read-only config operations should be allowed."""
        result = validate_command(command)
        assert result.allowed, f"False positive: {command} blocked: {result.message}"

    @pytest.mark.parametrize(
        "command,description",
        [
            ('echo "$(kubectl config set-context prod)"', "set-context modifies kubeconfig"),
            ('echo "$(kubectl config set-cluster new-cluster)"', "set-cluster modifies kubeconfig"),
            ('echo "$(kubectl config set-credentials admin)"', "set-credentials modifies kubeconfig"),
            ('echo "$(kubectl config delete-context old)"', "delete-context modifies kubeconfig"),
            ('echo "$(kubectl config delete-cluster old)"', "delete-cluster modifies kubeconfig"),
            ('echo "$(kubectl config delete-user old)"', "delete-user modifies kubeconfig"),
            ('echo "$(kubectl config use-context prod)"', "use-context modifies kubeconfig"),
            ('echo "$(kubectl config rename-context old new)"', "rename-context modifies kubeconfig"),
            ('echo "$(kubectl config unset users.admin)"', "unset modifies kubeconfig"),
            ('echo "$(kubectl config set users.admin.token secret)"', "set modifies kubeconfig"),
        ],
    )
    def test_dangerous_config_subcommands_blocked(self, command, description):
        """State-modifying config operations must be blocked."""
        result = validate_command(command)
        assert not result.allowed, f"SECURITY: {description} was NOT blocked!"


class TestKubectlAuthSubcommands:
    """kubectl auth has both safe and dangerous sub-subcommands."""

    def test_auth_can_i_allowed(self):
        result = validate_command('echo "$(kubectl auth can-i get pods)"')
        assert result.allowed

    def test_auth_whoami_allowed(self):
        result = validate_command('echo "$(kubectl auth whoami)"')
        assert result.allowed

    def test_auth_reconcile_blocked(self):
        """auth reconcile modifies RBAC — must be blocked."""
        result = validate_command('echo "$(kubectl auth reconcile -f rbac.yaml)"')
        assert not result.allowed


# ============================================================
# Structural bypass prevention
# ============================================================


class TestKubectlStructuralBypasses:
    """Dangerous structures must be blocked even with safe subcommands."""

    def test_kubectl_pipeline_blocked(self):
        """Pipeline after kubectl should be blocked."""
        result = validate_command('echo "$(kubectl get pods | bash)"')
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED

    def test_kubectl_command_chain_blocked(self):
        """Command chain after kubectl should be blocked."""
        result = validate_command('echo "$(kubectl get pods; rm -rf /)"')
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED

    def test_kubectl_redirect_blocked(self):
        """Output redirection should be blocked."""
        result = validate_command('echo "$(kubectl get pods > /tmp/pods.txt)"')
        assert not result.allowed
        assert result.risk_level == RiskLevel.BLOCKED


# ============================================================
# Process substitution
# ============================================================


class TestKubectlProcessSubstitution:
    """kubectl in process substitution <() context."""

    def test_safe_kubectl_in_process_substitution(self):
        """Safe kubectl in process substitution should work."""
        result = validate_command("diff <(kubectl get pods -n staging) <(kubectl get pods -n prod)")
        assert result.allowed

    def test_dangerous_kubectl_in_process_substitution(self):
        """Dangerous kubectl in process substitution must be blocked."""
        result = validate_command("bash <(kubectl exec pod -- cat /etc/shadow)")
        assert not result.allowed


# ============================================================
# Edge cases
# ============================================================


class TestKubectlEdgeCases:
    """Edge cases and corner scenarios."""

    def test_kubectl_no_subcommand(self):
        """kubectl with only flags and no subcommand should be blocked."""
        result = validate_command('echo "$(kubectl --namespace prod)"')
        assert not result.allowed

    def test_kubectl_with_short_alias_k(self):
        """'k' is not recognized as kubectl — separate handling if needed."""
        # k is not kubectl; it's a shell alias that can't be resolved at AST level
        result = validate_command('echo "$(k get pods)"')
        # Should be blocked as unknown command (k is not whitelisted)
        assert not result.allowed

    def test_direct_kubectl_get_pods_unchanged(self):
        """Direct kubectl get pods (not in substitution) must still work."""
        result = validate_command("kubectl get pods")
        assert result.allowed

    def test_direct_dangerous_kubectl_unchanged(self):
        """Direct dangerous kubectl must still be caught by YAML rules."""
        result = validate_command("kubectl exec -it pod -- bash")
        # With balanced preset, HIGH risk = allowed with "ask" prompt
        # The key thing: the risk level must be HIGH or BLOCKED, not SAFE
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCKED)


# ============================================================
# Unit tests for _find_kubectl_subcommand
# ============================================================


class TestFindKubectlSubcommand:
    """Direct unit tests for the subcommand parsing function."""

    def test_simple_subcommand(self):
        assert _find_kubectl_subcommand(["kubectl", "get", "pods"]) == "get"

    def test_with_namespace_flag(self):
        assert _find_kubectl_subcommand(["kubectl", "-n", "prod", "get", "pods"]) == "get"

    def test_with_long_namespace_flag(self):
        assert _find_kubectl_subcommand(["kubectl", "--namespace", "prod", "get", "pods"]) == "get"

    def test_with_equals_flag(self):
        assert _find_kubectl_subcommand(["kubectl", "--namespace=prod", "get", "pods"]) == "get"

    def test_with_context_flag(self):
        assert _find_kubectl_subcommand(["kubectl", "--context", "staging", "get", "pods"]) == "get"

    def test_with_kubeconfig_flag(self):
        assert _find_kubectl_subcommand(["kubectl", "--kubeconfig", "kubeconfig.conf", "get", "pods"]) == "get"

    def test_multiple_global_flags(self):
        assert _find_kubectl_subcommand(["kubectl", "-n", "prod", "--context", "staging", "get", "pods"]) == "get"

    def test_no_subcommand(self):
        assert _find_kubectl_subcommand(["kubectl", "-n", "prod"]) is None

    def test_only_kubectl(self):
        assert _find_kubectl_subcommand(["kubectl"]) is None

    def test_boolean_flag_skipped(self):
        assert _find_kubectl_subcommand(["kubectl", "--all-namespaces", "get", "pods"]) == "get"

    @pytest.mark.parametrize(
        "flag",
        [
            "--tls-server-name",
            "--username",
            "--password",
            "--profile",
            "--profile-output",
            "--log-flush-frequency",
            "--vmodule",
        ],
    )
    def test_all_value_consuming_flags_handled(self, flag):
        """All value-consuming global flags must skip their value argument."""
        result = _find_kubectl_subcommand(["kubectl", flag, "some-value", "exec", "pod"])
        assert result == "exec", f"Flag {flag} did not consume its value"


# ============================================================
# Bypass regression tests (from expert panel review)
# ============================================================


class TestSubcommandMaskingBypasses:
    """Regression: global flags that consume values must not allow subcommand masking.

    CVE-equivalent: missing value-consuming flags cause the parser to misidentify
    a flag's value as the subcommand.
    """

    @pytest.mark.parametrize(
        "flag",
        [
            "--tls-server-name",
            "--username",
            "--password",
            "--profile",
            "--profile-output",
            "--log-flush-frequency",
            "--vmodule",
        ],
    )
    def test_global_flag_masking_blocked(self, flag):
        """Flag value must not be mistaken for safe subcommand."""
        result = validate_command(f'echo "$(kubectl {flag} get exec pod -- bash)"')
        assert not result.allowed, f"SECURITY BYPASS: {flag} masks real subcommand 'exec'"


class TestRawAPIBypasses:
    """Regression: kubectl get --raw accesses arbitrary API paths."""

    def test_get_raw_secrets(self):
        result = validate_command('echo "$(kubectl get --raw /api/v1/secrets)"')
        assert not result.allowed

    def test_get_raw_namespaced_secret(self):
        result = validate_command('echo "$(kubectl get --raw /api/v1/namespaces/default/secrets/db-creds)"')
        assert not result.allowed

    def test_get_raw_any_path(self):
        result = validate_command('echo "$(kubectl get --raw /api/v1/pods)"')
        assert not result.allowed

    def test_get_raw_equals_form(self):
        """--raw=/path is equivalent to --raw /path."""
        result = validate_command('echo "$(kubectl get --raw=/api/v1/secrets)"')
        assert not result.allowed

    def test_get_raw_equals_metrics(self):
        """--raw=/metrics is info disclosure."""
        result = validate_command('echo "$(kubectl get --raw=/metrics)"')
        assert not result.allowed


class TestSecretAccessBypasses:
    """Regression: secret access must be caught regardless of argument order."""

    def test_secret_before_output_flag(self):
        """Standard order: kubectl get secrets -o json."""
        result = validate_command('echo "$(kubectl get secrets -o json)"')
        assert not result.allowed

    def test_output_flag_before_secret(self):
        """Reordered: kubectl get -o yaml secret."""
        result = validate_command('echo "$(kubectl get -o yaml secret db-creds)"')
        assert not result.allowed

    def test_describe_secret(self):
        result = validate_command('echo "$(kubectl describe secret db-creds)"')
        assert not result.allowed

    def test_multi_resource_with_secret(self):
        """Comma-separated: kubectl get configmaps,secrets."""
        result = validate_command('echo "$(kubectl get configmaps,secrets -o yaml)"')
        assert not result.allowed

    def test_secret_slash_notation(self):
        """Resource/name notation: kubectl get secret/db-creds."""
        result = validate_command('echo "$(kubectl get secret/db-creds -o yaml)"')
        assert not result.allowed


class TestConfigViewRawBypass:
    """Regression: kubectl config view --raw exposes certs and keys."""

    def test_config_view_raw(self):
        result = validate_command('echo "$(kubectl config view --raw)"')
        assert not result.allowed

    def test_config_view_raw_flatten(self):
        result = validate_command('echo "$(kubectl config view --raw --flatten)"')
        assert not result.allowed

    def test_config_view_flatten_alone(self):
        result = validate_command('echo "$(kubectl config view --flatten)"')
        assert not result.allowed

    def test_config_view_raw_equals_true(self):
        """--raw=true is equivalent to --raw."""
        result = validate_command('echo "$(kubectl config view --raw=true)"')
        assert not result.allowed

    def test_config_view_flatten_equals_true(self):
        """--flatten=true is equivalent to --flatten."""
        result = validate_command('echo "$(kubectl config view --flatten=true)"')
        assert not result.allowed

    def test_config_view_without_raw_allowed(self):
        """Plain config view is safe (redacts sensitive data by default)."""
        result = validate_command('echo "$(kubectl config view)"')
        assert result.allowed


class TestClusterInfoDumpBypass:
    """Regression: kubectl cluster-info dump exfiltrates cluster data."""

    def test_cluster_info_dump(self):
        result = validate_command('echo "$(kubectl cluster-info dump)"')
        assert not result.allowed

    def test_cluster_info_dump_all_namespaces(self):
        result = validate_command('echo "$(kubectl cluster-info dump --all-namespaces)"')
        assert not result.allowed

    def test_cluster_info_without_dump_allowed(self):
        """Plain cluster-info is safe (shows endpoint URLs only)."""
        result = validate_command('echo "$(kubectl cluster-info)"')
        assert result.allowed


class TestRolloutSubcommands:
    """Regression: rollout has both safe and dangerous sub-subcommands."""

    @pytest.mark.parametrize(
        "command",
        [
            'echo "$(kubectl rollout status deployment/app)"',
            'echo "$(kubectl rollout history deployment/app)"',
        ],
    )
    def test_safe_rollout_subcommands_allowed(self, command):
        """Read-only rollout operations should be allowed."""
        result = validate_command(command)
        assert result.allowed, f"False positive: {command} blocked: {result.message}"

    @pytest.mark.parametrize(
        "command,description",
        [
            ('echo "$(kubectl rollout restart deployment/app)"', "restart modifies deployment"),
            ('echo "$(kubectl rollout undo deployment/app)"', "undo modifies deployment"),
            ('echo "$(kubectl rollout pause deployment/app)"', "pause modifies deployment"),
            ('echo "$(kubectl rollout resume deployment/app)"', "resume modifies deployment"),
        ],
    )
    def test_dangerous_rollout_subcommands_blocked(self, command, description):
        """State-modifying rollout operations must be blocked."""
        result = validate_command(command)
        assert not result.allowed, f"SECURITY: {description} was NOT blocked!"
