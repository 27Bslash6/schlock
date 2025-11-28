# Security Rules Organization

## Overview

Security rules are organized by threat category in the `data/rules/` directory. This multi-file structure provides better organization, easier maintenance, and clearer categorization compared to a single monolithic YAML file.

## Directory Structure

Rules are split across 11 files with deterministic load order:

```
data/rules/
├── 00_whitelist.yaml              # Whitelisted safe commands
├── 01_privilege_escalation.yaml   # BLOCKED: sudo, su, pkexec
├── 02_file_destruction.yaml       # BLOCKED/HIGH: rm -rf, find -delete
├── 03_credential_theft.yaml       # BLOCKED: .env, .aws, .ssh credentials
├── 04_disk_operations.yaml        # BLOCKED: dd, mkfs, fdisk
├── 05_code_execution.yaml         # BLOCKED/HIGH: eval, curl|bash, python -c
├── 06_network_security.yaml       # HIGH: nc -e, http servers
├── 07_container_security.yaml     # HIGH: docker --privileged
├── 08_system_modification.yaml    # BLOCKED/HIGH: /etc writes, chmod 777
├── 09_log_tampering.yaml          # HIGH: history -c, /var/log clearing
└── 10_development_workflows.yaml  # MEDIUM/LOW/SAFE: git, npm, pip
```

## Category Details

### 00_whitelist.yaml
**Purpose**: Commands explicitly allowed regardless of other rules
**Risk Levels**: SAFE (override)
**Examples**: `git status`, `ls`, safe `rm -rf node_modules`
**Rules**: 0 (whitelist-only file)

### 01_privilege_escalation.yaml
**Purpose**: Commands that escalate privileges beyond current user
**Risk Levels**: BLOCKED
**Examples**: `sudo`, `su`, `pkexec`, `doas`, `chroot`
**Rules**: 2

### 02_file_destruction.yaml
**Purpose**: Commands that destroy files and directory trees
**Risk Levels**: BLOCKED (3), HIGH (3)
**Examples**: `rm -rf /`, fork bombs, `find -delete`, file truncation
**Rules**: 6

### 03_credential_theft.yaml
**Purpose**: Commands that expose credentials and sensitive data
**Risk Levels**: BLOCKED
**Examples**: `cat .env`, `cat ~/.ssh/id_rsa`, `export AWS_SECRET`
**Rules**: 3

### 04_disk_operations.yaml
**Purpose**: Direct disk device and filesystem manipulation
**Risk Levels**: BLOCKED
**Examples**: `dd of=/dev/sda`, `mkfs`, `fdisk`, `wipefs`
**Rules**: 6

### 05_code_execution.yaml
**Purpose**: Arbitrary code execution vectors
**Risk Levels**: BLOCKED (3), HIGH (4)
**Examples**: `curl|bash`, `eval`, `python -c`, command substitution
**Rules**: 7

### 06_network_security.yaml
**Purpose**: Network service exposure and backdoors
**Risk Levels**: BLOCKED (1), HIGH (2)
**Examples**: `nc -e`, `python -m http.server`, firewall modifications
**Rules**: 3

### 07_container_security.yaml
**Purpose**: Container escape and privilege escalation
**Risk Levels**: HIGH
**Examples**: `docker --privileged`, `docker -v /:/`, `--cap-add=SYS_ADMIN`
**Rules**: 2

### 08_system_modification.yaml
**Purpose**: Critical system file and permission changes
**Risk Levels**: BLOCKED (2), HIGH (3)
**Examples**: modifications to `/etc`, `/proc`, `chmod 777`, recursive permission changes
**Rules**: 5

### 09_log_tampering.yaml
**Purpose**: System log and audit trail manipulation
**Risk Levels**: HIGH
**Examples**: `history -c`, `/var/log` clearing, `HISTFILE` manipulation
**Rules**: 1

### 10_development_workflows.yaml
**Purpose**: Common development operations and package management
**Risk Levels**: HIGH (6), MEDIUM (6), LOW (10), SAFE (5)
**Examples**: `git push`, `npm install`, `docker build`, database operations
**Rules**: 27

## Load Order

Files are loaded in **alphabetical order**, which the `NN_` prefix guarantees is:
1. Critical security rules (BLOCKED) first
2. High-risk operational rules
3. Development workflows last

This ensures:
- **Deterministic ordering**: Same results every time
- **Testable**: Predictable rule precedence
- **Security-first**: Most dangerous patterns checked first

## File Format

Each category file follows this structure:

```yaml
# Category: Name
# Risk Levels: BLOCKED, HIGH, etc.
# Description: What this category protects against

whitelist:  # Optional
  - pattern1
  - pattern2

rules:
  - name: rule_name
    description: What this detects and why it's dangerous
    risk_level: BLOCKED|HIGH|MEDIUM|LOW|SAFE
    patterns: ['pattern1', 'pattern2']
    alternatives: ["Safer approach 1", "Safer approach 2"]
```

### Field Requirements

- **name**: Unique identifier (snake_case)
- **description**: Human-readable explanation (what + why)
- **risk_level**: One of: `BLOCKED`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`
- **patterns**: List of regex patterns (POSIX extended regex)
- **alternatives**: Safer approaches (empty list if none)

### Pattern Guidelines

1. **Use bounded quantifiers**: `{0,N}` instead of `*` or `+` for ReDoS protection
2. **No case-insensitive matching**: Security requirement (exact match only)
3. **Multiline mode**: Patterns can match across lines
4. **Escape special chars**: Use `\b` for word boundaries, `\.` for literal dots

Example:
```yaml
patterns: ['rm\s+.{0,100}(-rf|-fr)\s+/', '\bsudo\b', 'eval\s+.{0,200}']
```

## Adding New Rules

### 1. Choose Category

Determine which category file the rule belongs in:
- **Privilege escalation**: New ways to gain root/admin access
- **File destruction**: New destructive file operations
- **Credential theft**: New credential exposure vectors
- **Disk operations**: Direct disk/filesystem manipulation
- **Code execution**: New arbitrary code execution methods
- **Network security**: Network exposure or backdoors
- **Container security**: Container escape vectors
- **System modification**: System file/permission changes
- **Log tampering**: Audit trail manipulation
- **Development workflows**: Common dev operations

### 2. Add Rule

Edit the appropriate category file and add your rule in the correct risk level section:

```yaml
  - name: new_dangerous_operation
    description: Explanation of what this detects and why it's dangerous
    risk_level: HIGH
    patterns: ['pattern1', 'pattern2']
    alternatives: ["Safer approach"]
```

### 3. Test

Run tests to verify:
```bash
# Test rule loading
pytest tests/test_rules.py::TestMultiFileRuleLoading -v

# Test pattern matching
pytest tests/test_pattern_coverage.py -v

# Full test suite
pytest
```

### 4. Verify Coverage

Check that your pattern is tested:
```bash
pytest tests/test_pattern_coverage.py::test_all_patterns_have_tests -v
```

## Backward Compatibility

The system maintains full backward compatibility with single-file configurations:

**Loading Priority**:
1. If `data/rules/` directory exists → multi-file loading
2. Otherwise → fallback to `data/safety_rules.yaml`

This means:
- Old plugins still work (single file)
- New plugins use multi-file structure
- No migration required
- Gradual rollout possible

**Testing Backward Compatibility**:
```bash
# Temporarily rename rules directory
mv data/rules data/rules.bak

# Run tests with single file
pytest

# Restore
mv data/rules.bak data/rules
```

## Performance

**Load Time**: <50ms for all 60 rules across 11 files

**Caching**: Rules are compiled once at startup:
- Regex patterns pre-compiled
- LRU cache for validation results
- Cache hits: <0.1ms

**Memory**: Minimal overhead (~10KB for 60 rules)

## Maintenance

### Rule Auditing

Check rule statistics:
```bash
# Count rules per file
for f in data/rules/*.yaml; do
  echo "$f: $(grep -c "^  - name:" $f) rules"
done

# Count by risk level
grep "risk_level:" data/rules/*.yaml | cut -d: -f3 | sort | uniq -c
```

### Duplicate Detection

Ensure no duplicate rule names:
```bash
grep "^  - name:" data/rules/*.yaml | cut -d: -f3 | sort | uniq -d
```

Should return empty (no duplicates).

### Pattern Testing

Test a pattern against commands:
```bash
python -c "
from schlock import validate_command
result = validate_command('rm -rf /')
print(f'Risk: {result.risk_level.name}, Allowed: {result.allowed}')
"
```

## Migration Guide

### From Single File to Multi-File

If you have custom rules in `data/safety_rules.yaml`:

1. **Backup**: `cp data/safety_rules.yaml data/safety_rules.yaml.bak`
2. **Categorize**: Determine which category each rule belongs to
3. **Add to category files**: Copy rules to appropriate `data/rules/NN_*.yaml`
4. **Test**: Run full test suite
5. **Verify**: Ensure all custom rules still work

### From Multi-File Back to Single File

To consolidate (not recommended, but possible):

```bash
# Merge all rules into single file
cat data/rules/*.yaml > data/safety_rules_consolidated.yaml

# Edit to remove duplicate headers
# Remove data/rules/ directory to force single-file loading
```

## Best Practices

1. **Keep categories focused**: Each file should have a single clear purpose
2. **Maintain risk level grouping**: BLOCKED rules first, then HIGH, etc.
3. **Document patterns**: Use clear descriptions explaining what and why
4. **Test thoroughly**: Every pattern should have test coverage
5. **Review regularly**: Audit rules quarterly for false positives
6. **Use bounded quantifiers**: Prevent ReDoS attacks
7. **Avoid overly broad patterns**: Target specific dangerous behaviors
8. **Provide alternatives**: Help users understand safer approaches

## Troubleshooting

### Rules not loading
```bash
# Check for YAML syntax errors
python -c "
import yaml
from pathlib import Path
for f in Path('data/rules').glob('*.yaml'):
    try:
        yaml.safe_load(f.read_text())
        print(f'{f.name}: OK')
    except Exception as e:
        print(f'{f.name}: ERROR - {e}')
"
```

### Pattern not matching
```bash
# Test pattern directly
python -c "
import re
pattern = r'rm\s+-rf\s+/'
command = 'rm -rf /'
match = re.search(pattern, command)
print(f'Match: {match is not None}')
"
```

### Performance issues
```bash
# Profile rule loading
python -m cProfile -s cumtime -c "
from schlock.core.validator import load_rules
load_rules()
"
```

## See Also

- **[CONFIGURATION.md](CONFIGURATION.md)**: User configuration and customization
- **[DEVELOPMENT.md](DEVELOPMENT.md)**: Development workflow and architecture
- **[CONTRIBUTING.md](../CONTRIBUTING.md)**: Contributing guidelines
- **[README.md](../README.md)**: Project overview and quick start
