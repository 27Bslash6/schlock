"""Audit log analysis CLI tool.

Analyzes schlock audit logs to identify patterns, anomalies, and security insights.

Usage:
    python tests/audit_cli.py summary [--days N]
    python tests/audit_cli.py blocked [--days N] [--limit N]
    python tests/audit_cli.py patterns [--days N]
    python tests/audit_cli.py search --pattern REGEX [--days N]
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# Add project root to path for vendored imports
sys.path.insert(0, str(Path(__file__).parent.parent / ".claude-plugin" / "vendor"))
from platformdirs import user_data_dir


@dataclass
class AuditEntry:
    """Parsed audit log entry."""

    timestamp: datetime
    event_type: str
    command: str
    risk_level: str
    violations: list[str]
    decision: str
    execution_time_ms: Optional[float]

    @classmethod
    def from_json(cls, line: str) -> Optional["AuditEntry"]:
        """Parse JSON line into AuditEntry."""
        try:
            data = json.loads(line)
            return cls(
                timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
                event_type=data.get("event_type", "unknown"),
                command=data.get("command", ""),
                risk_level=data.get("risk_level", "UNKNOWN"),
                violations=data.get("violations", []),
                decision=data.get("decision", "unknown"),
                execution_time_ms=data.get("execution_time_ms"),
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None


def get_audit_dir() -> Path:
    """Get default audit log directory."""
    return Path(user_data_dir("schlock", "27b.io"))


def iter_audit_files(days: int = 7) -> Iterator[Path]:
    """Iterate over audit files for the given number of days."""
    audit_dir = get_audit_dir()
    if not audit_dir.exists():
        return

    today = datetime.now()
    for i in range(days):
        date = today - timedelta(days=i)
        filename = f"audit-{date.strftime('%Y-%m-%d')}.jsonl"
        filepath = audit_dir / filename
        if filepath.exists():
            yield filepath


def read_entries(days: int = 7) -> Iterator[AuditEntry]:
    """Read all audit entries from the past N days."""
    for filepath in iter_audit_files(days):
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    entry = AuditEntry.from_json(stripped)
                    if entry:
                        yield entry


def cmd_summary(args: argparse.Namespace) -> int:
    """Show summary statistics."""
    entries = list(read_entries(args.days))

    if not entries:
        print(f"No audit entries found in the past {args.days} days.")
        print(f"Audit directory: {get_audit_dir()}")
        return 0

    risk_counts: Counter[str] = Counter()
    decision_counts: Counter[str] = Counter()
    total_time_ms = 0.0
    timed_count = 0

    for entry in entries:
        risk_counts[entry.risk_level] += 1
        decision_counts[entry.decision] += 1
        if entry.execution_time_ms is not None:
            total_time_ms += entry.execution_time_ms
            timed_count += 1

    print(f"=== Audit Summary (past {args.days} days) ===\n")
    print(f"Total events: {len(entries)}")
    print(f"Date range: {entries[-1].timestamp.date()} to {entries[0].timestamp.date()}\n")

    print("By Risk Level:")
    for level in ["BLOCKED", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        count = risk_counts.get(level, 0)
        pct = (count / len(entries)) * 100 if entries else 0
        bar = "█" * int(pct / 5)
        print(f"  {level:8} {count:5} ({pct:5.1f}%) {bar}")

    print("\nBy Decision:")
    for decision in ["block", "allow", "warn"]:
        count = decision_counts.get(decision, 0)
        pct = (count / len(entries)) * 100 if entries else 0
        print(f"  {decision:8} {count:5} ({pct:5.1f}%)")

    if timed_count > 0:
        avg_time = total_time_ms / timed_count
        print(f"\nAvg validation time: {avg_time:.2f}ms")

    return 0


def cmd_blocked(args: argparse.Namespace) -> int:
    """List blocked commands."""
    entries = [e for e in read_entries(args.days) if e.decision == "block"]

    if not entries:
        print(f"No blocked commands in the past {args.days} days.")
        return 0

    # Group by command (normalized)
    by_command: dict[str, list[AuditEntry]] = defaultdict(list)
    for entry in entries:
        # Normalize command for grouping (remove specific args)
        normalized = re.sub(r"\s+", " ", entry.command.strip())
        by_command[normalized].append(entry)

    # Sort by frequency
    sorted_commands = sorted(by_command.items(), key=lambda x: -len(x[1]))

    print(f"=== Blocked Commands (past {args.days} days) ===\n")
    print(f"Total blocks: {len(entries)}\n")

    for i, (cmd, cmd_entries) in enumerate(sorted_commands[: args.limit]):
        count = len(cmd_entries)
        latest = cmd_entries[0].timestamp.strftime("%Y-%m-%d %H:%M")

        # Get unique violations
        violations = set()
        for e in cmd_entries:
            violations.update(e.violations)

        print(f"{i + 1}. [{count}x] {cmd[:80]}")
        print(f"   Latest: {latest}")
        if violations:
            print(f"   Rules: {', '.join(sorted(violations)[:3])}")
        print()

    return 0


def cmd_patterns(args: argparse.Namespace) -> int:
    """Analyze command patterns and anomalies."""
    entries = list(read_entries(args.days))

    if not entries:
        print(f"No audit entries found in the past {args.days} days.")
        return 0

    # Extract command prefixes (first word)
    command_prefixes: Counter[str] = Counter()
    hourly_blocks: Counter[int] = Counter()

    for entry in entries:
        prefix = entry.command.split()[0] if entry.command.split() else "unknown"
        command_prefixes[prefix] += 1

        if entry.decision == "block":
            hourly_blocks[entry.timestamp.hour] += 1

    print(f"=== Command Patterns (past {args.days} days) ===\n")

    print("Top 10 Command Types:")
    for cmd, count in command_prefixes.most_common(10):
        pct = (count / len(entries)) * 100
        print(f"  {cmd:15} {count:5} ({pct:5.1f}%)")

    # Check for anomalies
    print("\n=== Anomaly Detection ===\n")

    # High block rate
    block_count = sum(1 for e in entries if e.decision == "block")
    block_rate = (block_count / len(entries)) * 100 if entries else 0

    if block_rate > 10:
        print(f"⚠️  HIGH BLOCK RATE: {block_rate:.1f}% of commands blocked")
        print("   This may indicate attack attempts or overly strict rules.\n")

    # Blocked HIGH/BLOCKED commands
    dangerous_blocked = [e for e in entries if e.risk_level in ("HIGH", "BLOCKED") and e.decision == "block"]
    if dangerous_blocked:
        print(f"🛡️  {len(dangerous_blocked)} dangerous commands blocked")

    # Look for repeat offenders (same command blocked multiple times)
    blocked_cmds: Counter[str] = Counter()
    for e in entries:
        if e.decision == "block":
            blocked_cmds[e.command] += 1

    repeat_blocks = [(cmd, count) for cmd, count in blocked_cmds.items() if count >= 3]
    if repeat_blocks:
        print(f"\n⚠️  {len(repeat_blocks)} commands blocked 3+ times (possible automation):")
        for cmd, count in sorted(repeat_blocks, key=lambda x: -x[1])[:5]:
            print(f"   [{count}x] {cmd[:60]}")

    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Search audit logs for commands matching pattern."""
    try:
        pattern = re.compile(args.pattern, re.IGNORECASE)
    except re.error as e:
        print(f"Invalid regex pattern: {e}", file=sys.stderr)
        return 1

    matches = []
    for entry in read_entries(args.days):
        if pattern.search(entry.command):
            matches.append(entry)

    if not matches:
        print(f"No commands matching '{args.pattern}' in the past {args.days} days.")
        return 0

    print(f"=== Search Results: '{args.pattern}' (past {args.days} days) ===\n")
    print(f"Found {len(matches)} matching entries\n")

    for entry in matches[: args.limit]:
        time_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        decision_icon = "🚫" if entry.decision == "block" else "✅"
        print(f"{decision_icon} [{time_str}] {entry.risk_level}")
        print(f"   {entry.command[:100]}")
        if entry.violations:
            print(f"   Violations: {', '.join(entry.violations)}")
        print()

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Export audit data to CSV."""
    entries = list(read_entries(args.days))

    if not entries:
        print(f"No audit entries found in the past {args.days} days.", file=sys.stderr)
        return 1

    print("timestamp,event_type,risk_level,decision,command,violations")
    for entry in entries:
        cmd_escaped = entry.command.replace('"', '""')
        violations = "|".join(entry.violations)
        print(
            f'"{entry.timestamp.isoformat()}","{entry.event_type}","{entry.risk_level}","{entry.decision}","{cmd_escaped}","{violations}"'
        )

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze schlock audit logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # summary command
    p_summary = subparsers.add_parser("summary", help="Show summary statistics")
    p_summary.add_argument("--days", type=int, default=7, help="Days to analyze (default: 7)")
    p_summary.set_defaults(func=cmd_summary)

    # blocked command
    p_blocked = subparsers.add_parser("blocked", help="List blocked commands")
    p_blocked.add_argument("--days", type=int, default=7, help="Days to analyze (default: 7)")
    p_blocked.add_argument("--limit", type=int, default=20, help="Max commands to show (default: 20)")
    p_blocked.set_defaults(func=cmd_blocked)

    # patterns command
    p_patterns = subparsers.add_parser("patterns", help="Analyze command patterns")
    p_patterns.add_argument("--days", type=int, default=7, help="Days to analyze (default: 7)")
    p_patterns.set_defaults(func=cmd_patterns)

    # search command
    p_search = subparsers.add_parser("search", help="Search commands by pattern")
    p_search.add_argument("--pattern", "-p", required=True, help="Regex pattern to search")
    p_search.add_argument("--days", type=int, default=7, help="Days to analyze (default: 7)")
    p_search.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    p_search.set_defaults(func=cmd_search)

    # export command
    p_export = subparsers.add_parser("export", help="Export to CSV")
    p_export.add_argument("--days", type=int, default=7, help="Days to export (default: 7)")
    p_export.set_defaults(func=cmd_export)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
