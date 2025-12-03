"""Bash command parser using bashlex AST analysis.

This module provides bashlex-based parsing for command safety validation.
It extracts commands from bash syntax and detects dangerous constructs.

The parser is security-critical and REQUIRES bashlex for proper AST parsing.
Regex-based parsing is explicitly NOT supported due to security risks.
"""

import logging
from typing import Any, Optional

import bashlex
import bashlex.errors

from schlock.exceptions import ParseError

logger = logging.getLogger(__name__)


class BashCommandParser:
    """Parse bash commands using bashlex AST analysis.

    This parser is security-critical. It uses bashlex to parse commands into
    an Abstract Syntax Tree (AST), enabling accurate detection of dangerous
    patterns that regex cannot reliably catch.

    SECURITY: This class REQUIRES bashlex. It will not fall back to regex
    parsing, as regex-based command parsing has well-known bypass vulnerabilities.

    Example:
        >>> parser = BashCommandParser()
        >>> ast = parser.parse("git log | grep 'pattern'")
        >>> commands = parser.extract_commands(ast)
        >>> print(commands)  # ['git', 'grep']
    """

    def __init__(self):
        """Initialize BashCommandParser."""
        pass

    def parse(self, command: str) -> list[Any]:
        """Parse command into bashlex AST.

        Args:
            command: Bash command string to parse

        Returns:
            List of bashlex AST nodes

        Raises:
            ValueError: If command is empty or whitespace-only
            ParseError: If bashlex fails to parse the command syntax

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("echo hello")
            >>> ast  # [<bashlex.ast.node object>]
        """
        # Input validation
        if not command:
            raise ValueError("Command cannot be empty")
        if not command.strip():
            raise ValueError("Command cannot be whitespace-only")

        try:
            return bashlex.parse(command)
        except bashlex.errors.ParsingError as e:
            # Preserve original bashlex error for debugging
            raise ParseError(
                f"Failed to parse bash command: {command!r}",
                original_error=e,
            )
        except Exception as e:
            # Catch any other unexpected bashlex errors
            logger.error(f"Unexpected error parsing command: {e}")
            raise ParseError(
                f"Unexpected parsing error for command: {command!r}",
                original_error=e,
            )

    def extract_commands(self, ast_nodes: list[Any]) -> list[str]:
        """Extract all command names from AST.

        Traverses the AST and extracts the first word of each command node,
        which is typically the command name (e.g., 'git', 'rm', 'curl').

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of command names extracted from the AST

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("git log | grep pattern")
            >>> parser.extract_commands(ast)
            ['git', 'grep']
        """
        commands = []

        def visit(node):
            """Recursively visit AST nodes to extract commands."""
            if hasattr(node, "kind"):
                # Command nodes contain the actual command
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    # First part is typically the command name
                    for part in node.parts:
                        if hasattr(part, "word"):
                            commands.append(part.word)
                            break  # Only take first word (command name)

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return commands

    def extract_command_segments(self, command: str, ast_nodes: list[Any]) -> list[str]:
        """Extract full command segments from pipelines and command lists.

        SECURITY CRITICAL: Returns the full text of each command segment so
        each can be validated independently. Prevents bypass via piping/chaining
        dangerous commands after whitelisted ones.

        Args:
            command: Original command string
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of command segment strings extracted from the AST

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("ls | rm -rf / && echo done")
            >>> parser.extract_command_segments("ls | rm -rf / && echo done", ast)
            ['ls', 'rm -rf /', 'echo done']
        """
        segments = []

        def visit(node):  # noqa: PLR0912 - AST traversal requires multiple branches
            """Recursively visit AST nodes to extract command segments."""
            if hasattr(node, "kind"):
                # Command nodes contain individual commands
                if node.kind == "command" and hasattr(node, "pos"):
                    start, end = node.pos
                    if start < len(command) and end <= len(command):
                        segment = command[start:end].strip()
                        if segment:
                            segments.append(segment)
                    return  # Don't recurse into command parts

                # Pipeline nodes - visit each command in the pipeline
                if node.kind == "pipeline" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "kind") and part.kind != "pipe":
                            visit(part)
                    return

                # List nodes (;, &&, ||) - visit each command
                if node.kind == "list" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "kind") and part.kind not in ("operator",):
                            visit(part)
                    return

                # Compound commands (if, for, while, etc.) - recurse into body
                if node.kind == "compound" and hasattr(node, "list"):
                    for item in node.list if isinstance(node.list, list) else [node.list]:
                        visit(item)
                    return

                # Recursively visit other child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return segments

    def reconstruct_command(self, ast_nodes: list[Any]) -> str:
        """Reconstruct command from AST word nodes.

        SECURITY CRITICAL: Bashlex unescapes special characters during parsing.
        For example, 'rm\\ -rf\\ /' becomes word 'rm -rf /'.
        This reconstruction enables pattern matching against the ACTUAL command
        that will be executed, not the escaped input string.

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            Reconstructed command string with escapes resolved

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("rm\\\\ -rf\\\\ /")
            >>> parser.reconstruct_command(ast)
            'rm -rf /'
        """
        words = []

        def visit(node):
            """Recursively visit AST nodes to extract words."""
            if hasattr(node, "kind"):
                # Command nodes - extract their word parts
                if node.kind == "command" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "word"):
                            words.append(part.word)
                    return  # Don't recurse further into this command

                # Recursively visit child nodes for other structures
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return " ".join(words)

    def extract_heredoc_ranges(self, command: str, ast_nodes: list[Any]) -> list[tuple]:
        """Extract heredoc content ranges that should NOT be pattern matched.

        SECURITY: Heredoc content is only TEXT unless piped to a shell.
        'cat << EOF' outputs text, 'bash << EOF' executes it.

        Args:
            command: Original command string
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of (start, end, is_shell) tuples for heredoc content ranges.
            is_shell=True means the heredoc will be executed by a shell.
        """
        heredoc_ranges = []
        shell_commands = {"bash", "sh", "zsh", "ksh", "dash", "ash", "fish"}

        def visit(node, parent_cmd=None):
            """Recursively visit AST nodes to find heredocs."""
            if hasattr(node, "kind"):
                # Track command name for determining if heredoc goes to shell
                cmd_name = None
                if node.kind == "command" and hasattr(node, "parts") and node.parts:
                    for part in node.parts:
                        if hasattr(part, "word"):
                            cmd_name = part.word.split("/")[-1]  # Handle /bin/bash
                            break

                # Check for redirect nodes with heredocs
                if node.kind == "redirect" and hasattr(node, "heredoc"):
                    heredoc = node.heredoc
                    if hasattr(heredoc, "pos"):
                        start, end = heredoc.pos
                        is_shell = parent_cmd in shell_commands if parent_cmd else False
                        heredoc_ranges.append((start, end, is_shell))

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item, cmd_name or parent_cmd)
                        elif child:
                            visit(child, cmd_name or parent_cmd)

        for node in ast_nodes or []:
            visit(node)

        return heredoc_ranges

    def extract_string_literals(self, command: str, ast_nodes: list[Any]) -> list[tuple]:
        """Extract quoted string literals from AST with their positions.

        This method identifies strings that won't be executed (quoted literals)
        vs strings that will be executed. Used to avoid false positives when
        dangerous patterns appear in documentation, commit messages, or echo statements.

        Args:
            command: Original command string (needed for position mapping)
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of (start_pos, end_pos) tuples for each quoted string literal

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse('echo "rm -rf /"')
            >>> literals = parser.extract_string_literals('echo "rm -rf /"', ast)
            >>> # literals = [(6, 14)]  # Position of content inside quotes
        """
        string_literals = []

        def visit(node):
            """Recursively visit AST nodes to find quoted strings."""
            if hasattr(node, "kind"):
                # Look for word nodes that are quoted strings
                if node.kind == "word" and hasattr(node, "pos"):
                    start, end = node.pos
                    # Check if the position in the original command has quotes
                    if start < len(command) and end <= len(command):
                        if (command[start] == '"' and command[end - 1] == '"') or (
                            command[start] == "'" and command[end - 1] == "'"
                        ):
                            # Record the position INSIDE the quotes (exclude quote chars)
                            # Only append valid ranges (empty strings would create invalid ranges)
                            if start + 1 <= end - 1:
                                string_literals.append((start + 1, end - 1))

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return string_literals

    def has_dangerous_constructs(self, ast_nodes: list[Any]) -> list[str]:
        """Detect dangerous shell constructs in AST.

        Checks for constructs that enable command injection or arbitrary
        code execution:
        - Command substitution: $(cmd) or `cmd`
        - Process substitution: <(cmd) or >(cmd)
        - eval/exec commands
        - Remote code execution via curl/wget piped to shell

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of warning messages for detected dangerous constructs

        Example:
            >>> parser = BashCommandParser()
            >>> ast = parser.parse("rm $(whoami)")
            >>> parser.has_dangerous_constructs(ast)
            ['command substitution detected']
        """
        dangers = []

        # Check for dangerous pipelines (curl | sh patterns)
        pipeline_dangers = self._detect_dangerous_pipelines(ast_nodes)
        dangers.extend(pipeline_dangers)

        def visit(node):
            """Recursively visit AST nodes to detect dangerous patterns."""
            if hasattr(node, "kind"):
                # Command substitution: $(cmd) or `cmd`
                if node.kind == "commandsubstitution":
                    dangers.append("command substitution detected")

                # Process substitution: <(cmd) or >(cmd)
                elif node.kind == "processsubstitution":
                    dangers.append("process substitution detected")

                # Eval/exec commands (arbitrary code execution)
                elif node.kind == "command" and hasattr(node, "parts"):
                    for part in node.parts:
                        if hasattr(part, "word") and part.word in ["eval", "exec"]:
                            dangers.append(f"{part.word} command detected")

                # Recursively visit child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return dangers

    def _detect_dangerous_pipelines(self, ast_nodes: list[Any]) -> list[str]:
        """Detect remote code execution patterns in pipelines via AST.

        SECURITY CRITICAL: Detects patterns like 'curl URL | sh' using AST analysis.
        This is immune to obfuscation techniques that defeat regex patterns:
        - Environment variable prefixes: curl ... | VAR=value sh
        - Redirections: curl ... | sh 2>&1
        - Arguments: curl ... | bash -c
        - Whitespace tricks

        The AST-based detection looks at the actual command structure:
        1. Find pipeline nodes
        2. Extract first command name (download tool?)
        3. Extract subsequent command names (shell interpreter?)

        Args:
            ast_nodes: List of bashlex AST nodes from parse()

        Returns:
            List of warning messages for detected dangerous pipeline patterns
        """
        dangers = []

        # Download tools that fetch remote content
        download_tools = {
            "curl",
            "wget",
            "fetch",
            "aria2c",
            "http",
            "lynx",
            "links",
            "elinks",
            "w3m",  # Text browsers with -dump
            "nc",
            "netcat",
            "ncat",
            "socat",  # Network tools
            "GET",
            "lwp-request",  # Perl LWP tools
            # Additional download vectors (FINDING-001)
            "ftp",
            "tftp",
            "sftp",  # FTP variants
            "scp",
            "rsync",  # Remote copy tools
            "git",
            "svn",
            "hg",  # VCS tools that can fetch remote content
        }

        # Shell interpreters that execute piped input
        shell_interpreters = {
            "bash",
            "sh",
            "zsh",
            "dash",
            "ksh",
            "ash",
            "fish",
            "python",
            "python2",
            "python3",
            "perl",
            "ruby",
            "node",
            # Additional interpreters (FINDING-002)
            "env",  # CRITICAL: env bash executes bash with modified environment
            "xargs",  # xargs sh executes shell with piped args
            "lua",
            "lua5.1",
            "lua5.2",
            "lua5.3",
            "lua5.4",
            "luajit",
            "php",
            "php7",
            "php8",
            "Rscript",
            "R",
            "julia",
            "pwsh",
            "powershell",  # PowerShell Core (cross-platform)
            "tclsh",
            "wish",  # Tcl interpreters
            "gawk",
            "mawk",
            "nawk",  # awk variants (can execute via system())
            "busybox",  # Often contains sh applet
        }

        def get_command_name(node) -> Optional[str]:
            """Extract the command name from a command node.

            Handles cases where command has assignments before the command name:
            e.g., 'VAR=value sh' -> 'sh'
            """
            if not hasattr(node, "kind") or node.kind != "command":
                return None
            if not hasattr(node, "parts"):
                return None

            for part in node.parts:
                # Skip assignment nodes (VAR=value prefixes)
                if hasattr(part, "kind") and part.kind == "assignment":
                    continue
                # Skip redirects
                if hasattr(part, "kind") and part.kind == "redirect":
                    continue
                # Found a word node - this is the command name
                if hasattr(part, "word"):
                    # Handle paths like /usr/bin/curl -> curl
                    return part.word.split("/")[-1]

            return None

        def check_pipeline(node):
            """Check a pipeline node for dangerous patterns."""
            if not hasattr(node, "parts"):
                return

            # Extract command names from pipeline parts
            commands_in_pipeline = []
            for part in node.parts:
                if hasattr(part, "kind"):
                    if part.kind == "command":
                        cmd_name = get_command_name(part)
                        if cmd_name:
                            commands_in_pipeline.append(cmd_name)
                    elif part.kind == "pipe":
                        continue  # Skip pipe operators

            # Check for download -> shell pattern
            if len(commands_in_pipeline) >= 2:
                first_cmd = commands_in_pipeline[0]
                if first_cmd in download_tools:
                    for subsequent_cmd in commands_in_pipeline[1:]:
                        if subsequent_cmd in shell_interpreters:
                            dangers.append(f"remote code execution: {first_cmd} piped to {subsequent_cmd}")
                            break  # One warning per pipeline is enough

        def visit(node):
            """Recursively visit AST to find pipeline nodes."""
            if hasattr(node, "kind"):
                if node.kind == "pipeline":
                    check_pipeline(node)

                # Recurse into child nodes
                for attr in ["parts", "command", "list", "pipe", "compound"]:
                    if hasattr(node, attr):
                        child = getattr(node, attr)
                        if isinstance(child, list):
                            for item in child:
                                visit(item)
                        elif child:
                            visit(child)

        for node in ast_nodes or []:
            visit(node)

        return dangers
