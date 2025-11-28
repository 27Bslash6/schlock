"""Custom exceptions for schlock validation engine.

This module defines exception types for validation failures:
- ParseError: Raised when bashlex fails to parse command syntax
- ConfigurationError: Raised when YAML/regex patterns are invalid
"""

from typing import Optional


class ParseError(Exception):
    """Raised when bash command parsing fails.

    Preserves the original bashlex error message for debugging.
    Used by BashCommandParser when bashlex.parse() fails.

    Args:
        message: Error description
        original_error: Original bashlex exception (optional)

    Example:
        >>> raise ParseError("Invalid syntax", original_error=bashlex.errors.ParsingError())
    """

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize ParseError with message and optional original error.

        Args:
            message: Human-readable error description
            original_error: Original bashlex exception (preserved for debugging)
        """
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation with original error context if available."""
        if self.original_error:
            return f"{self.message} (original: {self.original_error})"
        return self.message


class ConfigurationError(Exception):
    """Raised when configuration is invalid.

    Used for:
    - Invalid YAML syntax in rules files
    - Invalid regex patterns in rules
    - Missing required configuration files
    - Malformed configuration structure

    Includes file path and line number context when available.

    Args:
        message: Error description
        file_path: Path to problematic config file (optional)
        line_number: Line number where error occurred (optional)

    Example:
        >>> raise ConfigurationError(
        ...     "Invalid regex pattern",
        ...     file_path="rules.yaml",
        ...     line_number=42
        ... )
    """

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
    ):
        """Initialize ConfigurationError with context.

        Args:
            message: Human-readable error description
            file_path: Path to configuration file with error (if applicable)
            line_number: Line number in file where error occurred (if known)
        """
        self.message = message
        self.file_path = file_path
        self.line_number = line_number
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format error message with file/line context if available."""
        parts = [self.message]
        if self.file_path:
            parts.append(f"in file: {self.file_path}")
        if self.line_number:
            parts.append(f"at line: {self.line_number}")
        return " ".join(parts)

    def __str__(self) -> str:
        """Return formatted error message."""
        return self._format_message()
