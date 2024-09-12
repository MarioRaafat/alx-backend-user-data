#!/usr/bin/env python3
import re

# Module-level docstring
"""
This module provides utilities for filtering log messages by obfuscating sensitive data fields.

Functions:
    - filter_datum: Obfuscates specified fields in a log message.
"""

def filter_datum(fields, redaction, message, separator):
    """
    Obfuscates specified fields in a log message.

    Args:
        fields (list of str): A list of field names to obfuscate.
        redaction (str): The string to replace the field values with.
        message (str): The log message containing key-value pairs to be filtered.
        separator (str): The character separating fields in the log message.

    Returns:
        str: The log message with specified fields obfuscated.
    
    Example:
        >>> filter_datum(["password"], "xxx", "name=John;password=12345;", ";")
        'name=John;password=xxx;'
    """
    pattern = f"({'|'.join(fields)})=[^{separator}]*"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)