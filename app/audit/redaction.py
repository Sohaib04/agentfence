"""Redaction utilities for masking sensitive credentials and omitting full file contents."""

from typing import Any

SENSITIVE_KEY_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "auth",
    "api_key",
    "private_key",
    "credential",
)


def redact_sensitive_payload(
    data: Any,
    tool_name: str | None = None,
    is_result: bool = False,
) -> Any:
    """Recursively redact sensitive keys and full file contents from payload dictionaries.

    - Sensitive keys matching known patterns are masked as '[REDACTED]'.
    - 'content' fields in write_file or read_file results are replaced with summary metadata
      so that large file bodies or secrets in file writes are not persisted in audit logs.
    """
    if isinstance(data, dict):
        redacted_dict: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).lower()

            # Check if key represents a credential or sensitive token
            if any(s in key_lower for s in SENSITIVE_KEY_SUBSTRINGS):
                redacted_dict[key] = "[REDACTED]"
            # Check for file content suppression
            elif key_lower == "content" and isinstance(value, str):
                if tool_name in ("write_file", "read_file") or is_result:
                    redacted_dict[key] = f"[CONTENT REDACTED ({len(value)} chars)]"
                else:
                    redacted_dict[key] = redact_sensitive_payload(value, tool_name, is_result)
            else:
                redacted_dict[key] = redact_sensitive_payload(value, tool_name, is_result)
        return redacted_dict

    elif isinstance(data, list):
        return [redact_sensitive_payload(item, tool_name, is_result) for item in data]

    return data
