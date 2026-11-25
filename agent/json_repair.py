"""Shared JSON repair utilities for handling malformed LLM output."""
import json
import structlog

log = structlog.get_logger(__name__)


def fix_json(text: str) -> str:
    """Fix unescaped newlines/tabs inside JSON string values."""
    result = []
    in_string = False
    escape_next = False
    for ch in text:
        if escape_next:
            result.append(ch)
            escape_next = False
            continue
        if ch == '\\' and in_string:
            result.append(ch)
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and ch == '\n':
            result.append('\\n')
            continue
        if in_string and ch == '\r':
            continue
        if in_string and ch == '\t':
            result.append('\\t')
            continue
        result.append(ch)
    return ''.join(result)


def parse_llm_json(raw_text: str, context: str = "LLM") -> dict:
    """
    Robustly parse JSON from LLM output.
    Handles: markdown fences, unescaped newlines, trailing garbage.
    """
    text = raw_text.strip()

    # Strip markdown fences
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    # Attempt 1: Parse as-is
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: Fix unescaped newlines inside strings
    try:
        return json.loads(fix_json(text))
    except json.JSONDecodeError:
        pass

    # Attempt 3: Truncate at the last valid closing brace/bracket
    # Find the outermost matching brace
    for end_char in ['}', ']']:
        last_pos = text.rfind(end_char)
        if last_pos > 0:
            truncated = text[:last_pos + 1]
            try:
                return json.loads(truncated)
            except json.JSONDecodeError:
                pass
            try:
                return json.loads(fix_json(truncated))
            except json.JSONDecodeError:
                pass

    # All attempts failed
    log.error(f"{context}_json_parse_error", raw=text[:500])
    raise ValueError(f"{context} returned invalid JSON that could not be repaired")
