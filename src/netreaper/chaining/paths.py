"""JSONPath-like path resolution for data binding."""

import re
from typing import Any


def resolve_path(data: Any, path: str) -> Any:
    """Resolve a JSONPath-like expression against data.

    Supports:
        - Simple key: "hosts"
        - Nested: "hosts.ip" or "hosts[0].ip"
        - Array index: "hosts[0]"
        - Wildcard: "hosts[*].ip" -> list of all IPs
        - Filter: "hosts[?state==up]" -> filtered list
        - Negative index: "hosts[-1]" -> last item

    Args:
        data: The data structure to query
        path: The path expression

    Returns:
        The resolved value, or None if not found

    Examples:
        >>> data = {"hosts": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}]}
        >>> resolve_path(data, "hosts[*].ip")
        ["192.168.1.1", "192.168.1.2"]
        >>> resolve_path(data, "hosts[0].ip")
        "192.168.1.1"
    """
    if not path or data is None:
        return data

    # Parse the path into segments
    segments = _parse_path(path)
    return _resolve_segments(data, segments)


def _parse_path(path: str) -> list[dict[str, Any]]:
    """Parse path string into segment list."""
    segments = []
    remaining = path

    while remaining:
        # Match array accessor [N], [*], or [?filter]
        array_match = re.match(r"^\[(-?\d+|\*|\?[^\]]+)\]\.?", remaining)
        if array_match:
            accessor = array_match.group(1)
            if accessor == "*":
                segments.append({"type": "wildcard"})
            elif accessor.startswith("?"):
                segments.append({"type": "filter", "expr": accessor[1:]})
            else:
                segments.append({"type": "index", "value": int(accessor)})
            remaining = remaining[array_match.end() :]
            continue

        # Match key accessor
        key_match = re.match(r"^([^.\[\]]+)\.?", remaining)
        if key_match:
            segments.append({"type": "key", "value": key_match.group(1)})
            remaining = remaining[key_match.end() :]
            continue

        # Skip leading dot
        if remaining.startswith("."):
            remaining = remaining[1:]
            continue

        break

    return segments


def _resolve_key(data: Any, segment: dict[str, Any], remaining: list) -> Any:
    if not isinstance(data, dict):
        return None
    return _resolve_segments(data.get(segment["value"]), remaining)


def _resolve_index(data: Any, segment: dict[str, Any], remaining: list) -> Any:
    if not isinstance(data, (list, tuple)):
        return None
    try:
        value = data[segment["value"]]
    except IndexError:
        return None
    return _resolve_segments(value, remaining)


def _resolve_wildcard(data: Any, _segment: dict[str, Any], remaining: list) -> Any:
    """Every element, with one flattening rule that is easy to miss.

    A list result is spliced in rather than nested, but only when there are
    further segments after the wildcard. With nothing remaining, a list element
    stays a list element. Changing that silently flattens the caller's data.
    """
    if not isinstance(data, (list, tuple)):
        return None
    results: list[Any] = []
    for item in data:
        result = _resolve_segments(item, remaining)
        if result is None:
            continue
        if isinstance(result, list) and remaining:
            results.extend(result)
        else:
            results.append(result)
    return results or None


def _resolve_filter(data: Any, segment: dict[str, Any], remaining: list) -> Any:
    if not isinstance(data, (list, tuple)):
        return None
    filtered = _apply_filter(data, segment["expr"])
    return _resolve_segments(filtered, remaining) if remaining else filtered


# Dispatch by segment type. Defined after the resolvers so a name that stops
# existing is an error at import rather than a path that silently returns None.
_SEGMENT_RESOLVERS = {
    "key": _resolve_key,
    "index": _resolve_index,
    "wildcard": _resolve_wildcard,
    "filter": _resolve_filter,
}


def _resolve_segments(data: Any, segments: list[dict[str, Any]]) -> Any:
    """Recursively resolve path segments."""
    if not segments:
        return data
    resolver = _SEGMENT_RESOLVERS.get(segments[0]["type"])
    if resolver is None:
        return None
    return resolver(data, segments[0], segments[1:])


def _apply_filter(data: list, expr: str) -> list:
    """Apply a filter expression to a list.

    Supports:
        - key==value (equality)
        - key!=value (inequality)
        - key>value (greater than, numeric)
        - key<value (less than, numeric)
        - key>=value (greater or equal)
        - key<=value (less or equal)
    """
    # Parse filter expression
    for op in ["==", "!=", ">=", "<=", ">", "<"]:
        if op in expr:
            parts = expr.split(op, 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()

                # Try to convert value to number
                try:
                    value = float(value)
                    if value.is_integer():
                        value = int(value)
                except ValueError:
                    pass

                return [
                    item
                    for item in data
                    if isinstance(item, dict) and _compare(item.get(key), op, value)
                ]
    return data


def _compare(left: Any, op: str, right: Any) -> bool:
    """Compare two values with operator."""
    if left is None:
        return False

    try:
        if op == "==":
            return str(left) == str(right)
        elif op == "!=":
            return str(left) != str(right)
        elif op == ">":
            return float(left) > float(right)
        elif op == "<":
            return float(left) < float(right)
        elif op == ">=":
            return float(left) >= float(right)
        elif op == "<=":
            return float(left) <= float(right)
    except (ValueError, TypeError):
        pass
    return False


def format_path(template: str, data: dict[str, Any]) -> str:
    """Format a string template with values from data.

    Args:
        template: String with {path} placeholders
        data: Data to resolve paths against

    Returns:
        Formatted string with resolved values

    Examples:
        >>> data = {"hosts": [{"ip": "192.168.1.1", "ports": [{"port": 22}]}]}
        >>> format_path("{hosts[0].ip}:{hosts[0].ports[0].port}", data)
        "192.168.1.1:22"
    """
    result = template

    # Find all {path} placeholders
    pattern = r"\{([^}]+)\}"
    for match in re.finditer(pattern, template):
        path = match.group(1)
        value = resolve_path(data, path)
        if value is not None:
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            result = result.replace(match.group(0), str(value))

    return result


def extract_keys(data: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    """Extract specific keys from a nested data structure.

    Args:
        data: Source data
        keys: List of paths to extract

    Returns:
        Dict with extracted values keyed by path
    """
    return {key: resolve_path(data, key) for key in keys}


def flatten_list(data: list[Any]) -> list[Any]:
    """Flatten a nested list one level.

    Args:
        data: Potentially nested list

    Returns:
        Flattened list
    """
    result = []
    for item in data:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result
