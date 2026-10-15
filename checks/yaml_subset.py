"""Dependency-free YAML subset parser for docker-compose files.

Strategy: use PyYAML's safe_load when available (recommended), otherwise fall
back to a small indentation-based parser that handles the YAML subset most
compose files use: nested maps, lists, lists of maps, quoted strings,
numbers, booleans, null.

The fallback does NOT support: flow style (``[a, b]`` / ``{k: v}``),
anchors/aliases, multi-line block scalars (``|`` / ``>``), or multi-document
files. For full YAML support: ``pip install pyyaml`` (optional).
"""

import re

try:
    import yaml as _pyyaml

    _HAVE_PYYAML = True
except ImportError:  # pragma: no cover - exercised via fallback tests
    _pyyaml = None
    _HAVE_PYYAML = False


def _strip_comment(line):
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
    return line


def _coerce(value):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


_PORT_RE = re.compile(r"^[\d\.\:\[\]]+(/\w+)?$")


def _is_list_item(content):
    return content == "-" or content.startswith("- ") or content.startswith("-\t")


def _parse_block(tokens, pos, indent):
    if pos < len(tokens) and _is_list_item(tokens[pos][1]):
        return _parse_list(tokens, pos, indent)
    return _parse_map(tokens, pos, indent)


def _parse_map(tokens, pos, indent):
    result = {}
    n = len(tokens)
    while pos < n:
        ind, content = tokens[pos]
        if ind != indent or _is_list_item(content):
            break
        key, sep, value = content.partition(":")
        if not sep:
            pos += 1
            continue
        key = key.strip().strip("\"'")
        value = value.strip()
        pos += 1
        if value == "":
            if pos < n and tokens[pos][0] > indent:
                child, pos = _parse_block(tokens, pos, tokens[pos][0])
                result[key] = child
            else:
                result[key] = None
        else:
            result[key] = _coerce(value)
    return result, pos


def _parse_list(tokens, pos, indent):
    items = []
    n = len(tokens)
    while pos < n:
        ind, content = tokens[pos]
        if ind != indent or not _is_list_item(content):
            break
        item_text = content[1:].strip()
        bare_text = item_text.strip("\"'")
        pos += 1
        if item_text == "":
            if pos < len(tokens) and tokens[pos][0] > indent:
                child, pos = _parse_block(tokens, pos, tokens[pos][0])
                items.append(child)
            else:
                items.append(None)
        elif (
            ":" in bare_text
            and not _PORT_RE.match(bare_text)
            and "=" not in bare_text.split(":")[0]
        ):
            # "- key: value" starts an inline mapping; more keys may follow.
            key, _, value = item_text.partition(":")
            mapping = {}
            first_val = value.strip()
            if first_val == "" and pos < n and tokens[pos][0] > indent:
                child, pos = _parse_block(tokens, pos, tokens[pos][0])
                mapping[key.strip().strip("\"'")] = child
            else:
                mapping[key.strip().strip("\"'")] = _coerce(first_val)
            while pos < n and tokens[pos][0] > indent:
                sub_ind, sub = tokens[pos]
                if _is_list_item(sub):
                    break
                k2, sep2, v2 = sub.partition(":")
                if not sep2:
                    break
                pos += 1
                v2s = v2.strip()
                if v2s == "" and pos < n and tokens[pos][0] > sub_ind:
                    child, pos = _parse_block(tokens, pos, tokens[pos][0])
                    mapping[k2.strip().strip("\"'")] = child
                else:
                    mapping[k2.strip().strip("\"'")] = _coerce(v2s)
            items.append(mapping)
        else:
            items.append(_coerce(item_text))
    return items, pos


def parse_subset(text):
    """Parse the supported YAML subset without any dependency."""
    tokens = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        tokens.append((indent, line.strip()))
    if not tokens:
        return {}
    value, _ = _parse_block(tokens, 0, tokens[0][0])
    return value


def load(text):
    """Parse YAML text, preferring PyYAML, else the built-in subset parser."""
    if _HAVE_PYYAML:
        return _pyyaml.safe_load(text)
    return parse_subset(text)


def using_pyyaml():
    return _HAVE_PYYAML
