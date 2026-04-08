from __future__ import annotations

import re
import shlex

from .constants import WRAPPER_TOKENS as _WRAPPER_TOKENS, SHELL_WRAPPERS as _SHELL_WRAPPERS

def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1].lower()

def extract_primary_binary(command: str) -> str:
    cmd = str(command or "").strip()
    if not cmd:
        return ""

    cmd = re.sub(r"^cd\s+/workspace(?:/[^\s]*)?\s*&&\s*", "", cmd)

    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    if not tokens:
        return ""

    i = 0
    while i < len(tokens):
        token = tokens[i]
        token_base = _basename(token)

        if token_base in _SHELL_WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            if i < len(tokens):
                nested = extract_primary_binary(tokens[i])
                if nested:
                    return nested
            return token_base

        if token_base in _WRAPPER_TOKENS:
            i += 1

            if token_base == "timeout":  # nosec B105

                while i < len(tokens) and tokens[i].startswith("-"):
                    i += 1
                if i < len(tokens) and re.match(r"^\d+[smhd]?$", tokens[i]):
                    i += 1
                if i < len(tokens) and tokens[i] == "--":
                    i += 1

            elif token_base == "stdbuf":  # nosec B105
                while i < len(tokens) and tokens[i].startswith("-"):
                    i += 1

            elif token_base == "env":  # nosec B105

                while i < len(tokens):
                    t = tokens[i]
                    if t == "--":
                        i += 1
                        break
                    if t.startswith("-"):
                        if t in {"-u", "--unset"} and i + 1 < len(tokens):
                            i += 2
                        else:
                            i += 1
                        continue
                    if "=" in t and not t.startswith("-"):
                        i += 1
                        continue
                    break

            continue

        if token.startswith("-"):
            i += 1
            continue

        return token_base

    return ""
