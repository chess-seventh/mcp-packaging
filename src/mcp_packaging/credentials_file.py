"""Pure parse of a KEY=VALUE credentials file, and a pure requirement check.

ADR-002 §1: every one of the five future consumers reads a credentials file, and
none of them should write this twice. The file *reading* stays in each consumer's
composition root; only the parse and the requirement live here.

Nothing in this module opens a file, reads an environment, or names a variable of
its own. It is handed text and a list of keys, and it answers about those.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

#: What separates a name from its value. One character, spelled once, because a
#: value may itself contain it and only the FIRST one separates.
ASSIGNMENT = "="

#: A line that says nothing. Comments are honoured because a rendered credentials
#: file is a template, and a template that cannot carry a comment grows a second
#: file that explains it.
COMMENT = "#"

#: The shell-ism a hand-written credentials file picks up from being sourced once.
EXPORT_PREFIX = "export "

#: The quoting a rendered file may carry around a value. Stripped in matched pairs
#: only, so a value that genuinely begins with a quote survives.
QUOTES = ("'", '"')


class CredentialsIncomplete(RuntimeError):
    """A required key is absent from the credentials mapping.

    Carries the missing KEY and never a value: ADR-006 §3's named refusal is the
    variable name, and C8 forbids the value at any level.
    """

    def __init__(self, missing_key: str) -> None:
        """Record which key was missing, and nothing else.

        Args:
            missing_key: The name of the absent variable.
        """
        super().__init__(f"credentials file is missing {missing_key}")
        self.missing_key = missing_key


def parse(text: str) -> Mapping[str, str]:
    """Parse KEY=VALUE credentials text into a mapping.

    A key present with an empty value is KEPT as an empty string rather than
    dropped. The two are materially different and only ``require`` may collapse
    them: a parser that quietly dropped a blank value would make "the key is there
    but empty" indistinguishable from "the key is absent", and the blank one is the
    realistic template typo.

    Args:
        text: The whole credentials file, as read by the caller.

    Returns:
        A mapping from variable name to value.
    """
    return dict(_assignment(line) for line in text.splitlines() if _is_an_assignment(line))


def require(mapping: Mapping[str, str], keys: Sequence[str]) -> None:
    """Refuse unless every named key is present and non-empty.

    Present-but-empty counts as missing. A blank line in a rendered credentials
    file is the realistic template typo, and carrying it forward means presenting
    an empty secret to the provider and reading the provider's refusal as a
    credential problem it is not.

    Args:
        mapping: The parsed credentials.
        keys: The variable names this service requires.

    Raises:
        CredentialsIncomplete: Naming the first missing key and no value.
    """
    for key in keys:
        if not mapping.get(key, ""):
            raise CredentialsIncomplete(key)


def source_message(path: str) -> str:
    """What a person is told about WHERE the credentials came from.

    Names the PATH, deliberately. A path is not a secret, and it is the one piece
    of information an operator actually needs: the reflex to redact everything in a
    credential message removes exactly the part that makes a fault fixable.

    Args:
        path: The file the values were read from.

    Returns:
        One line, naming the place and no value from it.
    """
    return f"credentials read from {path}"


def refusal_message(path: str, missing_key: str) -> str:
    """What a person is told when a credentials file will not do.

    Names the missing VARIABLE and the PATH. Never a value, at any level - not the
    value that was there, not its length, not a hash of it.

    Args:
        path: The file the values were read from.
        missing_key: The variable that is absent or empty.

    Returns:
        One line an operator can act on.
    """
    return f"{source_message(path)}, and {missing_key} is missing or empty"


def absent_message(path: str) -> str:
    """What a person is told when the file itself is not there.

    A missing file is NAMED rather than guessed at, and nothing else is tried. A
    fallback is the branch that turns "the file is missing" into "we quietly used
    something else", which is how a host ends up running on credentials nobody
    thinks it has.

    Args:
        path: The file the process was told to read.

    Returns:
        One line naming the place it looked.
    """
    return f"no credentials file at {path}, and no other source is consulted"


def _is_an_assignment(line: str) -> bool:
    """Whether a line assigns anything at all."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith(COMMENT) and ASSIGNMENT in stripped


def _assignment(line: str) -> tuple[str, str]:
    """One line as the name it assigns and the value it assigns to it."""
    name, _, value = line.strip().removeprefix(EXPORT_PREFIX).partition(ASSIGNMENT)
    return name.strip(), _unquoted(value.strip())


def _unquoted(value: str) -> str:
    """A value with one matched pair of surrounding quotes removed."""
    for quote in QUOTES:
        if len(value) >= 2 and value.startswith(quote) and value.endswith(quote):
            return value[1:-1]
    return value
