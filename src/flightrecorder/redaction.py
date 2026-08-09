import re
from dataclasses import dataclass


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(token|secret|password|passwd|api[_-]?key|authorization|cookie|credential|private[_-]?key)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_OPTION = re.compile(
    r"(?i)^-{1,2}(token|secret|password|passwd|api[_-]?key|authorization|cookie|credential|private[_-]?key)$"
)
_SECRET_OPTION_VALUE = re.compile(
    r"(?i)^(-{1,2}(?:token|secret|password|passwd|api[_-]?key|authorization|cookie|credential|private[_-]?key))([:=])(.+)$"
)


@dataclass(frozen=True)
class RedactionResult:
    value: bytes
    count: int


class Redactor:
    """Best-effort, fail-closed-at-call-site redaction before persistence."""

    def __init__(self, known_values: tuple[str, ...] = ()) -> None:
        self._known_values = tuple(value for value in known_values if len(value) >= 4)

    def redact(self, value: bytes | str) -> RedactionResult:
        if isinstance(value, bytes):
            raw = value
        else:
            raw = value.encode("utf-8", "surrogateescape")

        count = 0
        for known in self._known_values:
            encoded = known.encode("utf-8", "surrogateescape")
            occurrences = raw.count(encoded)
            if occurrences:
                raw = raw.replace(encoded, b"[REDACTED]")
                count += occurrences

        try:
            text = raw.decode("utf-8", "surrogateescape")
            text, substitutions = _SECRET_ASSIGNMENT.subn(
                lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text
            )
            text, bearer_substitutions = _BEARER.subn("Bearer [REDACTED]", text)
            raw = text.encode("utf-8", "surrogateescape")
            count += substitutions + bearer_substitutions
        except UnicodeError:
            # Opaque binary is preserved byte-for-byte unless a known value matched.
            pass

        return RedactionResult(raw, count)

    def redact_argv(self, argv: tuple[str, ...] | list[str]) -> tuple[list[str], int]:
        """Redact both inline and separate values for sensitive CLI options."""
        sensitive_values: list[str] = []
        pending_value = False
        for item in argv:
            inline = _SECRET_OPTION_VALUE.match(item)
            if inline:
                sensitive_values.append(inline.group(3))
                continue
            if pending_value:
                sensitive_values.append(item)
                pending_value = False
                continue
            if _SECRET_OPTION.fullmatch(item):
                pending_value = True

        self._known_values = tuple(
            dict.fromkeys(
                (*self._known_values, *(value for value in sensitive_values if len(value) >= 4))
            )
        )

        redacted: list[str] = []
        count = 0
        pending_value = False
        for item in argv:
            inline = _SECRET_OPTION_VALUE.match(item)
            if inline:
                redacted.append(f"{inline.group(1)}{inline.group(2)}[REDACTED]")
                count += 1
                continue
            if pending_value:
                redacted.append("[REDACTED]")
                count += 1
                pending_value = False
                continue
            redacted_item = self.redact(item)
            redacted.append(redacted_item.value.decode("utf-8", "replace"))
            count += redacted_item.count
            if _SECRET_OPTION.fullmatch(item):
                pending_value = True
        return redacted, count
