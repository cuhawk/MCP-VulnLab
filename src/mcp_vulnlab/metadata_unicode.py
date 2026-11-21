"""Shared normalization and review of hidden controls in tool metadata."""

import re
import unicodedata

HIDDEN = re.compile(r"[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")

# Common Greek and Cyrillic lookalikes for ASCII identifiers and markup.
CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i",
    "ј": "j", "к": "k", "м": "m", "о": "o", "р": "p", "ѕ": "s", "т": "t",
    "у": "y", "х": "x", "ԛ": "q", "ѵ": "v", "ӏ": "l",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "y", "χ": "x", "ϲ": "c",
})


def canonical(text: str) -> str:
    folded = unicodedata.normalize("NFKC", HIDDEN.sub("", text)).casefold()
    return " ".join(folded.translate(CONFUSABLES).split())


def contains_hidden(value):
    if isinstance(value, str):
        return bool(HIDDEN.search(value))
    if isinstance(value, list):
        return any(contains_hidden(item) for item in value)
    if isinstance(value, dict):
        return any(contains_hidden(key) or contains_hidden(item) for key, item in value.items())
    return False
