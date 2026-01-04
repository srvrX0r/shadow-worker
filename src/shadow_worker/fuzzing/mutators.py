"""
Fuzzing Mutators - Advanced input mutation strategies.

Provides intelligent mutation operators for maximum code coverage
and vulnerability discovery.
"""

from __future__ import annotations

import random
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


# Interesting values for mutation
INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
INTERESTING_16 = [0, 1, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
INTERESTING_32 = [
    0, 1, 32768, 65535, 65536, 100663045, 2147483647, 2147483648, 4294967295
]

# Common attack strings
ATTACK_STRINGS = [
    # SQL Injection
    b"'",
    b"\"",
    b"' OR '1'='1",
    b"'; DROP TABLE users;--",
    b"1' AND '1'='1",
    b"' UNION SELECT NULL--",
    b"1; SELECT * FROM users",

    # XSS
    b"<script>alert(1)</script>",
    b"<img src=x onerror=alert(1)>",
    b"javascript:alert(1)",
    b"'\"><script>alert(1)</script>",

    # Command Injection
    b"; ls -la",
    b"| cat /etc/passwd",
    b"$(whoami)",
    b"`id`",
    b"|| ping -c 1 localhost",

    # Path Traversal
    b"../../../etc/passwd",
    b"....//....//etc/passwd",
    b"..\\..\\..\\windows\\system32\\config\\sam",

    # Format String
    b"%s%s%s%s%s%s%s%s%s%s",
    b"%n%n%n%n%n",
    b"%x%x%x%x",
    b"AAAA%08x.%08x.%08x.%08x",

    # Integer Overflow
    b"4294967295",
    b"2147483647",
    b"-2147483648",
    b"9999999999999999999999999",

    # Buffer Overflow
    b"A" * 100,
    b"A" * 1000,
    b"A" * 10000,

    # NULL bytes
    b"\x00",
    b"\x00\x00\x00\x00",
    b"test\x00hidden",

    # Unicode
    b"\xc0\xae",  # Overlong encoding
    b"\xef\xbb\xbf",  # BOM
    b"\xff\xfe",  # UTF-16 LE BOM

    # SSRF
    b"http://localhost",
    b"http://127.0.0.1",
    b"http://[::1]",
    b"http://169.254.169.254/latest/meta-data/",

    # XXE
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',

    # LDAP Injection
    b"*)(uid=*))(|(uid=*",
    b"admin)(&)",

    # Template Injection
    b"{{7*7}}",
    b"${7*7}",
    b"<%= 7*7 %>",
    b"#{7*7}",
]


class Mutator(ABC):
    """Base class for input mutators."""

    name: str = "base"

    @abstractmethod
    def mutate(self, data: bytes, **kwargs) -> bytes:
        """Mutate input data."""
        pass

    def should_apply(self, data: bytes) -> bool:
        """Check if mutation should be applied."""
        return True


class BitFlipMutator(Mutator):
    """Flip random bits in input."""

    name = "bitflip"

    def __init__(self, flip_count: int = 1):
        self.flip_count = flip_count

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if not data:
            return data

        data = bytearray(data)
        for _ in range(self.flip_count):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)

        return bytes(data)


class ByteMutator(Mutator):
    """Mutate individual bytes."""

    name = "byte"

    def __init__(self, mutation_rate: float = 0.1):
        self.mutation_rate = mutation_rate

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if not data:
            return data

        data = bytearray(data)

        for i in range(len(data)):
            if random.random() < self.mutation_rate:
                mutation_type = random.randint(0, 4)

                if mutation_type == 0:
                    # Random byte
                    data[i] = random.randint(0, 255)
                elif mutation_type == 1:
                    # Interesting byte
                    data[i] = random.choice(INTERESTING_8)
                elif mutation_type == 2:
                    # Increment
                    data[i] = (data[i] + 1) % 256
                elif mutation_type == 3:
                    # Decrement
                    data[i] = (data[i] - 1) % 256
                else:
                    # Flip all bits
                    data[i] = data[i] ^ 0xFF

        return bytes(data)


class ArithmeticMutator(Mutator):
    """Apply arithmetic operations to numeric values."""

    name = "arithmetic"

    def __init__(self, max_delta: int = 35):
        self.max_delta = max_delta

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if len(data) < 4:
            return data

        data = bytearray(data)
        width = random.choice([1, 2, 4])
        pos = random.randint(0, len(data) - width)
        delta = random.randint(-self.max_delta, self.max_delta)

        if width == 1:
            data[pos] = (data[pos] + delta) % 256
        elif width == 2 and pos + 2 <= len(data):
            val = struct.unpack("<H", data[pos:pos+2])[0]
            val = (val + delta) % 65536
            data[pos:pos+2] = struct.pack("<H", val)
        elif width == 4 and pos + 4 <= len(data):
            val = struct.unpack("<I", data[pos:pos+4])[0]
            val = (val + delta) % (2**32)
            data[pos:pos+4] = struct.pack("<I", val)

        return bytes(data)


class DictionaryMutator(Mutator):
    """Insert dictionary tokens into input."""

    name = "dictionary"

    def __init__(
        self,
        tokens: list[bytes] | None = None,
        use_attack_strings: bool = True
    ):
        self.tokens = tokens or []
        if use_attack_strings:
            self.tokens.extend(ATTACK_STRINGS)

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if not self.tokens:
            return data

        token = random.choice(self.tokens)
        mutation = random.randint(0, 2)

        if mutation == 0:
            # Insert at random position
            pos = random.randint(0, len(data))
            return data[:pos] + token + data[pos:]
        elif mutation == 1:
            # Replace random section
            if len(data) > len(token):
                pos = random.randint(0, len(data) - len(token))
                return data[:pos] + token + data[pos + len(token):]
            return token
        else:
            # Append
            return data + token


class StructureMutator(Mutator):
    """Mutate input structure (insert, delete, duplicate)."""

    name = "structure"

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if not data:
            return data

        mutation = random.randint(0, 5)

        if mutation == 0:
            # Delete random chunk
            if len(data) > 1:
                start = random.randint(0, len(data) - 1)
                end = random.randint(start + 1, len(data))
                return data[:start] + data[end:]

        elif mutation == 1:
            # Duplicate random chunk
            start = random.randint(0, len(data) - 1)
            end = random.randint(start + 1, min(start + 100, len(data)))
            chunk = data[start:end]
            pos = random.randint(0, len(data))
            return data[:pos] + chunk + data[pos:]

        elif mutation == 2:
            # Insert random bytes
            pos = random.randint(0, len(data))
            length = random.randint(1, 100)
            insert = bytes([random.randint(0, 255) for _ in range(length)])
            return data[:pos] + insert + data[pos:]

        elif mutation == 3:
            # Swap chunks
            if len(data) >= 2:
                p1 = random.randint(0, len(data) - 1)
                p2 = random.randint(0, len(data) - 1)
                data = bytearray(data)
                data[p1], data[p2] = data[p2], data[p1]
                return bytes(data)

        elif mutation == 4:
            # Shuffle section
            if len(data) > 4:
                start = random.randint(0, len(data) - 4)
                end = random.randint(start + 4, min(start + 100, len(data)))
                chunk = list(data[start:end])
                random.shuffle(chunk)
                return data[:start] + bytes(chunk) + data[end:]

        elif mutation == 5:
            # Repeat section
            if len(data) > 1:
                start = random.randint(0, len(data) - 1)
                end = random.randint(start + 1, min(start + 50, len(data)))
                chunk = data[start:end]
                times = random.randint(2, 10)
                return data[:start] + chunk * times + data[end:]

        return data


class GrammarMutator(Mutator):
    """Grammar-aware mutation for structured data."""

    name = "grammar"

    def __init__(self, grammar: dict[str, list[str]] | None = None):
        self.grammar = grammar or self._default_grammar()

    def _default_grammar(self) -> dict[str, list[str]]:
        """Default grammar for common formats."""
        return {
            "json_value": [
                "null", "true", "false", "0", "1", "-1",
                "999999999999999", '""', '"test"', "[]", "{}"
            ],
            "sql_keyword": [
                "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
                "UNION", "WHERE", "AND", "OR", "LIKE"
            ],
            "html_tag": [
                "<script>", "<img>", "<svg>", "<iframe>",
                "<body>", "<div>", "<input>", "<form>"
            ],
        }

    def mutate(self, data: bytes, **kwargs) -> bytes:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return data

        # Detect format and apply appropriate mutations
        if "{" in text and "}" in text:
            text = self._mutate_json_like(text)
        elif "<" in text and ">" in text:
            text = self._mutate_html_like(text)
        elif "SELECT" in text.upper() or "INSERT" in text.upper():
            text = self._mutate_sql_like(text)

        return text.encode("utf-8", errors="replace")

    def _mutate_json_like(self, text: str) -> str:
        """Mutate JSON-like content."""
        values = self.grammar.get("json_value", [])
        if values:
            # Replace a value
            import re
            pattern = r':\s*([^,}\]]+)'
            matches = list(re.finditer(pattern, text))
            if matches:
                match = random.choice(matches)
                replacement = random.choice(values)
                text = text[:match.start(1)] + replacement + text[match.end(1):]
        return text

    def _mutate_html_like(self, text: str) -> str:
        """Mutate HTML-like content."""
        tags = self.grammar.get("html_tag", [])
        if tags:
            # Insert malicious tag
            pos = random.randint(0, len(text))
            tag = random.choice(tags)
            text = text[:pos] + tag + text[pos:]
        return text

    def _mutate_sql_like(self, text: str) -> str:
        """Mutate SQL-like content."""
        keywords = self.grammar.get("sql_keyword", [])
        if keywords:
            # Inject SQL keyword
            keyword = random.choice(keywords)
            text = text + f" {keyword} "
        return text


class SpliceMutator(Mutator):
    """Splice two inputs together."""

    name = "splice"

    def __init__(self, corpus: list[bytes] | None = None):
        self.corpus = corpus or []

    def mutate(self, data: bytes, **kwargs) -> bytes:
        if not self.corpus:
            return data

        other = random.choice(self.corpus)

        # Find splice point
        point1 = random.randint(0, len(data))
        point2 = random.randint(0, len(other))

        return data[:point1] + other[point2:]


class SmartMutator(Mutator):
    """
    Intelligent mutator that combines multiple strategies.

    Adapts mutation strategy based on input characteristics
    and historical success rates.
    """

    name = "smart"

    def __init__(self):
        self.mutators = [
            BitFlipMutator(),
            BitFlipMutator(flip_count=2),
            BitFlipMutator(flip_count=4),
            ByteMutator(),
            ArithmeticMutator(),
            DictionaryMutator(),
            StructureMutator(),
            GrammarMutator(),
        ]

        # Havoc mutators for chaotic mutations
        self.havoc_mutators = [
            BitFlipMutator(flip_count=random.randint(1, 8)),
            ByteMutator(mutation_rate=0.3),
            StructureMutator(),
        ]

        self.success_counts: dict[str, int] = {m.name: 0 for m in self.mutators}
        self.attempt_counts: dict[str, int] = {m.name: 0 for m in self.mutators}

    def mutate(
        self,
        data: bytes,
        strategy: str | None = None,
        havoc_mode: bool = False,
        **kwargs
    ) -> bytes:
        if havoc_mode:
            return self._havoc_mutate(data)

        if strategy:
            mutator = next((m for m in self.mutators if m.name == strategy), None)
            if mutator:
                self.attempt_counts[strategy] += 1
                return mutator.mutate(data, **kwargs)

        # Select based on success rate with exploration
        mutator = self._select_mutator()
        self.attempt_counts[mutator.name] += 1

        # Apply 1-4 mutations
        result = data
        for _ in range(random.randint(1, 4)):
            result = mutator.mutate(result, **kwargs)

        return result

    def _select_mutator(self) -> Mutator:
        """Select mutator using UCB1 (exploration-exploitation balance)."""
        import math

        total_attempts = sum(self.attempt_counts.values()) + 1

        best_score = -1
        best_mutator = self.mutators[0]

        for mutator in self.mutators:
            attempts = self.attempt_counts[mutator.name] + 1
            successes = self.success_counts[mutator.name]

            # UCB1 formula
            exploitation = successes / attempts
            exploration = math.sqrt(2 * math.log(total_attempts) / attempts)
            score = exploitation + exploration

            if score > best_score:
                best_score = score
                best_mutator = mutator

        return best_mutator

    def _havoc_mutate(self, data: bytes) -> bytes:
        """Apply chaotic mutations for deep exploration."""
        result = data

        # Apply 2-16 random mutations
        for _ in range(random.randint(2, 16)):
            mutator = random.choice(self.mutators + self.havoc_mutators)
            result = mutator.mutate(result)

        return result

    def record_success(self, mutator_name: str) -> None:
        """Record that a mutator produced interesting results."""
        if mutator_name in self.success_counts:
            self.success_counts[mutator_name] += 1


class FormatAwareMutator(Mutator):
    """Mutator that understands common data formats."""

    name = "format_aware"

    def __init__(self):
        self.format_handlers = {
            "json": self._mutate_json,
            "xml": self._mutate_xml,
            "http": self._mutate_http,
            "url": self._mutate_url,
        }

    def mutate(self, data: bytes, **kwargs) -> bytes:
        format_type = self._detect_format(data)

        if format_type in self.format_handlers:
            return self.format_handlers[format_type](data)

        # Fall back to byte mutation
        return ByteMutator().mutate(data)

    def _detect_format(self, data: bytes) -> str:
        """Detect data format."""
        try:
            text = data.decode("utf-8", errors="ignore")

            if text.strip().startswith("{") or text.strip().startswith("["):
                return "json"
            elif text.strip().startswith("<?xml") or text.strip().startswith("<"):
                return "xml"
            elif text.startswith("GET ") or text.startswith("POST "):
                return "http"
            elif "://" in text or text.startswith("/"):
                return "url"

        except Exception:
            pass

        return "unknown"

    def _mutate_json(self, data: bytes) -> bytes:
        """Mutate JSON data intelligently."""
        import json as json_lib

        try:
            obj = json_lib.loads(data)
            obj = self._mutate_json_value(obj)
            return json_lib.dumps(obj).encode()
        except Exception:
            return GrammarMutator().mutate(data)

    def _mutate_json_value(self, obj: Any, depth: int = 0) -> Any:
        """Recursively mutate JSON values."""
        if depth > 10:
            return obj

        if isinstance(obj, dict):
            # Mutate values
            for key in obj:
                if random.random() < 0.3:
                    obj[key] = self._mutate_json_value(obj[key], depth + 1)

            # Maybe add new key
            if random.random() < 0.1:
                obj["__fuzz__"] = random.choice([None, True, "", 0, [], {}])

        elif isinstance(obj, list):
            for i in range(len(obj)):
                if random.random() < 0.3:
                    obj[i] = self._mutate_json_value(obj[i], depth + 1)

        elif isinstance(obj, str):
            mutations = [
                lambda s: s + "' OR '1'='1",
                lambda s: "<script>alert(1)</script>",
                lambda s: "../../../etc/passwd",
                lambda s: s * 1000,
                lambda s: "\x00" + s,
                lambda s: s.replace("a", "\u0000"),
            ]
            if random.random() < 0.5:
                obj = random.choice(mutations)(obj)

        elif isinstance(obj, (int, float)):
            mutations = [
                lambda n: 2**31 - 1,
                lambda n: 2**31,
                lambda n: -1,
                lambda n: 0,
                lambda n: 2**63,
                lambda n: float("inf"),
                lambda n: float("nan"),
            ]
            if random.random() < 0.5:
                obj = random.choice(mutations)(obj)

        return obj

    def _mutate_xml(self, data: bytes) -> bytes:
        """Mutate XML data with XXE and other attacks."""
        xxe_payloads = [
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost">]>',
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]>',
        ]

        if random.random() < 0.3:
            return random.choice(xxe_payloads) + data

        return GrammarMutator().mutate(data)

    def _mutate_http(self, data: bytes) -> bytes:
        """Mutate HTTP request/response."""
        try:
            text = data.decode("utf-8")
            lines = text.split("\r\n")

            # Mutate headers
            for i, line in enumerate(lines):
                if ": " in line and random.random() < 0.3:
                    key, val = line.split(": ", 1)

                    # Header-specific mutations
                    if key.lower() == "content-length":
                        val = str(random.choice([0, -1, 999999999]))
                    elif key.lower() == "host":
                        val = random.choice(["localhost", "127.0.0.1", "[::1]"])
                    elif key.lower() == "content-type":
                        val = "../../../etc/passwd"
                    else:
                        val = random.choice(ATTACK_STRINGS).decode(errors="ignore")

                    lines[i] = f"{key}: {val}"

            return "\r\n".join(lines).encode()

        except Exception:
            return data

    def _mutate_url(self, data: bytes) -> bytes:
        """Mutate URL with path traversal, SSRF, etc."""
        try:
            url = data.decode("utf-8")

            mutations = [
                lambda u: u.replace("/", "/../"),
                lambda u: u + "?file=../../../etc/passwd",
                lambda u: u.replace("://", "://localhost@"),
                lambda u: u + "\r\nX-Injected: header",
                lambda u: "http://localhost/" + u.split("/")[-1],
                lambda u: u + "#" + "<script>alert(1)</script>",
            ]

            return random.choice(mutations)(url).encode()

        except Exception:
            return data
