"""
Input Generators - Generate fuzzing inputs from scratch.

Supports random, template-based, grammar-based, and corpus-derived generation.
"""

from __future__ import annotations

import json
import random
import re
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import structlog

logger = structlog.get_logger()


class InputGenerator(ABC):
    """Base class for input generators."""

    @abstractmethod
    def generate(self) -> bytes:
        """Generate a single input."""
        pass

    def generate_batch(self, count: int) -> list[bytes]:
        """Generate multiple inputs."""
        return [self.generate() for _ in range(count)]


class RandomGenerator(InputGenerator):
    """Generate random byte sequences."""

    def __init__(
        self,
        min_length: int = 1,
        max_length: int = 1024,
        charset: bytes | None = None
    ):
        self.min_length = min_length
        self.max_length = max_length
        self.charset = charset

    def generate(self) -> bytes:
        length = random.randint(self.min_length, self.max_length)

        if self.charset:
            return bytes(random.choice(self.charset) for _ in range(length))
        else:
            return bytes(random.randint(0, 255) for _ in range(length))


class PrintableGenerator(RandomGenerator):
    """Generate printable ASCII strings."""

    def __init__(self, min_length: int = 1, max_length: int = 256):
        super().__init__(
            min_length=min_length,
            max_length=max_length,
            charset=string.printable.encode()
        )


class TemplateGenerator(InputGenerator):
    """
    Generate inputs based on templates with placeholders.

    Template syntax:
        {{int}} - Random integer
        {{int:MIN:MAX}} - Integer in range
        {{str}} - Random string
        {{str:LEN}} - String of specific length
        {{hex:LEN}} - Hex string
        {{choice:A,B,C}} - Random choice
        {{fuzz}} - Fuzz marker
    """

    def __init__(self, template: str):
        self.template = template
        self.pattern = re.compile(r'\{\{(\w+)(?::([^}]*))?\}\}')

    def generate(self) -> bytes:
        def replace(match: re.Match) -> str:
            placeholder = match.group(1)
            args = match.group(2)

            if placeholder == "int":
                if args:
                    parts = args.split(":")
                    min_val = int(parts[0]) if len(parts) > 0 else 0
                    max_val = int(parts[1]) if len(parts) > 1 else 2**31
                    return str(random.randint(min_val, max_val))
                return str(random.randint(0, 2**31))

            elif placeholder == "str":
                length = int(args) if args else random.randint(1, 32)
                chars = string.ascii_letters + string.digits
                return ''.join(random.choice(chars) for _ in range(length))

            elif placeholder == "hex":
                length = int(args) if args else 16
                return ''.join(random.choice("0123456789abcdef") for _ in range(length))

            elif placeholder == "choice":
                if args:
                    choices = args.split(",")
                    return random.choice(choices)
                return ""

            elif placeholder == "uuid":
                import uuid
                return str(uuid.uuid4())

            elif placeholder == "email":
                return f"fuzz{random.randint(1, 9999)}@test.com"

            elif placeholder == "url":
                return f"http://localhost/{random.randint(1, 9999)}"

            elif placeholder == "fuzz":
                # Insert fuzz marker for mutation
                return "FUZZ" + str(random.randint(1, 999))

            return match.group(0)

        result = self.pattern.sub(replace, self.template)
        return result.encode()


class GrammarGenerator(InputGenerator):
    """
    Generate inputs based on context-free grammar.

    Grammar format:
        {
            "start": ["<expr>"],
            "expr": ["<term> + <term>", "<term>"],
            "term": ["<number>", "(<expr>)"],
            "number": ["0", "1", "2", ...]
        }
    """

    def __init__(
        self,
        grammar: dict[str, list[str]],
        max_depth: int = 10,
        start_symbol: str = "start"
    ):
        self.grammar = grammar
        self.max_depth = max_depth
        self.start_symbol = start_symbol
        self.pattern = re.compile(r'<(\w+)>')

    def generate(self) -> bytes:
        result = self._expand(f"<{self.start_symbol}>", 0)
        return result.encode()

    def _expand(self, text: str, depth: int) -> str:
        if depth >= self.max_depth:
            # Remove remaining non-terminals
            return self.pattern.sub("", text)

        def replace(match: re.Match) -> str:
            symbol = match.group(1)
            if symbol in self.grammar:
                return random.choice(self.grammar[symbol])
            return match.group(0)

        # Keep expanding until no more non-terminals
        prev = ""
        while prev != text and depth < self.max_depth:
            prev = text
            text = self.pattern.sub(replace, text)
            depth += 1

        return text

    @classmethod
    def for_json(cls) -> GrammarGenerator:
        """Create generator for JSON."""
        grammar = {
            "start": ["<value>"],
            "value": [
                "<object>", "<array>", "<string>",
                "<number>", "true", "false", "null"
            ],
            "object": ["{}", "{<members>}"],
            "members": ["<pair>", "<pair>, <members>"],
            "pair": ["<string>: <value>"],
            "array": ["[]", "[<elements>]"],
            "elements": ["<value>", "<value>, <elements>"],
            "string": [
                '""', '"test"', '"<chars>"', '"\\n"', '"\\u0000"'
            ],
            "chars": ["a", "ab", "abc", "test123", "<attack>"],
            "attack": [
                "' OR '1'='1", "<script>alert(1)</script>",
                "../../../etc/passwd", "${7*7}"
            ],
            "number": [
                "0", "1", "-1", "123", "99999999999",
                "1.5", "-0.001", "1e10", "1e-10"
            ],
        }
        return cls(grammar)

    @classmethod
    def for_xml(cls) -> GrammarGenerator:
        """Create generator for XML."""
        grammar = {
            "start": ["<document>"],
            "document": [
                '<?xml version="1.0"?><root><content></root>',
                '<root><content></root>',
                '<xxe_test>'
            ],
            "content": [
                "<element>", "<element><content>", ""
            ],
            "element": [
                "<tag><value></tag>",
                "<tag attr=\"<attrval>\"><value></tag>"
            ],
            "tag": ["item", "data", "test", "node"],
            "value": ["text", "<number>", "<attack>", "<content>"],
            "attrval": ["value", "<attack>"],
            "attack": [
                "&xxe;", "]]>", "<!--", "<?", "<!ENTITY"
            ],
            "number": ["0", "1", "123", "-1"],
            "xxe_test": [
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ],
        }
        return cls(grammar)

    @classmethod
    def for_http_request(cls) -> GrammarGenerator:
        """Create generator for HTTP requests."""
        grammar = {
            "start": ["<method> <path> HTTP/1.1\r\nHost: <host>\r\n<headers>\r\n\r\n<body>"],
            "method": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            "path": ["/", "/api", "/api/<resource>", "/<attack>", "/api?<params>"],
            "resource": ["users", "items", "data", "admin", "config", "..%2f..%2fetc/passwd"],
            "host": ["localhost", "127.0.0.1", "example.com", "<attack>"],
            "headers": ["", "<header>\r\n<headers>"],
            "header": [
                "Content-Type: application/json",
                "Content-Type: <attack>",
                "Authorization: Bearer <token>",
                "X-Custom: <attack>",
                "Content-Length: <number>"
            ],
            "token": ["test123", "{{attack}}", "<attack>"],
            "params": ["id=1", "id=<attack>", "file=<attack>"],
            "body": ["", '{"test": "<attack>"}', "<attack>"],
            "attack": [
                "' OR '1'='1", "../../../etc/passwd",
                "<script>alert(1)</script>", "{{7*7}}",
                "; cat /etc/passwd", "| id"
            ],
            "number": ["0", "-1", "99999999", "1"],
        }
        return cls(grammar)

    @classmethod
    def for_sql(cls) -> GrammarGenerator:
        """Create generator for SQL queries."""
        grammar = {
            "start": ["<query>"],
            "query": [
                "SELECT <columns> FROM <table> <where>",
                "INSERT INTO <table> VALUES (<values>)",
                "UPDATE <table> SET <assignments> <where>",
                "DELETE FROM <table> <where>",
            ],
            "columns": ["*", "<column>", "<column>, <columns>"],
            "column": ["id", "name", "data", "<attack>"],
            "table": ["users", "items", "data", "<attack>"],
            "where": ["", "WHERE <condition>"],
            "condition": [
                "<column> = <value>",
                "<column> = '<attack>'",
                "1=1", "1=0",
                "<column> LIKE '%<attack>%'"
            ],
            "values": ["<value>", "<value>, <values>"],
            "value": ["1", "'test'", "NULL", "'<attack>'"],
            "assignments": ["<column> = <value>"],
            "attack": [
                "'; DROP TABLE users;--",
                "' OR '1'='1",
                "' UNION SELECT * FROM users--",
                "1; SELECT * FROM users",
            ],
        }
        return cls(grammar)


class CorpusGenerator(InputGenerator):
    """Generate inputs by mutating corpus samples."""

    def __init__(
        self,
        corpus_dir: str | Path,
        mutation_rate: float = 0.1
    ):
        self.corpus_dir = Path(corpus_dir)
        self.mutation_rate = mutation_rate
        self.samples: list[bytes] = []
        self._load_corpus()

    def _load_corpus(self) -> None:
        """Load corpus samples from directory."""
        if not self.corpus_dir.exists():
            return

        for file in self.corpus_dir.rglob("*"):
            if file.is_file() and file.stat().st_size < 1_000_000:
                try:
                    self.samples.append(file.read_bytes())
                except Exception:
                    pass

        logger.info("corpus_loaded", samples=len(self.samples))

    def generate(self) -> bytes:
        if not self.samples:
            return RandomGenerator().generate()

        sample = random.choice(self.samples)

        # Apply light mutations
        from shadow_worker.fuzzing.mutators import ByteMutator
        mutator = ByteMutator(mutation_rate=self.mutation_rate)
        return mutator.mutate(sample)


class ProtocolGenerator(InputGenerator):
    """Generate protocol-specific messages."""

    def __init__(self, protocol: str):
        self.protocol = protocol.lower()

    def generate(self) -> bytes:
        if self.protocol == "http":
            return self._generate_http()
        elif self.protocol == "websocket":
            return self._generate_websocket()
        elif self.protocol == "graphql":
            return self._generate_graphql()
        elif self.protocol == "grpc":
            return self._generate_grpc()
        else:
            return RandomGenerator().generate()

    def _generate_http(self) -> bytes:
        return GrammarGenerator.for_http_request().generate()

    def _generate_websocket(self) -> bytes:
        """Generate WebSocket message."""
        messages = [
            b'{"type": "message", "data": "test"}',
            b'{"type": "subscribe", "channel": "test"}',
            b'{"action": "ping"}',
        ]

        msg = random.choice(messages)
        # Add WebSocket frame header (simplified)
        return b'\x81' + bytes([len(msg)]) + msg

    def _generate_graphql(self) -> bytes:
        """Generate GraphQL query."""
        queries = [
            '{"query": "{ __schema { types { name } } }"}',
            '{"query": "query { users { id name } }"}',
            '{"query": "mutation { createUser(name: \\"{{attack}}\\") { id } }"}',
            '{"query": "{ user(id: \\"{{attack}}\\") { name } }"}',
        ]

        query = random.choice(queries)
        query = query.replace("{{attack}}", random.choice([
            "' OR '1'='1", "${7*7}", "<script>", "../../../etc/passwd"
        ]))

        return query.encode()

    def _generate_grpc(self) -> bytes:
        """Generate gRPC-like message (simplified protobuf)."""
        # Simplified protobuf-like structure
        msg = bytearray()

        # Field 1: string
        msg.extend(b'\x0a')  # Field 1, wire type 2 (length-delimited)
        data = b"test_value"
        msg.append(len(data))
        msg.extend(data)

        # Field 2: int32
        msg.extend(b'\x10')  # Field 2, wire type 0 (varint)
        msg.append(random.randint(0, 127))

        return bytes(msg)


class SmartGenerator(InputGenerator):
    """
    Intelligent generator that combines multiple strategies.

    Learns from successful inputs to improve generation.
    """

    def __init__(self):
        self.generators = [
            RandomGenerator(),
            PrintableGenerator(),
            GrammarGenerator.for_json(),
            GrammarGenerator.for_http_request(),
            TemplateGenerator('{"id": {{int}}, "name": "{{str:10}}"}'),
        ]

        self.weights = [1.0] * len(self.generators)
        self.success_counts = [0] * len(self.generators)
        self.attempt_counts = [0] * len(self.generators)

    def generate(self) -> bytes:
        # Select generator based on weights
        idx = random.choices(range(len(self.generators)), weights=self.weights, k=1)[0]
        self.attempt_counts[idx] += 1

        return self.generators[idx].generate()

    def record_success(self, generator_idx: int) -> None:
        """Record successful generation."""
        self.success_counts[generator_idx] += 1

        # Update weights
        for i in range(len(self.generators)):
            if self.attempt_counts[i] > 0:
                self.weights[i] = (
                    self.success_counts[i] / self.attempt_counts[i] + 0.1
                )
