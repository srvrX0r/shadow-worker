"""
Protocol Fuzzers - Specialized fuzzers for web protocols.

Provides intelligent fuzzing for HTTP, WebSocket, GraphQL, gRPC, and REST APIs.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import struct
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator
from uuid import UUID, uuid4

import httpx
import structlog

from shadow_worker.fuzzing.engine import FuzzConfig, FuzzInput, FuzzResult, VulnType, Severity
from shadow_worker.fuzzing.mutators import SmartMutator, DictionaryMutator, ATTACK_STRINGS
from shadow_worker.fuzzing.generators import GrammarGenerator, TemplateGenerator

logger = structlog.get_logger()


@dataclass
class ProtocolFuzzResult:
    """Result from protocol fuzzing."""

    id: UUID = field(default_factory=uuid4)
    target: str = ""
    protocol: str = ""

    # Timing
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime | None = None
    duration_seconds: float = 0.0

    # Statistics
    requests_sent: int = 0
    errors: int = 0
    timeouts: int = 0
    interesting_responses: int = 0

    # Findings
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    crashes: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "target": self.target,
            "protocol": self.protocol,
            "duration_seconds": self.duration_seconds,
            "requests_sent": self.requests_sent,
            "vulnerabilities": self.vulnerabilities,
        }


class ProtocolFuzzer(ABC):
    """Base class for protocol fuzzers."""

    protocol: str = "unknown"

    def __init__(self, config: FuzzConfig | None = None):
        self.config = config or FuzzConfig()
        self.mutator = SmartMutator()

    @abstractmethod
    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        **kwargs
    ) -> ProtocolFuzzResult:
        """Run fuzzing against target."""
        pass

    def _check_for_vulnerability(
        self,
        request: bytes,
        response: bytes,
        status_code: int,
        response_time_ms: float
    ) -> dict[str, Any] | None:
        """Analyze response for potential vulnerabilities."""
        vuln = None

        # Error-based detection
        error_patterns = {
            VulnType.INJECTION: [
                b"sql syntax", b"mysql_fetch", b"ORA-", b"PostgreSQL",
                b"sqlite", b"ODBC", b"syntax error"
            ],
            VulnType.INFO_DISCLOSURE: [
                b"stack trace", b"exception", b"error in", b"debug",
                b"/home/", b"/var/", b"root:", b"password"
            ],
            VulnType.XXE: [
                b"root:x:", b"ENTITY", b"DOCTYPE"
            ],
            VulnType.SSRF: [
                b"localhost", b"127.0.0.1", b"169.254", b"metadata"
            ],
        }

        response_lower = response.lower()

        for vuln_type, patterns in error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_lower:
                    vuln = {
                        "type": vuln_type.value,
                        "severity": Severity.HIGH.value,
                        "pattern_matched": pattern.decode(errors="ignore"),
                        "request_preview": request[:200].decode(errors="ignore"),
                        "response_preview": response[:500].decode(errors="ignore"),
                    }
                    break
            if vuln:
                break

        # Status code analysis
        if status_code == 500:
            if not vuln:
                vuln = {
                    "type": VulnType.CRASH.value,
                    "severity": Severity.MEDIUM.value,
                    "status_code": status_code,
                    "request_preview": request[:200].decode(errors="ignore"),
                }

        # Timing analysis (potential for timing attacks)
        if response_time_ms > 10000:
            if not vuln:
                vuln = {
                    "type": VulnType.HANG.value,
                    "severity": Severity.LOW.value,
                    "response_time_ms": response_time_ms,
                }

        return vuln


class HTTPFuzzer(ProtocolFuzzer):
    """
    Advanced HTTP Protocol Fuzzer.

    Features:
    - Header fuzzing
    - Parameter fuzzing
    - Body fuzzing
    - Method fuzzing
    - Path fuzzing
    - Authentication bypass testing
    - WAF bypass techniques
    """

    protocol = "http"

    # HTTP methods to test
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

    # Headers to fuzz
    FUZZ_HEADERS = [
        "Content-Type", "Accept", "User-Agent", "Referer", "Origin",
        "X-Forwarded-For", "X-Real-IP", "X-Custom-Header", "Authorization",
        "Cookie", "Host", "Content-Length", "Transfer-Encoding"
    ]

    # WAF bypass techniques
    WAF_BYPASS = [
        lambda p: p.replace(" ", "/**/"),  # SQL comment bypass
        lambda p: p.replace(" ", "%20"),   # URL encoding
        lambda p: p.replace("'", "%27"),   # Quote encoding
        lambda p: p.upper(),               # Case change
        lambda p: p.lower(),
        lambda p: p.replace("<", "%3C"),   # HTML encoding
        lambda p: p + "\x00",              # Null byte
        lambda p: f"/*!{p}*/",             # MySQL inline comment
    ]

    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        endpoints: list[str] | None = None,
        fuzz_params: bool = True,
        fuzz_headers: bool = True,
        fuzz_body: bool = True,
        fuzz_paths: bool = True,
        **kwargs
    ) -> ProtocolFuzzResult:
        """
        Fuzz HTTP target.

        Args:
            target: Base URL to fuzz
            duration_seconds: Fuzzing duration
            endpoints: Specific endpoints to test
            fuzz_params: Fuzz query parameters
            fuzz_headers: Fuzz HTTP headers
            fuzz_body: Fuzz request body
            fuzz_paths: Fuzz URL paths
        """
        result = ProtocolFuzzResult(target=target, protocol=self.protocol)
        result.start_time = datetime.utcnow()

        start_time = time.time()
        endpoints = endpoints or ["/"]

        async with httpx.AsyncClient(
            timeout=self.config.input_timeout_ms / 1000,
            verify=False,
            follow_redirects=False
        ) as client:

            while (time.time() - start_time) < duration_seconds:
                endpoint = random.choice(endpoints)
                url = urllib.parse.urljoin(target, endpoint)

                # Select fuzzing strategy
                strategies = []
                if fuzz_params:
                    strategies.append(self._fuzz_params)
                if fuzz_headers:
                    strategies.append(self._fuzz_headers)
                if fuzz_body:
                    strategies.append(self._fuzz_body)
                if fuzz_paths:
                    strategies.append(self._fuzz_path)

                if not strategies:
                    strategies = [self._fuzz_params]

                strategy = random.choice(strategies)

                try:
                    vuln = await strategy(client, url, result)
                    if vuln:
                        result.vulnerabilities.append(vuln)

                except httpx.TimeoutException:
                    result.timeouts += 1
                except Exception as e:
                    result.errors += 1
                    logger.debug("http_fuzz_error", error=str(e))

                result.requests_sent += 1

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        logger.info(
            "http_fuzzing_complete",
            target=target,
            requests=result.requests_sent,
            vulns=len(result.vulnerabilities)
        )

        return result

    async def _fuzz_params(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ProtocolFuzzResult
    ) -> dict[str, Any] | None:
        """Fuzz query parameters."""
        attack = random.choice(ATTACK_STRINGS)
        params = {"fuzz": attack.decode(errors="ignore")}

        # Add WAF bypass
        if random.random() < 0.3:
            bypass = random.choice(self.WAF_BYPASS)
            params["fuzz"] = bypass(params["fuzz"])

        start = time.time()
        response = await client.get(url, params=params)
        elapsed = (time.time() - start) * 1000

        request_bytes = f"GET {url}?fuzz={params['fuzz']}".encode()
        response_bytes = response.content

        return self._check_for_vulnerability(
            request_bytes, response_bytes, response.status_code, elapsed
        )

    async def _fuzz_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ProtocolFuzzResult
    ) -> dict[str, Any] | None:
        """Fuzz HTTP headers."""
        header_name = random.choice(self.FUZZ_HEADERS)
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")

        headers = {header_name: attack}

        # Special header attacks
        if header_name == "Host":
            headers["Host"] = random.choice([
                "localhost", "127.0.0.1", "evil.com", "[::1]"
            ])
        elif header_name == "X-Forwarded-For":
            headers["X-Forwarded-For"] = "127.0.0.1"
        elif header_name == "Content-Length":
            headers["Content-Length"] = str(random.choice([-1, 0, 999999999]))

        start = time.time()
        response = await client.get(url, headers=headers)
        elapsed = (time.time() - start) * 1000

        request_bytes = f"GET {url}\n{header_name}: {attack}".encode()
        return self._check_for_vulnerability(
            request_bytes, response.content, response.status_code, elapsed
        )

    async def _fuzz_body(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ProtocolFuzzResult
    ) -> dict[str, Any] | None:
        """Fuzz request body."""
        content_types = [
            ("application/json", self._generate_json_body),
            ("application/xml", self._generate_xml_body),
            ("application/x-www-form-urlencoded", self._generate_form_body),
            ("multipart/form-data", self._generate_multipart_body),
        ]

        content_type, generator = random.choice(content_types)
        body = generator()

        headers = {"Content-Type": content_type}

        start = time.time()
        response = await client.post(url, content=body, headers=headers)
        elapsed = (time.time() - start) * 1000

        return self._check_for_vulnerability(
            body, response.content, response.status_code, elapsed
        )

    async def _fuzz_path(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ProtocolFuzzResult
    ) -> dict[str, Any] | None:
        """Fuzz URL path."""
        path_attacks = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/admin",
            "/api/v1/../../../etc/passwd",
            "/.git/config",
            "/.env",
            "/server-status",
            "/debug",
            "/phpinfo.php",
        ]

        path = random.choice(path_attacks)
        fuzz_url = urllib.parse.urljoin(url, path)

        start = time.time()
        response = await client.get(fuzz_url)
        elapsed = (time.time() - start) * 1000

        # Check for sensitive file exposure
        sensitive_patterns = [b"root:", b"password", b"[core]", b"DB_PASSWORD"]
        for pattern in sensitive_patterns:
            if pattern in response.content:
                return {
                    "type": VulnType.INFO_DISCLOSURE.value,
                    "severity": Severity.CRITICAL.value,
                    "path": path,
                    "pattern_matched": pattern.decode(errors="ignore"),
                }

        return self._check_for_vulnerability(
            path.encode(), response.content, response.status_code, elapsed
        )

    def _generate_json_body(self) -> bytes:
        """Generate fuzzed JSON body."""
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")
        body = {
            "id": random.choice([1, -1, 999999999, "1' OR '1'='1"]),
            "name": attack,
            "data": {"nested": attack},
            "items": [attack, 1, None, True],
        }
        return json.dumps(body).encode()

    def _generate_xml_body(self) -> bytes:
        """Generate fuzzed XML body with XXE."""
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            '<root><data><![CDATA[<script>alert(1)</script>]]></data></root>',
        ]
        return random.choice(xxe_payloads).encode()

    def _generate_form_body(self) -> bytes:
        """Generate fuzzed form body."""
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")
        params = urllib.parse.urlencode({
            "username": attack,
            "password": attack,
            "data": attack,
        })
        return params.encode()

    def _generate_multipart_body(self) -> bytes:
        """Generate fuzzed multipart body."""
        boundary = "----FuzzBoundary"
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")

        body = f"""--{boundary}\r
Content-Disposition: form-data; name="file"; filename="{attack}"\r
Content-Type: application/octet-stream\r
\r
{attack}\r
--{boundary}--\r
"""
        return body.encode()


class WebSocketFuzzer(ProtocolFuzzer):
    """
    WebSocket Protocol Fuzzer.

    Features:
    - Message fuzzing
    - Frame manipulation
    - State machine testing
    - Connection flooding
    """

    protocol = "websocket"

    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        **kwargs
    ) -> ProtocolFuzzResult:
        """Fuzz WebSocket endpoint."""
        import websockets

        result = ProtocolFuzzResult(target=target, protocol=self.protocol)
        result.start_time = datetime.utcnow()

        start_time = time.time()

        # Convert http to ws
        ws_url = target.replace("http://", "ws://").replace("https://", "wss://")

        while (time.time() - start_time) < duration_seconds:
            try:
                async with websockets.connect(ws_url, close_timeout=5) as ws:
                    # Send fuzzed messages
                    for _ in range(random.randint(1, 10)):
                        message = self._generate_message()

                        try:
                            await asyncio.wait_for(ws.send(message), timeout=5)
                            result.requests_sent += 1

                            response = await asyncio.wait_for(ws.recv(), timeout=5)

                            # Check response
                            vuln = self._analyze_ws_response(message, response)
                            if vuln:
                                result.vulnerabilities.append(vuln)

                        except asyncio.TimeoutError:
                            result.timeouts += 1
                        except Exception:
                            result.errors += 1

            except Exception as e:
                result.errors += 1
                logger.debug("websocket_error", error=str(e))

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _generate_message(self) -> str | bytes:
        """Generate fuzzed WebSocket message."""
        message_types = [
            self._generate_json_message,
            self._generate_text_message,
            self._generate_binary_message,
        ]

        return random.choice(message_types)()

    def _generate_json_message(self) -> str:
        """Generate JSON WebSocket message."""
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")

        templates = [
            {"type": "message", "data": attack},
            {"action": attack, "payload": {"nested": attack}},
            {"command": "eval", "code": attack},
            {"id": random.randint(-999999, 999999), "method": attack},
        ]

        return json.dumps(random.choice(templates))

    def _generate_text_message(self) -> str:
        """Generate text WebSocket message."""
        return random.choice(ATTACK_STRINGS).decode(errors="ignore")

    def _generate_binary_message(self) -> bytes:
        """Generate binary WebSocket message."""
        return self.mutator.mutate(random.choice(ATTACK_STRINGS))

    def _analyze_ws_response(
        self,
        request: str | bytes,
        response: str | bytes
    ) -> dict[str, Any] | None:
        """Analyze WebSocket response for vulnerabilities."""
        if isinstance(response, str):
            response = response.encode()
        if isinstance(request, str):
            request = request.encode()

        return self._check_for_vulnerability(request, response, 200, 0)


class GraphQLFuzzer(ProtocolFuzzer):
    """
    GraphQL Protocol Fuzzer.

    Features:
    - Query fuzzing
    - Mutation fuzzing
    - Introspection attacks
    - Batch query attacks
    - Alias-based DoS
    - Field suggestion extraction
    """

    protocol = "graphql"

    # Introspection queries
    INTROSPECTION_QUERIES = [
        '{"query": "{ __schema { types { name fields { name } } } }"}',
        '{"query": "{ __type(name: \\"User\\") { name fields { name type { name } } } }"}',
        '{"query": "{ __schema { queryType { name } mutationType { name } } }"}',
    ]

    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        known_types: list[str] | None = None,
        known_fields: list[str] | None = None,
        **kwargs
    ) -> ProtocolFuzzResult:
        """Fuzz GraphQL endpoint."""
        result = ProtocolFuzzResult(target=target, protocol=self.protocol)
        result.start_time = datetime.utcnow()

        start_time = time.time()

        async with httpx.AsyncClient(
            timeout=self.config.input_timeout_ms / 1000,
            verify=False
        ) as client:

            # First, try introspection
            schema_info = await self._try_introspection(client, target)
            if schema_info:
                result.anomalies.append({
                    "type": "introspection_enabled",
                    "severity": "medium",
                    "data": schema_info
                })

            while (time.time() - start_time) < duration_seconds:
                query = self._generate_query(known_types, known_fields)

                try:
                    start = time.time()
                    response = await client.post(
                        target,
                        json={"query": query},
                        headers={"Content-Type": "application/json"}
                    )
                    elapsed = (time.time() - start) * 1000

                    result.requests_sent += 1

                    vuln = self._analyze_graphql_response(
                        query, response.content, response.status_code, elapsed
                    )
                    if vuln:
                        result.vulnerabilities.append(vuln)

                except httpx.TimeoutException:
                    result.timeouts += 1
                except Exception as e:
                    result.errors += 1

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    async def _try_introspection(
        self,
        client: httpx.AsyncClient,
        target: str
    ) -> dict[str, Any] | None:
        """Try to extract schema via introspection."""
        for query in self.INTROSPECTION_QUERIES:
            try:
                response = await client.post(
                    target,
                    content=query,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__schema" in str(data):
                        return data

            except Exception:
                pass

        return None

    def _generate_query(
        self,
        known_types: list[str] | None,
        known_fields: list[str] | None
    ) -> str:
        """Generate fuzzed GraphQL query."""
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")

        query_templates = [
            # Injection in arguments
            f'{{ user(id: "{attack}") {{ id name }} }}',
            f'{{ users(filter: "{attack}") {{ id }} }}',
            f'{{ search(query: "{attack}") {{ results }} }}',

            # Nested query DoS
            '{ users { friends { friends { friends { id } } } } }',

            # Alias-based DoS
            ' '.join([f'a{i}: user(id: {i}) {{ id }}' for i in range(100)]),

            # Directive injection
            f'{{ user @include(if: {attack}) {{ id }} }}',

            # Fragment injection
            f'{{ ...on User {{ id name {attack} }} }}',

            # Batch queries
            '[' + ','.join([
                f'{{"query": "{{ user(id: {i}) {{ id }} }}"}}'
                for i in range(50)
            ]) + ']',
        ]

        # Add mutations
        mutation_templates = [
            f'mutation {{ createUser(name: "{attack}") {{ id }} }}',
            f'mutation {{ updateUser(id: 1, data: "{attack}") {{ id }} }}',
            f'mutation {{ deleteUser(id: "{attack}") {{ success }} }}',
        ]

        all_templates = query_templates + mutation_templates
        return random.choice(all_templates)

    def _analyze_graphql_response(
        self,
        query: str,
        response: bytes,
        status_code: int,
        elapsed: float
    ) -> dict[str, Any] | None:
        """Analyze GraphQL response for vulnerabilities."""
        try:
            data = json.loads(response)

            # Check for detailed error messages
            if "errors" in data:
                for error in data["errors"]:
                    message = str(error.get("message", "")).lower()

                    # SQL errors in GraphQL
                    if any(x in message for x in ["sql", "syntax", "mysql", "postgres"]):
                        return {
                            "type": VulnType.INJECTION.value,
                            "severity": Severity.CRITICAL.value,
                            "query": query[:200],
                            "error": error.get("message", "")[:500],
                        }

                    # Path disclosure
                    if any(x in message for x in ["/var/", "/home/", "\\users\\"]):
                        return {
                            "type": VulnType.INFO_DISCLOSURE.value,
                            "severity": Severity.MEDIUM.value,
                            "error": error.get("message", "")[:500],
                        }

        except json.JSONDecodeError:
            pass

        return self._check_for_vulnerability(
            query.encode(), response, status_code, elapsed
        )


class GRPCFuzzer(ProtocolFuzzer):
    """
    gRPC Protocol Fuzzer.

    Features:
    - Protobuf message fuzzing
    - Service reflection
    - Streaming attacks
    - Metadata injection
    """

    protocol = "grpc"

    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        proto_file: str | None = None,
        **kwargs
    ) -> ProtocolFuzzResult:
        """Fuzz gRPC endpoint."""
        result = ProtocolFuzzResult(target=target, protocol=self.protocol)
        result.start_time = datetime.utcnow()

        start_time = time.time()

        # Try to discover services via reflection
        services = await self._discover_services(target)

        while (time.time() - start_time) < duration_seconds:
            message = self._generate_grpc_message()

            try:
                response = await self._send_grpc_request(target, message)
                result.requests_sent += 1

                if response:
                    vuln = self._analyze_grpc_response(message, response)
                    if vuln:
                        result.vulnerabilities.append(vuln)

            except Exception as e:
                result.errors += 1
                logger.debug("grpc_error", error=str(e))

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    async def _discover_services(self, target: str) -> list[str]:
        """Discover gRPC services via reflection."""
        # Simplified - in practice would use grpc_reflection
        return []

    def _generate_grpc_message(self) -> bytes:
        """Generate fuzzed protobuf-like message."""
        message = bytearray()

        # Generate random protobuf fields
        for field_num in range(1, random.randint(2, 10)):
            wire_type = random.choice([0, 1, 2, 5])  # varint, 64bit, length-delimited, 32bit

            # Field tag
            tag = (field_num << 3) | wire_type
            message.extend(self._encode_varint(tag))

            if wire_type == 0:  # Varint
                val = random.choice([0, 1, -1, 2**31, 2**63, 2**64-1])
                message.extend(self._encode_varint(val & 0xFFFFFFFFFFFFFFFF))

            elif wire_type == 1:  # 64-bit
                message.extend(struct.pack("<Q", random.randint(0, 2**64-1)))

            elif wire_type == 2:  # Length-delimited
                data = random.choice(ATTACK_STRINGS)
                message.extend(self._encode_varint(len(data)))
                message.extend(data)

            elif wire_type == 5:  # 32-bit
                message.extend(struct.pack("<I", random.randint(0, 2**32-1)))

        return bytes(message)

    def _encode_varint(self, value: int) -> bytes:
        """Encode integer as protobuf varint."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result) if result else b'\x00'

    async def _send_grpc_request(
        self,
        target: str,
        message: bytes
    ) -> bytes | None:
        """Send gRPC request (HTTP/2 with protobuf)."""
        # Simplified - would use httpx with HTTP/2 or grpcio
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            try:
                response = await client.post(
                    target,
                    content=message,
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                    }
                )
                return response.content
            except Exception:
                return None

    def _analyze_grpc_response(
        self,
        request: bytes,
        response: bytes
    ) -> dict[str, Any] | None:
        """Analyze gRPC response."""
        return self._check_for_vulnerability(request, response, 200, 0)


class RESTFuzzer(HTTPFuzzer):
    """
    REST API Fuzzer.

    Extends HTTP fuzzer with REST-specific features:
    - OpenAPI/Swagger spec parsing
    - CRUD operation fuzzing
    - Authentication bypass
    - Rate limit testing
    - BOLA/IDOR testing
    """

    protocol = "rest"

    async def fuzz(
        self,
        target: str,
        duration_seconds: int = 60,
        openapi_spec: dict[str, Any] | None = None,
        **kwargs
    ) -> ProtocolFuzzResult:
        """Fuzz REST API."""
        result = ProtocolFuzzResult(target=target, protocol=self.protocol)
        result.start_time = datetime.utcnow()

        start_time = time.time()

        # Parse OpenAPI spec if provided
        endpoints = []
        if openapi_spec:
            endpoints = self._parse_openapi(openapi_spec)
        else:
            endpoints = [
                {"path": "/api/users", "method": "GET"},
                {"path": "/api/users/{id}", "method": "GET"},
                {"path": "/api/users", "method": "POST"},
                {"path": "/api/items", "method": "GET"},
            ]

        async with httpx.AsyncClient(
            timeout=self.config.input_timeout_ms / 1000,
            verify=False
        ) as client:

            while (time.time() - start_time) < duration_seconds:
                endpoint = random.choice(endpoints)

                try:
                    vuln = await self._fuzz_endpoint(client, target, endpoint, result)
                    if vuln:
                        result.vulnerabilities.append(vuln)

                except Exception as e:
                    result.errors += 1

                result.requests_sent += 1

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _parse_openapi(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse OpenAPI spec to extract endpoints."""
        endpoints = []

        for path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method.upper() in self.METHODS:
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "parameters": details.get("parameters", []),
                        "requestBody": details.get("requestBody", {}),
                    })

        return endpoints

    async def _fuzz_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: dict[str, Any],
        result: ProtocolFuzzResult
    ) -> dict[str, Any] | None:
        """Fuzz a specific REST endpoint."""
        path = endpoint["path"]
        method = endpoint["method"]

        # Replace path parameters with fuzz values
        fuzz_values = ["1", "-1", "0", "99999999", "admin", "../../../etc/passwd", "' OR '1'='1"]
        path = re.sub(r'\{[^}]+\}', lambda m: random.choice(fuzz_values), path)

        url = urllib.parse.urljoin(base_url, path)
        attack = random.choice(ATTACK_STRINGS).decode(errors="ignore")

        # Test IDOR
        if "{id}" in endpoint["path"] or "id" in path.lower():
            # Try accessing other users' resources
            for test_id in ["1", "2", "0", "admin", "../../1"]:
                test_path = re.sub(r'\d+', test_id, path)
                test_url = urllib.parse.urljoin(base_url, test_path)

                response = await client.request(method, test_url)
                if response.status_code == 200:
                    return {
                        "type": VulnType.AUTH_BYPASS.value,
                        "severity": Severity.HIGH.value,
                        "description": "Potential IDOR - accessed resource with different ID",
                        "url": test_url,
                    }

        # Standard request with attack payload
        headers = {"Content-Type": "application/json"}
        body = json.dumps({"data": attack, "id": attack})

        start = time.time()
        response = await client.request(
            method,
            url,
            headers=headers,
            content=body if method in ["POST", "PUT", "PATCH"] else None,
            params={"q": attack} if method == "GET" else None
        )
        elapsed = (time.time() - start) * 1000

        return self._check_for_vulnerability(
            body.encode(), response.content, response.status_code, elapsed
        )
