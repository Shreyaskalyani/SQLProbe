import asyncio
import unittest
import re
from unittest.mock import AsyncMock, MagicMock, patch
from difflib import SequenceMatcher
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quick_scan import (
    AdvancedVulnerabilityFinder,
    VulnerabilityFinding,
    ConfidenceScorer,
    FalsePositiveReducer,
)


class TestVulnerabilityFinding(unittest.TestCase):
    def test_finding_creation(self):
        finding = VulnerabilityFinding(
            url="http://example.com",
            parameter="id",
            method="GET",
            injection_type="boolean_based",
            payload="' AND '1'='1",
            confidence=0.8,
            evidence="Length changed"
        )
        self.assertEqual(finding.url, "http://example.com")
        self.assertEqual(finding.parameter, "id")
        self.assertEqual(finding.injection_type, "boolean_based")
        self.assertEqual(finding.confidence, 0.8)

    def test_finding_with_details(self):
        finding = VulnerabilityFinding(
            url="http://test.com",
            parameter="q",
            method="POST",
            injection_type="error_based",
            payload="'",
            confidence=0.9,
            evidence="SQL error found",
            details={"patterns": ["SQL syntax"]}
        )
        self.assertEqual(finding.method, "POST")
        self.assertEqual(finding.details["patterns"], ["SQL syntax"])


class TestConfidenceScorer(unittest.TestCase):
    def test_error_based_score(self):
        score = ConfidenceScorer.calculate_confidence(
            "error_based", 0, 0, 0.5, False, 0.0
        )
        self.assertGreater(score, 0.5)

    def test_time_based_score(self):
        score = ConfidenceScorer.calculate_confidence(
            "time_based", 0, 0, 0.5, False, 4.0
        )
        self.assertGreater(score, 0.5)

    def test_union_based_score(self):
        score = ConfidenceScorer.calculate_confidence(
            "union_based", 100, 0, 0.5, False, 0.0
        )
        self.assertGreater(score, 0.3)

    def test_boolean_based_score(self):
        score = ConfidenceScorer.calculate_confidence(
            "boolean_based", 50, 0, 0.7, False, 0.0
        )
        self.assertGreater(score, 0.1)

    def test_max_score_cap(self):
        score = ConfidenceScorer.calculate_confidence(
            "error_based", 1000, 500, 0.1, True, 10.0
        )
        self.assertLessEqual(score, 1.0)


class TestFalsePositiveReducer(unittest.TestCase):
    def setUp(self):
        self.reducer = FalsePositiveReducer()

    def test_normal_content_not_fp(self):
        content = "Welcome to our website, please login"
        result = self.reducer.is_false_positive(content, "boolean_based")
        self.assertFalse(result)

    def test_high_similarity_fp(self):
        content = "Welcome to our site dashboard"
        result = self.reducer.is_false_positive(content, "boolean_based")
        self.assertFalse(result)

    def test_fp_reducer_logic(self):
        content = "Welcome to our site dashboard"
        result = self.reducer.is_false_positive(content, "boolean_based")
        self.assertFalse(result)


class TestAdvancedVulnerabilityFinder(unittest.TestCase):
    def setUp(self):
        self.finder = AdvancedVulnerabilityFinder(timeout=10.0, delay=0.1)

    def test_initialization(self):
        self.assertEqual(self.finder.timeout, 10.0)
        self.assertEqual(self.finder.delay, 0.1)
        self.assertEqual(len(self.finder.vulnerabilities), 0)

    def test_boolean_payloads_exist(self):
        self.assertTrue(len(self.finder.BOOLEAN_PAYLOADS) > 0)
        self.assertIn(("' AND '1'='1", "boolean_true"), self.finder.BOOLEAN_PAYLOADS)

    def test_error_payloads_exist(self):
        self.assertTrue(len(self.finder.ERROR_PAYLOADS) > 0)

    def test_time_payloads_exist(self):
        self.assertTrue(len(self.finder.TIME_PAYLOADS) > 0)

    def test_union_payloads_exist(self):
        self.assertTrue(len(self.finder.UNION_PAYLOADS) > 0)

    def test_error_patterns_exist(self):
        self.assertTrue(len(self.finder.ERROR_PATTERNS) > 0)
        self.assertTrue(any("SQL syntax" in p for p in self.finder.ERROR_PATTERNS))

    def test_compiled_patterns(self):
        self.assertTrue(len(self.finder._compiled_patterns) > 0)
        for pattern in self.finder._compiled_patterns:
            self.assertIsInstance(pattern, type(re.compile("test")))

    def test_reducer_exists(self):
        self.assertIsNotNone(self.finder._reducer)

    def test_scorer_exists(self):
        self.assertIsNotNone(self.finder._scorer)


class TestAsyncVulnerabilityDetection(unittest.TestCase):
    def setUp(self):
        self.finder = AdvancedVulnerabilityFinder(timeout=5.0, delay=0.05)

    def _create_mock_response(self, text: str, status_code: int = 200):
        response = MagicMock()
        response.text = text
        response.status_code = status_code
        response.content_length = len(text)
        response.elapsed = MagicMock()
        response.elapsed.__mul__ = lambda self, x: 100
        return response

    async def _run_boolean_test(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock()
        mock_client.post = AsyncMock()

        baseline = {
            "content": "<html>Normal response</html>",
            "content_length": 25,
            "status_code": 200,
            "elapsed_ms": 100,
        }

        mock_client.get.return_value = self._create_mock_response(
            "<html>Different response with error</html>", 500
        )

        result = await self.finder._test_boolean_based(
            mock_client, "http://test.com?id=1", "id", "GET", baseline
        )
        return result

    async def _run_error_test(self):
        mock_client = AsyncMock()

        mock_client.get.return_value = self._create_mock_response(
            "Error: SQL syntax near 'SELECT'", 200
        )

        result = await self.finder._test_error_based(
            mock_client, "http://test.com?id=1", "id", "GET"
        )
        return result

    async def _run_union_test(self):
        mock_client = AsyncMock()

        baseline = {
            "content": "<html>Normal</html>",
            "content_length": 15,
            "status_code": 200,
            "elapsed_ms": 100,
        }

        mock_client.get.return_value = self._create_mock_response(
            "<html>Result: union select from users</html>", 200
        )

        result = await self.finder._test_union_based(
            mock_client, "http://test.com?id=1", "id", "GET", baseline
        )
        return result

    def test_boolean_based_detection(self):
        result = asyncio.run(self._run_boolean_test())
        self.assertIsNotNone(result)
        self.assertEqual(result.injection_type, "boolean_based")

    def test_error_based_detection(self):
        result = asyncio.run(self._run_error_test())
        self.assertIsNotNone(result)
        self.assertEqual(result.injection_type, "error_based")

    def test_union_based_detection(self):
        result = asyncio.run(self._run_union_test())
        self.assertIsNotNone(result)
        self.assertEqual(result.injection_type, "union_based")


class TestDifferentialAnalysis(unittest.TestCase):
    def setUp(self):
        self.finder = AdvancedVulnerabilityFinder()

    def test_content_similarity_calc(self):
        s1 = "SELECT * FROM users"
        s2 = "SELECT * FROM users"
        s3 = "INSERT INTO users VALUES (1)"

        sim_same = SequenceMatcher(None, s1, s2).ratio()
        sim_diff = SequenceMatcher(None, s1, s3).ratio()

        self.assertGreater(sim_same, sim_diff)

    def test_length_difference_detection(self):
        baseline_len = 100
        test_len = 150
        diff_percent = abs(test_len - baseline_len) / max(baseline_len, 1) * 100
        self.assertEqual(diff_percent, 50.0)


class TestPayloadTypes(unittest.TestCase):
    def setUp(self):
        self.finder = AdvancedVulnerabilityFinder()

    def test_boolean_payload_categories(self):
        categories = [p[1] for p in self.finder.BOOLEAN_PAYLOADS]
        self.assertIn("boolean_true", categories)
        self.assertIn("boolean_false", categories)

    def test_time_payload_database_targets(self):
        time_payloads = self.finder.TIME_PAYLOADS
        self.assertTrue(any("mssql" in p[1] for p in time_payloads))
        self.assertTrue(any("mysql" in p[1] for p in time_payloads))

    def test_union_payload_variations(self):
        union_payloads = self.finder.UNION_PAYLOADS
        self.assertTrue(any("NULL" in p[0] for p in union_payloads))
        self.assertTrue(any("SELECT" in p[0] for p in union_payloads))


class TestFalsePositiveReduction(unittest.TestCase):
    def test_similarity_threshold(self):
        from difflib import SequenceMatcher

        baseline = "<html><body>Normal response</body></html>"
        vuln_response = "<html><body>Error occurred</body></html>"
        normal_response = "<html><body>Normal response</body></html>"

        vuln_sim = SequenceMatcher(None, baseline, vuln_response).ratio()
        normal_sim = SequenceMatcher(None, baseline, normal_response).ratio()

        self.assertLess(vuln_sim, normal_sim)
        self.assertGreater(normal_sim, 0.95)


class TestMultipleDetectionMethods(unittest.TestCase):
    def test_all_detection_types_present(self):
        finder = AdvancedVulnerabilityFinder()
        self.assertTrue(len(finder.BOOLEAN_PAYLOADS) > 0)
        self.assertTrue(len(finder.ERROR_PAYLOADS) > 0)
        self.assertTrue(len(finder.TIME_PAYLOADS) > 0)
        self.assertTrue(len(finder.UNION_PAYLOADS) > 0)

    def test_confidence_scoring_various_scenarios(self):
        scorer = ConfidenceScorer()

        scenarios = [
            ("error_based", 0, 0, 0.5, False, 0.0),
            ("time_based", 0, 0, 0.5, False, 5.0),
            ("union_based", 200, 0, 0.4, False, 0.0),
            ("boolean_based", 50, 0, 0.7, False, 0.0),
        ]

        for scenario in scenarios:
            score = scorer.calculate_confidence(*scenario)
            self.assertGreater(score, 0)
            self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()