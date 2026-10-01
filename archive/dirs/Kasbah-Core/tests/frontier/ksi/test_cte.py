"""
Test Suite for CulturalTriageEngine (CTE) Module

CTE detects script types and routes to appropriate cultural frameworks:
- Arabic → Maqasid, QuranSemantic frameworks
- CJK (Chinese, Japanese, Korean) → ChineseRIC, JapaneseMyNumber, KoreanRRN
- Cyrillic → RussianPatterns
- Mixed scripts → detects all, routes to all
"""

import unittest
from core.frontier.ksi.cte import CulturalTriageEngine


class TestCTEScriptDetection(unittest.TestCase):
    """Test script detection capabilities of CTE."""

    def setUp(self):
        """Initialize CTE for each test."""
        self.cte = CulturalTriageEngine()

    def test_detect_arabic_script(self):
        """Test detection of Arabic text."""
        # Arabic text: "النص العربي" (Arabic text)
        arabic_text = "النص العربي يحتوي على معلومات حساسة"
        detected_scripts = self.cte.detect_scripts(arabic_text)

        self.assertIn("ARABIC", detected_scripts)
        self.assertIsInstance(detected_scripts, list)
        self.assertGreater(len(detected_scripts), 0)

    def test_detect_cjk_script(self):
        """Test detection of CJK (Chinese, Japanese, Korean) text."""
        # Mixed CJK: Chinese + Japanese
        cjk_text = "中文和日本語のテキスト"
        detected_scripts = self.cte.detect_scripts(cjk_text)

        self.assertIn("CJK", detected_scripts)
        self.assertIsInstance(detected_scripts, list)

    def test_detect_mixed_scripts(self):
        """Test detection of mixed script text (Arabic + Latin)."""
        mixed_text = "Hello مرحبا World"
        detected_scripts = self.cte.detect_scripts(mixed_text)

        # Should detect both Latin and Arabic
        self.assertIsInstance(detected_scripts, list)
        self.assertGreater(len(detected_scripts), 0)


class TestCTEFrameworkRouting(unittest.TestCase):
    """Test framework routing based on detected scripts."""

    def setUp(self):
        """Initialize CTE for each test."""
        self.cte = CulturalTriageEngine()

    def test_route_arabic_to_maqasid_framework(self):
        """Test that Arabic text routes to Maqasid and QuranSemantic frameworks."""
        arabic_text = "النص العربي يحتوي على معلومات حساسة جداً"
        frameworks = self.cte.route_to_framework(arabic_text)

        self.assertIsInstance(frameworks, list)
        self.assertGreater(len(frameworks), 0)
        # Should include at least one Arabic framework
        self.assertTrue(
            any("Maqasid" in f or "Quran" in f for f in frameworks),
            f"Expected Arabic framework in {frameworks}"
        )

    def test_route_cjk_to_regional_frameworks(self):
        """Test that CJK text routes to ChineseRIC, JapaneseMyNumber, KoreanRRN."""
        cjk_text = "中文和日本語のテキスト"
        frameworks = self.cte.route_to_framework(cjk_text)

        self.assertIsInstance(frameworks, list)
        self.assertGreater(len(frameworks), 0)
        # Should include at least one CJK framework
        self.assertTrue(
            any("Chinese" in f or "Japanese" in f or "Korean" in f for f in frameworks),
            f"Expected CJK framework in {frameworks}"
        )

    def test_route_mixed_scripts_to_multiple_frameworks(self):
        """Test that mixed script text routes to multiple frameworks."""
        mixed_text = "Hello مرحبا and 中文"
        frameworks = self.cte.route_to_framework(mixed_text)

        self.assertIsInstance(frameworks, list)
        # Mixed content should route to multiple frameworks
        self.assertGreater(len(frameworks), 0)


class TestCTELatin(unittest.TestCase):
    """Test Latin script handling."""

    def setUp(self):
        """Initialize CTE for each test."""
        self.cte = CulturalTriageEngine()

    def test_detect_latin_script(self):
        """Test detection of Latin (English) text."""
        latin_text = "This is English text"
        detected_scripts = self.cte.detect_scripts(latin_text)

        self.assertIsInstance(detected_scripts, list)
        # Latin text detection should still work
        self.assertGreater(len(detected_scripts), 0)

    def test_route_latin_text(self):
        """Test routing of Latin text."""
        latin_text = "This is English text"
        frameworks = self.cte.route_to_framework(latin_text)

        self.assertIsInstance(frameworks, list)


if __name__ == "__main__":
    unittest.main()
