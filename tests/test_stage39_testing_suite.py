"""
Master Verification Suite for Section 40 (Step 39: Testing).
Conforms strictly to IMPLEMENT.md Section 40:
- Verifies directory layout:
    tests/
    ├── connectors/
    ├── ingestion/
    ├── extraction/
    ├── classification/
    ├── deduplication/
    ├── search/
    ├── security/
    └── api/
- Verifies comprehensive test coverage across all 13 mandated subsystems:
    1. Connector
    2. Parser
    3. Normalizer
    4. Deduplication
    5. Classification
    6. Entity extraction
    7. Search
    8. API
    9. Database
    10. Authentication
    11. Authorization
    12. SSRF prevention
    13. File validation
- Executes all subsystem test suites to verify 100% pass rate.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
TESTS_DIR = ROOT_DIR / "tests"

sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

# Import the 13 subsystem test cases
from tests.connectors.test_connector import TestConnectorsSubsystem
from tests.ingestion.test_parser import TestParserSubsystem
from tests.ingestion.test_normalizer import TestNormalizerSubsystem
from tests.deduplication.test_deduplication import TestDeduplicationSubsystem
from tests.classification.test_classification import TestClassificationSubsystem
from tests.extraction.test_entity_extraction import TestEntityExtractionSubsystem
from tests.search.test_search import TestSearchSubsystem
from tests.api.test_api_endpoints import TestAPIEndpointsSubsystem
from tests.ingestion.test_database import TestDatabaseSubsystem
from tests.security.test_authentication import TestAuthenticationSubsystem
from tests.security.test_authorization import TestAuthorizationSubsystem
from tests.security.test_ssrf_prevention import TestSSRFPreventionSubsystem
from tests.security.test_file_validation import TestFileValidationSubsystem


class TestStage39TestingSuiteVerification(unittest.TestCase):
    """Master Verification Test Suite for Section 40 Step 39."""

    def test_01_mandated_directory_structure_exists(self):
        """Verify the exact directory layout required by IMPLEMENT.md Section 40."""
        mandated_subdirs = [
            "connectors",
            "ingestion",
            "extraction",
            "classification",
            "deduplication",
            "search",
            "security",
            "api",
        ]
        for subdir in mandated_subdirs:
            target_path = TESTS_DIR / subdir
            self.assertTrue(
                target_path.exists() and target_path.is_dir(),
                f"Mandated test directory 'tests/{subdir}' does not exist",
            )
            init_file = target_path / "__init__.py"
            self.assertTrue(
                init_file.exists(),
                f"Mandated package init file 'tests/{subdir}/__init__.py' does not exist",
            )

    def test_02_all_thirteen_subsystem_test_modules_exist(self):
        """Verify test files for all 13 subsystems are present in the filesystem."""
        subsystem_files = {
            "Connector": TESTS_DIR / "connectors" / "test_connector.py",
            "Parser": TESTS_DIR / "ingestion" / "test_parser.py",
            "Normalizer": TESTS_DIR / "ingestion" / "test_normalizer.py",
            "Deduplication": TESTS_DIR / "deduplication" / "test_deduplication.py",
            "Classification": TESTS_DIR / "classification" / "test_classification.py",
            "Entity extraction": TESTS_DIR / "extraction" / "test_entity_extraction.py",
            "Search": TESTS_DIR / "search" / "test_search.py",
            "API": TESTS_DIR / "api" / "test_api_endpoints.py",
            "Database": TESTS_DIR / "ingestion" / "test_database.py",
            "Authentication": TESTS_DIR / "security" / "test_authentication.py",
            "Authorization": TESTS_DIR / "security" / "test_authorization.py",
            "SSRF prevention": TESTS_DIR / "security" / "test_ssrf_prevention.py",
            "File validation": TESTS_DIR / "security" / "test_file_validation.py",
        }
        for name, path in subsystem_files.items():
            self.assertTrue(path.exists(), f"Subsystem '{name}' test file not found at: {path}")

    def test_03_execute_all_thirteen_subsystems_suite(self):
        """
        Execute comprehensive test suite composed of all 13 subsystems.
        Ensures all 13 subsystems pass completely with zero failures and zero errors.
        """
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()

        subsystem_classes = [
            ("1. Connector", TestConnectorsSubsystem),
            ("2. Parser", TestParserSubsystem),
            ("3. Normalizer", TestNormalizerSubsystem),
            ("4. Deduplication", TestDeduplicationSubsystem),
            ("5. Classification", TestClassificationSubsystem),
            ("6. Entity extraction", TestEntityExtractionSubsystem),
            ("7. Search", TestSearchSubsystem),
            ("8. API", TestAPIEndpointsSubsystem),
            ("9. Database", TestDatabaseSubsystem),
            ("10. Authentication", TestAuthenticationSubsystem),
            ("11. Authorization", TestAuthorizationSubsystem),
            ("12. SSRF prevention", TestSSRFPreventionSubsystem),
            ("13. File validation", TestFileValidationSubsystem),
        ]

        self.assertEqual(len(subsystem_classes), 13, "Must test exactly 13 subsystems")

        for name, cls in subsystem_classes:
            tests = loader.loadTestsFromTestCase(cls)
            suite.addTests(tests)
            self.assertGreater(
                tests.countTestCases(),
                0,
                f"Subsystem '{name}' ({cls.__name__}) must contain test cases",
            )

        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)

        self.assertEqual(
            len(result.failures),
            0,
            f"Failures encountered in subsystem tests: {result.failures}",
        )
        self.assertEqual(
            len(result.errors),
            0,
            f"Errors encountered in subsystem tests: {result.errors}",
        )
        self.assertGreaterEqual(
            result.testsRun,
            65,
            f"Expected at least 65 total tests across all 13 subsystems, got {result.testsRun}",
        )


if __name__ == "__main__":
    unittest.main()
