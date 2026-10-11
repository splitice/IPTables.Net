#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import sys
sys.dont_write_bytecode = True
import unittest

spec = importlib.util.spec_from_file_location("checker", Path(__file__).parents[1] / "check-native-results.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class NativeResultsTests(unittest.TestCase):
    def check(self, outcomes):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".trx") as report:
            report.write('<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results>')
            for name, outcome in outcomes:
                report.write(f'<UnitTestResult testName="IPTables.Net.Tests.{name}.Example" outcome="{outcome}"/>')
            report.write('</Results></TestRun>')
            report.flush()
            checker.check(report.name)

    def test_all_required_classes_pass(self):
        self.check([(name, "Passed") for name, count in checker.REQUIRED.items() for _ in range(count)])

    def test_skipped_native_case_is_an_error_even_with_passed_cases(self):
        with self.assertRaisesRegex(ValueError, "NativeFamilyTests"):
            self.check([(name, "Passed") for name, count in checker.REQUIRED.items() for _ in range(count)] + [("NativeFamilyTests", "NotExecuted")])

    def test_partially_missing_class_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "NativeFamilyTests"):
            self.check([(name, "Passed") for name, count in checker.REQUIRED.items()
                        for _ in range(count - (name == "NativeFamilyTests"))])

    def test_missing_native_classes_are_an_error(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            self.check([])


if __name__ == "__main__":
    unittest.main()
