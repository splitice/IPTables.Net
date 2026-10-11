#!/usr/bin/env python3
"""Require stable native coverage on provisioned CI runners, and report skips."""
import sys
import xml.etree.ElementTree as ET

REQUIRED = {"NativeFamilyTests": 3, "NativeLifecycleTests": 8, "IptcInterfaceTest": 7, "IpTableSystemTests": 1}


def check(path):
    root = ET.parse(path).getroot()
    results = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "UnitTestResult"]
    counts = {}
    for result in results:
        outcome = result.get("outcome", "Unknown")
        counts[outcome] = counts.get(outcome, 0) + 1
    print(f"Test outcomes: {counts}")
    errors = []
    for name in REQUIRED:
        selected = [r for r in results if name + "." in r.get("testName", "")]
        passed = sum(r.get("outcome") == "Passed" for r in selected)
        print(f"{name}: {passed}/{len(selected)} passed")
        if len(selected) < REQUIRED[name] or passed != len(selected):
            errors.append(f"{name}: native tests missing, skipped, or failed")
    if errors:
        raise ValueError("; ".join(errors))


if __name__ == "__main__":
    try:
        check(sys.argv[1])
    except (ValueError, IndexError, OSError, ET.ParseError) as error:
        sys.exit(str(error))
