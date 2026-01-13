#!/usr/bin/env python3
"""
Test Runner

Run all tests for the Hash Audit Tool with comprehensive reporting.
"""

import unittest
import sys
import os
import time
from io import StringIO

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestResult:
    """Container for test results."""
    
    def __init__(self):
        self.total_tests = 0
        self.failures = 0
        self.errors = 0
        self.skipped = 0
        self.success_rate = 0.0
        self.execution_time = 0.0
        self.test_modules = []
        self.details = []


def run_test_module(module_name, test_suite):
    """Run a specific test module and return results."""
    print(f"\n{'='*60}")
    print(f"Running {module_name}")
    print('='*60)
    
    # Create stream for output capture
    stream = StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    
    start_time = time.time()
    result = runner.run(test_suite)
    execution_time = time.time() - start_time
    
    # Get output
    output = stream.getvalue()
    
    # Store results
    module_result = {
        'module': module_name,
        'total_tests': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'execution_time': execution_time,
        'success_rate': (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100 if result.testsRun > 0 else 0,
        'output': output
    }
    
    # Print summary
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print(f"Success rate: {module_result['success_rate']:.1f}%")
    print(f"Execution time: {execution_time:.2f}s")
    
    return module_result


def main():
    """Main test runner."""
    print("Hash Audit Tool - Test Suite")
    print("=" * 60)
    print("Running comprehensive tests...")
    
    # Import test modules
    try:
        from tests.test_hashes import TestHashAlgorithms
        from tests.test_attacks import TestAttackStrategies
        from tests.test_utils import TestFormatters, TestValidators, TestHelpers, TestIntegration
    except ImportError as e:
        print(f"Error importing test modules: {e}")
        return 1
    
    # Create test suites
    test_suites = [
        ('Hash Algorithms', unittest.TestLoader().loadTestsFromTestCase(TestHashAlgorithms)),
        ('Attack Strategies', unittest.TestLoader().loadTestsFromTestCase(TestAttackStrategies)),
        ('Formatters', unittest.TestLoader().loadTestsFromTestCase(TestFormatters)),
        ('Validators', unittest.TestLoader().loadTestsFromTestCase(TestValidators)),
        ('Helpers', unittest.TestLoader().loadTestsFromTestCase(TestHelpers)),
        ('Integration Tests', unittest.TestLoader().loadTestsFromTestCase(TestIntegration))
    ]
    
    # Run all tests
    overall_result = TestResult()
    start_time = time.time()
    
    for module_name, test_suite in test_suites:
        module_result = run_test_module(module_name, test_suite)
        overall_result.test_modules.append(module_result)
        
        # Update overall totals
        overall_result.total_tests += module_result['total_tests']
        overall_result.failures += module_result['failures']
        overall_result.errors += module_result['errors']
        overall_result.skipped += module_result['skipped']
    
    overall_result.execution_time = time.time() - start_time
    
    # Calculate overall success rate
    total_issues = overall_result.failures + overall_result.errors
    overall_result.success_rate = (overall_result.total_tests - total_issues) / overall_result.total_tests * 100 if overall_result.total_tests > 0 else 0
    
    # Print overall summary
    print(f"\n{'='*60}")
    print("OVERALL TEST RESULTS")
    print('='*60)
    print(f"Total tests run: {overall_result.total_tests}")
    print(f"Total failures: {overall_result.failures}")
    print(f"Total errors: {overall_result.errors}")
    print(f"Total skipped: {overall_result.skipped}")
    print(f"Overall success rate: {overall_result.success_rate:.1f}%")
    print(f"Total execution time: {overall_result.execution_time:.2f}s")
    
    # Print module breakdown
    print(f"\n{'='*60}")
    print("MODULE BREAKDOWN")
    print('='*60)
    print(f"{'Module':<20} {'Tests':<8} {'Fail':<5} {'Error':<5} {'Skip':<5} {'Time':<8} {'Success':<8}")
    print("-" * 70)
    
    for module in overall_result.test_modules:
        print(f"{module['module']:<20} {module['total_tests']:<8} {module['failures']:<5} "
              f"{module['errors']:<5} {module['skipped']:<5} {module['execution_time']:<8.2f} "
              f"{module['success_rate']:<7.1f}%")
    
    # Determine exit code
    if overall_result.failures > 0 or overall_result.errors > 0:
        print(f"\n{'='*60}")
        print("TESTS FAILED - See detailed output above")
        print('='*60)
        return 1
    else:
        print(f"\n{'='*60}")
        print("ALL TESTS PASSED")
        print('='*60)
        return 0


if __name__ == '__main__':
    sys.exit(main())
