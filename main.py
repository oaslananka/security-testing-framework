import argparse
from modules.web_security.sql_injection import SQLInjectionTester
from modules.web_security.xss import XSSTester
from modules.web_security.rce import RCETester
from modules.reporting.report_generator import ReportGenerator


def main():
    """
    Security Testing Framework
    This function is the entry point of the Security Testing Framework. It takes command line arguments
    to specify the target URL, the type of test to perform, and an optional parameter to test.
    Parameters:
    - --url: The target URL for testing (required)
    - --test: The type of test to perform, options are "sql", "xss", or "rce" (required)
    - --param: The parameter to test (optional)
    Returns:
    None
    Side Effects:
    - Executes the specified security test based on the provided arguments
    - Generates a security report and saves it to "security_report.json"
    - Prints a message indicating that the security report has been saved
    """
    parser = argparse.ArgumentParser(description="Security Testing Framework")
    parser.add_argument("--url", required=True, help="Target URL for testing")
    parser.add_argument("--test", required=True,
                        choices=["sql", "xss", "rce"], help="Type of test to perform")
    parser.add_argument("--param", help="Parameter to test")
    args = parser.parse_args()

    report_data = []

    if args.test == "sql":
        tester = SQLInjectionTester(args.url, args.param)
        results = tester.run_test()
        report_data.append({"type": "SQL Injection", "results": results})

    elif args.test == "xss":
        tester = XSSTester(args.url, args.param)
        results = tester.run_test()
        report_data.append({"type": "XSS", "results": results})

    elif args.test == "rce":
        tester = RCETester(args.url, args.param)
        results = tester.run_test()
        report_data.append({"type": "RCE", "results": results})

    generator = ReportGenerator(report_data)
    generator.save_report("security_report.json")
    print("Security report saved to security_report.json")


if __name__ == "__main__":
    main()
