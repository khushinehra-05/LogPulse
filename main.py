import argparse
from log_analyzer.detector import analyze_security_risk
from log_analyzer.report import print_security_summary
from log_analyzer.parser import parse_logs
from log_analyzer.analyzer import analyze_logs
from log_analyzer.detector import detect_suspicious_activity
from log_analyzer.report import generate_report, export_csv, print_alerts
from log_analyzer.utils import watch_log_file


def get_arguments():

    parser = argparse.ArgumentParser(description="CLI Log Analyzer Tool")

    parser.add_argument(
        "command",
        choices=["analyze", "watch"],
        help="Command to run: analyze logs or watch logs in real time"
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    parser.add_argument(
        "--export",
        action="store_true",
        help="Export report to CSV"
    )

    parser.add_argument(
        "--detect",
        action="store_true",
        help="Enable suspicious activity detection"
    )

    return parser.parse_args()


def main():

    print("LOG ANALYZER TOOL")

    args = get_arguments()

    log_file = args.logfile

    if args.command == "analyze":

        logs = parse_logs(log_file)

        stats = analyze_logs(logs)

        generate_report(stats)

        if args.export:
            export_csv(stats)

        if args.detect:

            suspicious = detect_suspicious_activity(logs)

            print_alerts(suspicious)

            security_report = analyze_security_risk(suspicious)

            print_security_summary(security_report)
    elif args.command == "watch":

        print("\nWatching log file in real time...\n")

        for line in watch_log_file(log_file):

            print("New Log:", line)


if __name__ == "__main__":
    main()