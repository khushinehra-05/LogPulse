from tabulate import tabulate
import csv
from colorama import Fore, Style, init
init(autoreset=True)
def print_alerts(suspicious):

    if not suspicious:
        print(Fore.GREEN + "\nNo suspicious activity detected.")
        return

    print(Fore.RED + "\n⚠ Suspicious Activity Detected:\n")

    for item in suspicious:

        ip = item["ip"]
        reason = item["reason"]
        count = item["count"]

        if count >= 10:
            level = Fore.RED + "HIGH RISK"
        elif count >= 5:
            level = Fore.YELLOW + "MEDIUM RISK"
        else:
            level = Fore.CYAN + "LOW RISK"

        print(level, "-", ip, "-", reason, "-", count)
def print_security_summary(report):

    if not report:
        return

    print("\nSECURITY SUMMARY\n")

    for item in report:

        print("IP:", item["ip"])
        print("Attack Type:", item["attack_type"])
        print("Risk Score:", str(item["risk_score"]) + "/100")
        print("Recommendation:", item["recommendation"])
        print("-" * 30)

def generate_report(stats):

    print("\n===== LOG ANALYSIS REPORT =====\n")

    metrics = [
        ["Total Requests", stats["total_requests"]],
        ["Unique IPs", stats["unique_ips"]],
        ["Most Requested Endpoint", stats["most_requested_endpoint"]],
    ]

    print(tabulate(metrics, headers=["Metric", "Value"], tablefmt="grid"))

    print("\nStatus Code Distribution\n")

    status_table = []
    for status, count in stats["status_count"].items():
        status_table.append([status, count])

    print(tabulate(status_table, headers=["Status Code", "Count"], tablefmt="grid"))

    print("\nEndpoint Distribution\n")

    endpoint_table = []
    for endpoint, count in stats["endpoint_count"].items():
        endpoint_table.append([endpoint, count])

    print(tabulate(endpoint_table, headers=["Endpoint", "Requests"], tablefmt="grid"))


def export_csv(stats, file_path="output/report.csv"):

    with open(file_path, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Requests", stats["total_requests"]])
        writer.writerow(["Unique IPs", stats["unique_ips"]])
        writer.writerow(["Most Requested Endpoint", stats["most_requested_endpoint"]])