from pathlib import Path

from src.log_parser import parse_log_file
from src.analyzer import (
    remove_duplicates,
    remove_missing_values,
    normalize_records,
    standardize_timestamps,
    count_activity_by_ip,
    count_failed_logins_by_ip,
    count_failed_logins_by_user,
    get_top_suspicious_ips
)
from src.detector import analyze_ip_threats
from src.report_generator import (
    generate_report,
    save_report,
    save_excel_report
)


if __name__ == "__main__":

    project_folder = Path(__file__).resolve().parent

    data_folder = project_folder / "data"
    report_file = project_folder / "reports" / "security_report.txt"
    excel_file = project_folder / "reports" / "security_report.xlsx"

    # Automatically find log files
    log_files = list(data_folder.glob("*.log"))

    if not log_files:
        print("No .log files found!")
        exit()

    log_file = log_files[0]

    print("Log file found:", log_file.name)

    # Read log file
    records = parse_log_file(log_file)

    print("Records before cleaning:", len(records))

    # Clean data
    records = remove_duplicates(records)
    records = remove_missing_values(records)
    records = normalize_records(records)
    records = standardize_timestamps(records)

    print("Records after cleaning:", len(records))

    # Analyze IP activity
    ip_activity = count_activity_by_ip(records)
    failed_logins_by_ip = count_failed_logins_by_ip(records)

    # Failed logins by user
    failed_users = count_failed_logins_by_user(records)

    # Detect threats
    threats = analyze_ip_threats(
        ip_activity,
        failed_logins_by_ip
    )

    # Count successful and failed logins
    successful_logins = 0
    failed_login_total = 0

    for record in records:
        if record["status"] == "SUCCESS":
            successful_logins += 1
        elif record["status"] == "FAILED":
            failed_login_total += 1

    # Count suspicious and high-risk events
    suspicious_events = 0
    high_risk_events = 0

    for result in threats:

        if result["threat"] in [
            "Suspicious",
            "Suspicious IP"
        ]:
            suspicious_events += 1

        elif result["threat"] in [
            "High Risk",
            "Possible Brute Force"
        ]:
            high_risk_events += 1

    # Get suspicious IPs
    top_suspicious_ips = get_top_suspicious_ips(threats)

    # Generate text report
    report_text = generate_report(
        total_events=len(records),
        successful_logins=successful_logins,
        failed_logins=failed_login_total,
        suspicious_events=suspicious_events,
        high_risk_events=high_risk_events,
        top_suspicious_ips=top_suspicious_ips,
        targeted_users=failed_users,
        ip_activity=ip_activity,
        failed_logins_by_ip=failed_logins_by_ip
    )

    # Save text report
    save_report(report_text, report_file)

    # Save Excel report
    save_excel_report(
        records,
        threats,
        excel_file
    )

    print("\nReport generated successfully!")
    print("Text report saved to:", report_file)
    print("Excel report saved to:", excel_file)

    print("\n" + report_text)