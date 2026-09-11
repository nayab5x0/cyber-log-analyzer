from pathlib import Path
import pandas as pd


def generate_report(
    total_events,
    successful_logins,
    failed_logins,
    suspicious_events,
    high_risk_events,
    top_suspicious_ips,
    targeted_users,
    ip_activity,
    failed_logins_by_ip
):
    report = []

    report.append("CYBERSECURITY LOG ANALYSIS REPORT")
    report.append("=" * 40)
    report.append("")

    report.append(f"Total Events: {total_events}")
    report.append(f"Successful Logins: {successful_logins}")
    report.append(f"Failed Logins: {failed_logins}")
    report.append(f"Suspicious Events: {suspicious_events}")
    report.append(f"High-Risk Events: {high_risk_events}")
    report.append("")

    report.append("IP ANALYSIS")
    report.append("-" * 25)

    for ip, count in ip_activity.items():
        failed = failed_logins_by_ip.get(ip, 0)

        report.append(
            f"{ip} | Activity: {count} | Failed Logins: {failed}"
        )

    report.append("")

    report.append("Top Suspicious IPs")
    report.append("-" * 25)

    for result in top_suspicious_ips:
        report.append(
            f"{result['ip']} | "
            f"{result['threat']} | "
            f"Failed Logins: {result['failed_logins']}"
        )

    report.append("")
    report.append("Most Targeted Users")
    report.append("-" * 25)

    for username, count in targeted_users.items():
        report.append(
            f"{username}: {count} failed logins"
        )

    return "\n".join(report)


def save_report(report_text, file_path):
    file_path = Path(file_path)

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report_text)


def save_excel_report(
    records,
    threats,
    file_path
):
    file_path = Path(file_path)

    with pd.ExcelWriter(file_path, engine="openpyxl") as writer:

        records_df = pd.DataFrame(records)

        records_df.to_excel(
            writer,
            sheet_name="Log Records",
            index=False
        )

        threats_df = pd.DataFrame(threats)

        threats_df.to_excel(
            writer,
            sheet_name="Threat Analysis",
            index=False
        )