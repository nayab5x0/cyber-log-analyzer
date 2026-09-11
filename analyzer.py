import ipaddress
from datetime import datetime


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def remove_duplicates(records):
    unique_records = []
    seen = set()

    for record in records:
        record_key = tuple(record.items())

        if record_key not in seen:
            seen.add(record_key)
            unique_records.append(record)

    return unique_records


def remove_missing_values(records):
    cleaned_records = []

    for record in records:
        if all(record.get(field) for field in [
            "timestamp",
            "ip",
            "username",
            "event",
            "status"
        ]):
            cleaned_records.append(record)

    return cleaned_records


def normalize_records(records):
    normalized_records = []

    for record in records:
        record["username"] = record["username"].strip().lower()
        record["event"] = record["event"].strip().upper()
        record["status"] = record["status"].strip().upper()

        normalized_records.append(record)

    return normalized_records


def standardize_timestamps(records):
    standardized_records = []

    for record in records:
        try:
            dt = datetime.strptime(
                record["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            record["timestamp"] = dt
            standardized_records.append(record)

        except ValueError:
            continue

    return standardized_records


def count_activity_by_ip(records):
    ip_counts = {}

    for record in records:
        ip = record["ip"]

        if is_valid_ip(ip):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return ip_counts


def count_failed_logins_by_ip(records):
    failed_counts = {}

    for record in records:
        ip = record["ip"]

        if is_valid_ip(ip) and record["status"] == "FAILED":
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    return failed_counts


def count_failed_logins_by_user(records):
    failed_counts = {}

    for record in records:
        username = record["username"]

        if record["status"] == "FAILED":
            failed_counts[username] = failed_counts.get(username, 0) + 1

    return failed_counts
def get_top_suspicious_ips(threats):
    suspicious_ips = []

    for result in threats:
        if result["threat"] in ["Suspicious", "High Risk", "Possible Brute Force", "Suspicious IP"]:
            suspicious_ips.append(result)

    suspicious_ips.sort(
        key=lambda x: x["failed_logins"],
        reverse=True
    )

    return suspicious_ips