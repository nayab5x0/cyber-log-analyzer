def detect_failed_login_threat(failed_count):
    if failed_count >= 20:
        return "Possible Brute Force"
    elif failed_count >= 10:
        return "High Risk"
    elif failed_count >= 5:
        return "Suspicious"
    else:
        return "Normal"


def detect_suspicious_ip(activity_count):
    if activity_count >= 10:
        return "Suspicious IP"
    else:
        return "Normal"


def analyze_ip_threats(ip_activity, failed_logins):
    results = []

    all_ips = set(ip_activity.keys()) | set(failed_logins.keys())

    for ip in all_ips:
        activity_count = ip_activity.get(ip, 0)
        failed_count = failed_logins.get(ip, 0)

        threat = detect_failed_login_threat(failed_count)

        if activity_count >= 10 and threat == "Normal":
            threat = "Suspicious IP"

        results.append({
            "ip": ip,
            "activity_count": activity_count,
            "failed_logins": failed_count,
            "threat": threat
        })

    return results


if __name__ == "__main__":

    test_activity = {
        "192.168.1.20": 6,
        "192.168.1.10": 2
    }

    test_failed = {
        "192.168.1.20": 6,
        "192.168.1.10": 1
    }

    threats = analyze_ip_threats(test_activity, test_failed)

    for result in threats:
        print(result)