def detect_suspicious_activity(logs):

    failed_requests = {}
    request_count = {}

    for log in logs:

        ip = log["ip"]
        status = log["status"]

        # Count total requests per IP
        if ip not in request_count:
            request_count[ip] = 0
        request_count[ip] += 1

        # Count failed requests (example: status 401 or 403)
        if status in ["401", "403"]:
            if ip not in failed_requests:
                failed_requests[ip] = 0
            failed_requests[ip] += 1

    suspicious_ips = []

    # Rule 1: Too many failed logins
    for ip, count in failed_requests.items():
        if count >= 3:
            suspicious_ips.append({
                "ip": ip,
                "reason": "Too many failed requests",
                "count": count
            })

    # Rule 2: Too many total requests
    for ip, count in request_count.items():
        if count >= 10:
            suspicious_ips.append({
                "ip": ip,
                "reason": "High traffic from IP",
                "count": count
            })

    return suspicious_ips
def analyze_security_risk(suspicious):

    security_report = []

    for item in suspicious:

        ip = item["ip"]
        reason = item["reason"]
        count = item["count"]

        risk_score = min(count * 10, 100)

        if "failed requests" in reason:
            attack_type = "Brute Force Attempt"
        elif "High traffic" in reason:
            attack_type = "Possible Bot Traffic"
        else:
            attack_type = "Unknown"

        if risk_score >= 70:
            recommendation = "Block IP"
        elif risk_score >= 40:
            recommendation = "Monitor IP"
        else:
            recommendation = "Low Risk"

        security_report.append({
            "ip": ip,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "recommendation": recommendation
        })

    return security_report