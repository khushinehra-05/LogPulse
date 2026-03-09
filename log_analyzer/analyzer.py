def analyze_logs(logs):

    total_requests = len(logs)

    unique_ips = set()

    endpoint_count = {}

    status_count = {}

    for log in logs:

        ip = log["ip"]
        endpoint = log["endpoint"]
        status = log["status"]

        unique_ips.add(ip)

        if endpoint not in endpoint_count:
            endpoint_count[endpoint] = 0
        endpoint_count[endpoint] += 1

        if status not in status_count:
            status_count[status] = 0
        status_count[status] += 1

    most_requested_endpoint = max(endpoint_count, key=endpoint_count.get)

    result = {
        "total_requests": total_requests,
        "unique_ips": len(unique_ips),
        "most_requested_endpoint": most_requested_endpoint,
        "endpoint_count": endpoint_count,
        "status_count": status_count
    }

    return result