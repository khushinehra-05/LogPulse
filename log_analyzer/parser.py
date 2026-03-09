def parse_logs(file_path):
    logs = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if line == "":
                continue

            parts = line.split()

            if len(parts) != 4:
                continue

            log_entry = {
                "ip": parts[0],
                "method": parts[1],
                "endpoint": parts[2],
                "status": parts[3]
            }

            logs.append(log_entry)

    return logs