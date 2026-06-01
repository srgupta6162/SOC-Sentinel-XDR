import re
from datetime import datetime

AUTH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+'
    r'(?P<day>\d+)\s+'
    r'(?P<time>[\d:]+)\s+\S+\s+'
    r'sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+'
    r'for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
)

def parse_auth_log(path="sample_logs/auth.log"):

    events = []

    with open(path, "r") as file:

        for line in file:

            match = AUTH_PATTERN.search(line)

            if match:

                events.append({
                    "type": "auth",
                    "status": match.group("status").lower(),
                    "user": match.group("user"),
                    "ip": match.group("ip"),
                    "timestamp": datetime.now().isoformat(),
                    "raw": line.strip()
                })

    return events


if __name__ == "__main__":

    logs = parse_auth_log()

    for log in logs:
        print(log)