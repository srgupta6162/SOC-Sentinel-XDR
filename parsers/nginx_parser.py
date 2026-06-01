import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"GET (?P<url>.*?) HTTP'
)

def parse_web_log(path="sample_logs/access.log"):

    events = []

    with open(path, "r") as file:

        for line in file:

            match = LOG_PATTERN.search(line)

            if match:

                events.append({
                    "type": "web",
                    "ip": match.group("ip"),
                    "url": match.group("url"),
                    "timestamp": datetime.now().isoformat(),
                    "raw": line.strip()
                })

    return events