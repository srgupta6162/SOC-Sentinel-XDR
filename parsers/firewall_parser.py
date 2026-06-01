import re
from datetime import datetime

FIREWALL_PATTERN = re.compile(
    r"SRC=(?P<src_ip>[\d.]+).*?DST=(?P<dst_ip>[\d.]+).*?DPT=(?P<dst_port>\d+)"
)

def parse_firewall_log(path="sample_logs/firewall.log"):

    events = []

    with open(path, "r") as file:

        for line in file:

            match = FIREWALL_PATTERN.search(line)

            if match:

                events.append({
                    "type": "firewall",
                    "src_ip": match.group("src_ip"),
                    "dst_ip": match.group("dst_ip"),
                    "dst_port": int(match.group("dst_port")),
                    "timestamp": datetime.now().isoformat(),
                    "raw": line.strip()
                })

    return events