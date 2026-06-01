
from collections import defaultdict

from sigma_engine import load_sigma_rules


def detect_port_scan(events):

    # =====================================
    # LOAD SIGMA RULE
    # =====================================

    rules = load_sigma_rules()

    threshold = rules[
        "Port Scan Detection"
    ]["detection"]["threshold"]

    alerts = []

    ports_seen = defaultdict(set)

    # =====================================
    # COLLECT PORTS
    # =====================================

    for event in events:

        if event["type"] == "firewall":

            ports_seen[
                event["src_ip"]
            ].add(
                event["dst_port"]
            )

    # =====================================
    # DETECT PORT SCANS
    # =====================================

    for ip, ports in ports_seen.items():

        if len(ports) >= threshold:

            alerts.append({

                "severity": "MEDIUM",

                "rule":
                "Port Scan Detection",

                "ip": ip,

                "count":
                len(ports),

                "source":
                "Firewall",

                "timestamp":
                "N/A",

                "message":
                f"Possible port scan from {ip}"

            })

    return alerts
