from collections import defaultdict

from sigma_engine import load_sigma_rules


def detect_brute_force(events):

    # =====================================
    # LOAD SIGMA RULE
    # =====================================

    rules = load_sigma_rules()

    threshold = rules[
        "Brute Force Detection"
    ]["detection"]["threshold"]

    failed_attempts = defaultdict(int)

    alerts = []

    # =====================================
    # DETECTION LOGIC
    # =====================================

    for event in events:

        if event["status"] == "failed":

            ip = event["ip"]

            failed_attempts[ip] += 1

            if failed_attempts[ip] >= threshold:

                alerts.append({

                    "severity": "HIGH",

                    "rule":
                    "Brute Force Detection",

                    "ip": ip,

                    "count":
                    failed_attempts[ip],

                    "source": "SSH",

                    "timestamp":
                    event["timestamp"],

                    "message":
                    f"Possible brute force attack from {ip}"

                })

    return alerts