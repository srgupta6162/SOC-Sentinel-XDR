import json
import os


DB_FILE = os.path.join(
    os.path.dirname(__file__),
    "malicious_ips.json"
)


def lookup_ip(ip):

    try:

        with open(
            DB_FILE,
            "r"
        ) as f:

            data = json.load(f)

        if ip in data:

            return data[ip]

    except Exception as e:

        print(
            f"Threat Lookup Error: {e}"
        )

    return {

        "country": "Unknown",

        "asn": "Unknown",

        "threat_score": 0,

        "risk": "LOW"

    }