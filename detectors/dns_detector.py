from collections import Counter

from threat_intel.threat_lookup import (
    lookup_ip
)

from mitre.mapper import (
    map_to_mitre
)


def detect_dns_threats(events):

    alerts = []

    if not events:
        return alerts

    ip_counter = Counter()

    domain_counter = Counter()

    for event in events:

        ip = event.get(
            "ip",
            ""
        )

        query = event.get(
            "query",
            ""
        )

        ip_counter[ip] += 1

        domain_counter[query] += 1

    # =====================================
    # HIGH DNS ACTIVITY
    # =====================================

    for ip, count in ip_counter.items():

        if count >= 100:

            intel = lookup_ip(ip)

            mitre = map_to_mitre(
                "High DNS Activity"
            )

            alerts.append({

                "severity": "MEDIUM",

                "rule":
                "High DNS Activity",

                "ip": ip,

                "count": count,

                "source": "DNS",

                "timestamp":
                events[0]["timestamp"],

                "risk_score": 60,

                "ip_type": "Internal",

                "message":
                f"High DNS activity detected from {ip}",

                # =====================
                # THREAT INTEL
                # =====================

                "country":
                intel["country"],

                "asn":
                intel["asn"],

                "threat_score":
                intel["threat_score"],

                "risk":
                intel["risk"],

                # =====================
                # MITRE
                # =====================

                "mitre_technique":
                mitre["technique"],

                "mitre_name":
                mitre["name"],

                "mitre_tactic":
                mitre["tactic"]

            })

    # =====================================
    # SUSPICIOUS DOMAINS
    # =====================================

    suspicious_keywords = [

        "malware",

        "trojan",

        "evil",

        "payload",

        "c2",

        "command"

    ]

    for domain, count in domain_counter.items():

        for keyword in suspicious_keywords:

            if keyword in str(domain).lower():

                mitre = map_to_mitre(
                    "Suspicious Domain"
                )

                alerts.append({

                    "severity": "HIGH",

                    "rule":
                    "Suspicious Domain",

                    "ip": "Unknown",

                    "count": count,

                    "source": "DNS",

                    "timestamp":
                    events[0]["timestamp"],

                    "risk_score": 85,

                    "ip_type": "Unknown",

                    "message":
                    f"Suspicious domain detected: {domain}",

                    # =====================
                    # THREAT INTEL
                    # =====================

                    "country":
                    "Unknown",

                    "asn":
                    "Unknown",

                    "threat_score":
                    85,

                    "risk":
                    "HIGH",

                    # =====================
                    # MITRE
                    # =====================

                    "mitre_technique":
                    mitre["technique"],

                    "mitre_name":
                    mitre["name"],

                    "mitre_tactic":
                    mitre["tactic"]

                })

                break

    print(
        f"[DNS DETECTOR] Generated "
        f"{len(alerts)} alerts"
    )

    return alerts