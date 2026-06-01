import ipaddress


def get_risk_score(alert):

    if alert["severity"] == "HIGH":
        return 90

    elif alert["severity"] == "MEDIUM":
        return 60

    return 30


def get_ip_type(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "Private"

        return "Public"

    except Exception:

        return "Unknown"


def enrich_alert(alert):

    alert["risk_score"] = get_risk_score(alert)

    alert["ip_type"] = get_ip_type(
        alert["ip"]
    )

    # ==================================
    # Demo Threat Intelligence
    # ==================================

    if alert["ip_type"] == "Private":

        alert["country"] = "Internal Network"

        alert["asn"] = "Local LAN"

        alert["threat_score"] = alert[
            "risk_score"
        ]

    else:

        alert["country"] = "Unknown"

        alert["asn"] = "Unknown"

        alert["threat_score"] = alert[
            "risk_score"
        ]

    # ==================================
    # Risk Level
    # ==================================

    if alert["threat_score"] >= 80:

        alert["risk"] = "HIGH"

    elif alert["threat_score"] >= 50:

        alert["risk"] = "MEDIUM"

    else:

        alert["risk"] = "LOW"

    return alert