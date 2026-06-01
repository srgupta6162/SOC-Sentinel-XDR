import ipaddress


def get_risk_score(alert):

    if alert["severity"] == "HIGH":
        return 90

    elif alert["severity"] == "MEDIUM":
        return 60

    else:
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

    return alert