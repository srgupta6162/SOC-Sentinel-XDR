import os


def detect_log_type(filepath):

    filename = os.path.basename(filepath).lower()

    auth_keywords = [
        "auth",
        "secure",
        "security",
        "ssh",
        "login"
    ]

    firewall_keywords = [
        "firewall",
        "ufw",
        "iptables",
        "pfsense",
        "fortigate"
    ]

    web_keywords = [
        "access",
        "nginx",
        "apache",
        "web",
        "http"
    ]

    dns_keywords = [
        "dns",
        "bro_dns",
        "zeek_dns"
    ]

    windows_keywords = [
        "windows",
        "event",
        "sysmon"
    ]

    for keyword in auth_keywords:
        if keyword in filename:
            return "auth"

    for keyword in firewall_keywords:
        if keyword in filename:
            return "firewall"

    for keyword in web_keywords:
        if keyword in filename:
            return "web"

    for keyword in dns_keywords:
        if keyword in filename:
            return "dns"

    for keyword in windows_keywords:
        if keyword in filename:
            return "windows"

    return "unknown"


if __name__ == "__main__":

    test_files = [
        "auth.log",
        "firewall.log",
        "access.log",
        "dns.log",
        "windows_event.log"
    ]

    for file in test_files:

        print(
            f"{file} -> "
            f"{detect_log_type(file)}"
        )