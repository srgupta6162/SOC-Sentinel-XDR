
from sigma_engine import load_sigma_rules


def detect_web_attacks(events):

    rules = load_sigma_rules()

    alerts = []

    # =====================================
    # LOAD SIGMA RULES
    # =====================================

    sql_rule = rules.get(
        "SQL Injection",
        {}
    )

    xss_rule = rules.get(
        "Cross Site Scripting",
        {}
    )

    sql_keywords = sql_rule.get(
        "detection",
        {}
    ).get(
        "keywords",
        [
            "or 1=1",
            "'"
        ]
    )

    xss_keywords = xss_rule.get(
        "detection",
        {}
    ).get(
        "keywords",
        [
            "<script>"
        ]
    )

    # =====================================
    # ANALYZE EVENTS
    # =====================================

    for event in events:

        url = event["url"].lower()

        # =================================
        # SQL INJECTION
        # =================================

        if any(
            keyword.lower() in url
            for keyword in sql_keywords
        ):

            alerts.append({

                "severity": "HIGH",

                "rule":
                "SQL Injection",

                "ip":
                event["ip"],

                "count": 1,

                "source": "Web",

                "timestamp":
                event["timestamp"],

                "message":
                f"Possible SQL Injection from {event['ip']}"

            })

        # =================================
        # CROSS SITE SCRIPTING
        # =================================

        elif any(
            keyword.lower() in url
            for keyword in xss_keywords
        ):

            alerts.append({

                "severity": "HIGH",

                "rule":
                "Cross Site Scripting",

                "ip":
                event["ip"],

                "count": 1,

                "source": "Web",

                "timestamp":
                event["timestamp"],

                "message":
                f"Possible XSS attack from {event['ip']}"

            })

        # =================================
        # DIRECTORY TRAVERSAL
        # =================================

        elif "../" in url:

            alerts.append({

                "severity": "HIGH",

                "rule":
                "Directory Traversal",

                "ip":
                event["ip"],

                "count": 1,

                "source": "Web",

                "timestamp":
                event["timestamp"],

                "message":
                f"Possible Directory Traversal from {event['ip']}"

            })

        # =================================
        # ADMIN PANEL ACCESS
        # =================================

        elif "/admin" in url:

            alerts.append({

                "severity": "MEDIUM",

                "rule":
                "Admin Panel Access",

                "ip":
                event["ip"],

                "count": 1,

                "source": "Web",

                "timestamp":
                event["timestamp"],

                "message":
                f"Admin panel access from {event['ip']}"

            })

    return alerts
