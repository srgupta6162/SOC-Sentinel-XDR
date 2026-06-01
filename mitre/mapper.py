MITRE_MAP = {

    # =====================================
    # AUTH LOGS
    # =====================================

    "Brute Force Detection": {

        "technique": "T1110",

        "name": "Brute Force",

        "tactic": "Credential Access"

    },

    # =====================================
    # FIREWALL
    # =====================================

    "Port Scan Detection": {

        "technique": "T1046",

        "name": "Network Service Discovery",

        "tactic": "Discovery"

    },

    # =====================================
    # WEB ATTACKS
    # =====================================

    "SQL Injection": {

        "technique": "T1190",

        "name": "Exploit Public-Facing Application",

        "tactic": "Initial Access"

    },

    "Cross Site Scripting": {

        "technique": "T1059.007",

        "name": "JavaScript",

        "tactic": "Execution"

    },

    "Directory Traversal": {

        "technique": "T1006",

        "name": "Path Traversal",

        "tactic": "Defense Evasion"

    },

    "Admin Panel Access": {

        "technique": "T1190",

        "name": "Exploit Public-Facing Application",

        "tactic": "Initial Access"

    },

    # =====================================
    # DNS
    # =====================================

    "High DNS Activity": {

        "technique": "T1071.004",

        "name": "DNS Protocol",

        "tactic": "Command and Control"

    },

    "Suspicious Domain": {

        "technique": "T1071.004",

        "name": "DNS Protocol",

        "tactic": "Command and Control"

    }

}


def map_to_mitre(rule):

    return MITRE_MAP.get(

        rule,

        {

            "technique": "Unknown",

            "name": "Unknown",

            "tactic": "Unknown"

        }

    )