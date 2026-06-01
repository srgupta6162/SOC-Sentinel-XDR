import re

from datetime import datetime


# ==========================================
# WINDOWS EVENT LOG PATTERNS
# ==========================================

FAILED_LOGIN_PATTERN = re.compile(
    r"EventID:\s*4625.*?Account Name:\s*(\S+).*?Source Network Address:\s*([\d\.]+)",
    re.DOTALL
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"EventID:\s*4624.*?Account Name:\s*(\S+).*?Source Network Address:\s*([\d\.]+)",
    re.DOTALL
)

ACCOUNT_LOCK_PATTERN = re.compile(
    r"EventID:\s*4740.*?Account Name:\s*(\S+)",
    re.DOTALL
)


# ==========================================
# WINDOWS LOG PARSER
# ==========================================

def parse_windows_log(filepath):

    events = []

    try:

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

        # ==================================
        # FAILED LOGIN
        # ==================================

        failed_matches = FAILED_LOGIN_PATTERN.findall(
            content
        )

        for user, ip in failed_matches:

            events.append({

                "type": "windows",

                "status": "failed",

                "user": user,

                "ip": ip,

                "timestamp": datetime.now().isoformat(),

                "raw": f"Failed Login | {user} | {ip}"

            })

        # ==================================
        # SUCCESS LOGIN
        # ==================================

        success_matches = SUCCESS_LOGIN_PATTERN.findall(
            content
        )

        for user, ip in success_matches:

            events.append({

                "type": "windows",

                "status": "success",

                "user": user,

                "ip": ip,

                "timestamp": datetime.now().isoformat(),

                "raw": f"Successful Login | {user} | {ip}"

            })

        # ==================================
        # ACCOUNT LOCKOUT
        # ==================================

        lock_matches = ACCOUNT_LOCK_PATTERN.findall(
            content
        )

        for user in lock_matches:

            events.append({

                "type": "windows",

                "status": "locked",

                "user": user,

                "ip": "N/A",

                "timestamp": datetime.now().isoformat(),

                "raw": f"Account Locked | {user}"

            })

    except Exception as e:

        print(
            f"[ERROR] Windows Parser: {e}"
        )

    return events


# ==========================================
# TEST MODE
# ==========================================

if __name__ == "__main__":

    sample_file = "sample_windows.log"

    results = parse_windows_log(
        sample_file
    )

    print("\n=== WINDOWS EVENTS ===\n")

    for event in results:

        print(event)