from datetime import datetime


def parse_dns_log(filepath):

    events = []

    MAX_EVENTS = 1000

    try:

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                parts = line.split()

                if len(parts) < 5:
                    continue

                try:
                    src_ip = parts[2]
                except:
                    src_ip = "Unknown"

                query = "Unknown"

                for item in parts:

                    if (
                        "." in item
                        and not item.replace(".", "").isdigit()
                    ):
                        query = item
                        break

                events.append({

                    "type": "dns",

                    "status": "query",

                    "ip": src_ip,

                    "query": query,

                    "timestamp":
                    datetime.now().isoformat(),

                    "raw": line

                })

                if len(events) >= MAX_EVENTS:

                    print(
                        f"[DNS] Reached limit of {MAX_EVENTS} events"
                    )

                    break

    except Exception as e:

        print(
            f"[DNS PARSER ERROR] {e}"
        )

    print(
        f"[DNS] Parsed {len(events)} events"
    )

    return events