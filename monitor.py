
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import os
import time

# ==========================================
# PARSERS
# ==========================================

from parsers.auth_parser import parse_auth_log
from parsers.firewall_parser import parse_firewall_log
from parsers.dns_parser import parse_dns_log
from parsers.nginx_parser import parse_web_log

# ==========================================
# DETECTORS
# ==========================================

from detectors.brute_force import detect_brute_force
from detectors.port_scan import detect_port_scan
from detectors.dns_detector import detect_dns_threats
from detectors.web_attacks import detect_web_attacks

from detectors.threat_intel import enrich_alert

# ==========================================
# MITRE
# ==========================================

from mitre.mapper import map_to_mitre

# ==========================================
# STORAGE
# ==========================================

from storage import (
    insert_alert,
    create_incident
)


# ==========================================
# ALERT PROCESSING
# ==========================================

def process_alerts(alerts):

    for alert in alerts:

        try:

            # MITRE ATT&CK

            mitre = map_to_mitre(
                alert["rule"]
            )

            alert["mitre_technique"] = (
                mitre["technique"]
            )

            alert["mitre_name"] = (
                mitre["name"]
            )

            alert["mitre_tactic"] = (
                mitre["tactic"]
            )

            # Threat Intelligence

            alert = enrich_alert(
                alert
            )

            # Store Alert

            insert_alert(
                alert
            )

            # Create Incident

            create_incident(
                alert
            )

            print(
                f"[ALERT] "
                f"{alert['rule']} | "
                f"{alert['ip']}"
            )

        except Exception as e:

            print(
                f"[ALERT ERROR] {e}"
            )


# ==========================================
# FILE MONITOR
# ==========================================

class LogHandler(
    FileSystemEventHandler
):

    def on_modified(
        self,
        event
    ):

        if event.is_directory:
            return

        path = event.src_path.lower()

        print(
            f"[+] Modified: {path}"
        )

        try:

            # ==========================
            # AUTH LOG
            # ==========================

            if "auth.log" in path:

                events = parse_auth_log(
                    path
                )

                alerts = detect_brute_force(
                    events
                )

                process_alerts(
                    alerts
                )

            # ==========================
            # FIREWALL LOG
            # ==========================

            elif "firewall.log" in path:

                events = parse_firewall_log(
                    path
                )

                alerts = detect_port_scan(
                    events
                )

                process_alerts(
                    alerts
                )

            # ==========================
            # DNS LOG
            # ==========================

            elif "dns.log" in path:

                events = parse_dns_log(
                    path
                )

                alerts = detect_dns_threats(
                    events
                )

                process_alerts(
                    alerts
                )

            # ==========================
            # NGINX LOG
            # ==========================

            elif "nginx.log" in path:

                events = parse_web_log(
                    path
                )

                alerts = detect_web_attacks(
                    events
                )

                process_alerts(
                    alerts
                )

        except Exception as e:

            print(
                f"[ERROR] {e}"
            )


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    LOG_DIR = os.path.join(
        os.getcwd(),
        "test_logs"
    )

    print(
        f"Monitoring: {LOG_DIR}"
    )

    if not os.path.exists(
        LOG_DIR
    ):

        print(
            "[ERROR] test_logs folder not found!"
        )

        exit()

    observer = Observer()

    observer.schedule(

        LogHandler(),

        LOG_DIR,

        recursive=False

    )

    observer.start()

    print(
        "[SOC Sentinel] V16 Real-Time Monitoring Started"
    )

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()

