from parsers.auth_parser import parse_auth_log
from parsers.firewall_parser import parse_firewall_log
from parsers.nginx_parser import parse_web_log

from detectors.brute_force import detect_brute_force
from detectors.port_scan import detect_port_scan
from detectors.web_attacks import detect_web_attacks
from detectors.threat_intel import enrich_alert

from mitre.mapper import map_to_mitre

from storage import (
    init_db,
    insert_event,
    insert_alert,
    create_incident
)


def main():

    # ==========================================
    # INITIALIZE DATABASE
    # ==========================================

    init_db()

    print("\n==============================")
    print("     SOC SENTINEL XDR")
    print("==============================\n")

    # ==========================================
    # COLLECT EVENTS
    # ==========================================

    auth_events = parse_auth_log()

    firewall_events = parse_firewall_log()

    web_events = parse_web_log()

    events = (
        auth_events +
        firewall_events +
        web_events
    )

    print(f"Collected Events : {len(events)}")

    # ==========================================
    # STORE EVENTS
    # ==========================================

    for event in events:
        insert_event(event)

    # ==========================================
    # DETECTION ENGINE
    # ==========================================

    alerts = []

    # SSH BRUTE FORCE

    alerts.extend(
        detect_brute_force(auth_events)
    )

    # PORT SCAN

    alerts.extend(
        detect_port_scan(firewall_events)
    )

    # WEB ATTACKS

    alerts.extend(
        detect_web_attacks(web_events)
    )

    # ==========================================
    # THREAT INTELLIGENCE + MITRE ENRICHMENT
    # ==========================================

    enriched_alerts = []

    for alert in alerts:

        # Threat Intelligence
        enriched = enrich_alert(alert)

        # ======================================
        # MITRE ATT&CK ENRICHMENT
        # ======================================

        mitre = map_to_mitre(
            enriched["rule"]
        )

        enriched["mitre_technique"] = (
            mitre["technique"]
        )

        enriched["mitre_name"] = (
            mitre["name"]
        )

        enriched["mitre_tactic"] = (
            mitre["tactic"]
        )

        enriched_alerts.append(
            enriched
        )

        # Store Alert
        insert_alert(
            enriched
        )

        # Create Incident Automatically
        create_incident(
            enriched
        )

    # ==========================================
    # SUMMARY
    # ==========================================

    print("\n===== SUMMARY =====\n")

    print(
        f"Events Stored  : {len(events)}"
    )

    print(
        f"Alerts Created : {len(enriched_alerts)}"
    )

    print(
        f"Incidents Open : {len(enriched_alerts)}"
    )

    print("\n===== ALERT SUMMARY =====\n")

    for alert in enriched_alerts:

        print(
            f"[{alert['severity']}] "
            f"{alert['rule']} | "
            f"{alert['ip']} | "
            f"Risk Score={alert['risk_score']} | "
            f"MITRE={alert['mitre_technique']}"
        )

    print("\nSOC Sentinel completed successfully.\n")


if __name__ == "__main__":
    main()