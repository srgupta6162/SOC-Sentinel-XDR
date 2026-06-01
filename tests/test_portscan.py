from parsers.firewall_parser import parse_firewall_log
from detectors.port_scan import detect_port_scan

events = parse_firewall_log()

alerts = detect_port_scan(events)

print("\n=== EVENTS ===")

for e in events:
    print(e)

print("\n=== ALERTS ===")

for alert in alerts:
    print(alert)