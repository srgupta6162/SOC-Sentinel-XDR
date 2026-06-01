from parsers.auth_parser import parse_auth_log
from detectors.brute_force import detect_brute_force

events = parse_auth_log()

alerts = detect_brute_force(events)

print("\n=== EVENTS ===")

for e in events:
    print(e)

print("\n=== ALERTS ===")

for alert in alerts:
    print(alert)