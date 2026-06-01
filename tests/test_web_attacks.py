from parsers.nginx_parser import parse_web_log
from detectors.web_attacks import detect_web_attacks

events = parse_web_log()

alerts = detect_web_attacks(events)

print("\n=== WEB ALERTS ===\n")

for alert in alerts:
    print(alert)