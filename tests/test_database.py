from parsers.auth_parser import parse_auth_log
from detectors.brute_force import detect_brute_force

from storage import (
    init_db,
    insert_event,
    insert_alert
)

init_db()

events = parse_auth_log()

for event in events:
    insert_event(event)

alerts = detect_brute_force(events)

for alert in alerts:
    insert_alert(alert)

print("Events stored successfully")
print("Alerts stored successfully")