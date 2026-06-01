from parsers.dns_parser import parse_dns_log

events = parse_dns_log(
    "uploads/dns.log"
)

print(
    "TOTAL EVENTS:",
    len(events)
)

for e in events[:5]:

    print(e)