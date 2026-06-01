from parsers.nginx_parser import parse_web_log

events = parse_web_log()

for event in events:
    print(event)