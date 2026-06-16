from parser.ssh_parser import identify_event

line = "Failed password for invalid user fakeuser from ::1 port 60198 ssh2"

result = identify_event(line)

print(result)