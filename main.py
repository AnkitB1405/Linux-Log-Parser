from parser.ssh_parser import identify_event


with open("sample_logs/ssh_sample.txt") as file:

    for line in file:

        event = identify_event(line)

        if event:
            print(event)