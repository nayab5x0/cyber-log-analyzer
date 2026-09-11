import re
from pathlib import Path
def parse_log_line(line):
    pattern = (
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
        r"IP=(?P<ip>\S+) "
        r"USER=(?P<username>\S+) "
        r"EVENT=(?P<event>\S+) "
        r"STATUS=(?P<status>\S+)"
    )

    match = re.search(pattern, line)

    if match:
        return match.groupdict()

    return None


def parse_log_file(file_path):
    records = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            record = parse_log_line(line)

            if record:
                records.append(record)

    return records


if __name__ == "__main__":
    file_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.log"

    records = parse_log_file(file_path)

    print("Total records:", len(records))

    for record in records:
        print(record)