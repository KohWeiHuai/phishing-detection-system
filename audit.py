from datetime import datetime

LOG_FILE = "audit.log"


def log_event(event: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {event}\n")