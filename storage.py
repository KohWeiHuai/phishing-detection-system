from datetime import datetime

RESULTS_FILE = "results.txt"
AUDIT_FILE = "audit.log"


def save_result(username: str, result: str, score: int, reasons):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reasons_text = "; ".join(reasons) if reasons else ""
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{timestamp} | user={username} | result={result} | score={score} | reasons={reasons_text}\n"
        )


def _parse_result_line(line: str):
    """
    Parses a line like:
    2026-02-23 11:10:05 | user=TestUser1 | result=SUSPICIOUS | score=5 | reasons=...
    Returns dict: {timestamp, user, result, score, reasons(list), raw}
    """
    raw = line.strip()
    parts = [p.strip() for p in raw.split("|")]

    if len(parts) < 4:
        return None

    timestamp = parts[0]  

    user = ""
    result = ""
    score = 0
    reasons_list = []

    for p in parts[1:]:
        if p.startswith("user="):
            user = p.replace("user=", "", 1).strip()
        elif p.startswith("result="):
            result = p.replace("result=", "", 1).strip()
        elif p.startswith("score="):
            try:
                score = int(p.replace("score=", "", 1).strip())
            except ValueError:
                score = 0
        elif p.startswith("reasons="):
            reasons_text = p.replace("reasons=", "", 1).strip()
            if reasons_text:
                # split back from "; "
                reasons_list = [x.strip() for x in reasons_text.split(";") if x.strip()]

    return {
        "timestamp": timestamp,
        "user": user,
        "result": result,
        "score": score,
        "reasons": reasons_list,
        "raw": raw
    }


def get_user_results(username: str, limit: int = 50):
    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            lines = [ln for ln in f if f"user={username}" in ln]

        parsed = []
        for ln in reversed(lines):
            obj = _parse_result_line(ln)
            if obj:
                parsed.append(obj)
            if len(parsed) >= limit:
                break

        return parsed
    except FileNotFoundError:
        return []


def read_all_results(limit: int = 100):
    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        parsed = []
        for ln in reversed(lines):
            obj = _parse_result_line(ln)
            if obj:
                parsed.append(obj)
            if len(parsed) >= limit:
                break

        return parsed
    except FileNotFoundError:
        return []


def read_audit_log(limit: int = 120):
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return list(reversed(lines))[:limit]
    except FileNotFoundError:
        return []