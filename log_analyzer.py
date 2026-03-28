import re
from collections import Counter
from datetime import datetime

LOG_PATH = "logs/sample_auth.log"

FAILED_PATTERN = re.compile(
    r"^(?P<timestamp>\S+ \S+) FAILED login for user (?P<user>\S+) from (?P<ip>\S+)"
)
SUCCESS_PATTERN = re.compile(
    r"^(?P<timestamp>\S+ \S+) SUCCESS login for user (?P<user>\S+) from (?P<ip>\S+)"
)

def parse_timestamp(ts_str):
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")

def analyze_log(path: str):
    failed_attempts = []
    successful_logins = []
    by_ip_failed = Counter()
    by_user_failed = Counter()
    night_logins = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m_failed = FAILED_PATTERN.match(line)
            m_success = SUCCESS_PATTERN.match(line)

            if m_failed:
                ts = parse_timestamp(m_failed.group("timestamp"))
                user = m_failed.group("user")
                ip = m_failed.group("ip")
                failed_attempts.append((ts, user, ip))
                by_ip_failed[ip] += 1
                by_user_failed[user] += 1

            elif m_success:
                ts = parse_timestamp(m_success.group("timestamp"))
                user = m_success.group("user")
                ip = m_success.group("ip")
                successful_logins.append((ts, user, ip))

                if ts.hour >= 22 or ts.hour < 6:
                    night_logins.append((ts, user, ip))

    return {
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "by_ip_failed": by_ip_failed,
        "by_user_failed": by_user_failed,
        "night_logins": night_logins,
    }

def detect_bruteforce(by_ip_failed: Counter, threshold: int = 3):
    return {ip: count for ip, count in by_ip_failed.items() if count >= threshold}

def main():
    print(f"[+] Analyzing log file: {LOG_PATH}")
    results = analyze_log(LOG_PATH)

    print("\n=== Summary ===")
    print(f"Total failed attempts: {len(results['failed_attempts'])}")
    print(f"Total successful logins: {len(results['successful_logins'])}")

    print("\nTop IPs with failed attempts:")
    for ip, count in results["by_ip_failed"].most_common():
        print(f"  {ip}: {count}")

    print("\nTop users with failed attempts:")
    for user, count in results["by_user_failed"].most_common():
        print(f"  {user}: {count}")

    print("\nPossible brute force (>=3 failed attempts):")
    suspects = detect_bruteforce(results["by_ip_failed"])
    if suspects:
        for ip, count in suspects.items():
            print(f"  {ip}: {count}")
    else:
        print("  None")

    print("\nNight-time successful logins (22:00–06:00):")
    if results["night_logins"]:
        for ts, user, ip in results["night_logins"]:
            print(f"  {ts} - {user} from {ip}")
    else:
        print("  None")

if __name__ == "__main__":
    main()




