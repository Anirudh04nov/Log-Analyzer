import re
from collections import defaultdict, Counter
from datetime import datetime
import matplotlib.pyplot as plt

# -------------------------------
# Timestamp Extractor
# -------------------------------
class TimestampExtractor:
    def __init__(self):
        self.patterns = [
            re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
            re.compile(r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}")
        ]

    def extract(self, line):
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                return match.group()
        return None


# -------------------------------
# Main Analyzer
# -------------------------------
def analyze_log(file_path):
    extractor = TimestampExtractor()

    failed_attempts = defaultdict(list)
    successful_logins = []
    timeline = []
    alerts = []
    risk_scores = {}

    ip_pattern = re.compile(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")

    with open(file_path, "r") as file:
        for line in file:
            ip_match = ip_pattern.search(line)
            time_str = extractor.extract(line)

            if not ip_match or not time_str:
                continue

            ip = ip_match.group(1)

            try:
                time_obj = datetime.strptime(time_str, "%b %d %H:%M:%S")
            except:
                time_obj = None

            # -------- EVENTS --------
            if "Failed password" in line:
                if time_obj:
                    failed_attempts[ip].append(time_obj)
                timeline.append(f"{time_str} - FAILED login from {ip}")

            elif "Accepted password" in line:
                if time_obj:
                    successful_logins.append((ip, time_obj))
                timeline.append(f"{time_str} - SUCCESS login from {ip}")

    # -------- DETECTION --------
    for ip, times in failed_attempts.items():
        times.sort()
        count = len(times)

        # brute force detection
        for i in range(len(times)):
            window = [t for t in times if (t - times[i]).seconds <= 120]
            if len(window) >= 3:
                alerts.append(f"HIGH: Brute force attack from {ip}")
                break

        if count >= 5:
            alerts.append(f"MEDIUM: Multiple failed attempts from {ip} ({count})")

        if count >= 10:
            alerts.append(f"HIGH: Aggressive attack from {ip}")

    # suspicious login
    for ip, _ in successful_logins:
        if ip in failed_attempts:
            alerts.append(f"HIGH: Suspicious login from {ip}")

    # -------- CLEAN OUTPUT --------
    alerts = list(set(alerts))[:10]
    timeline = timeline[-20:]

    # -------- TOP ATTACKERS --------
    sorted_attackers = sorted(
        failed_attempts.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

    top_attackers = sorted_attackers[:5]
    graph_attackers = sorted_attackers[:10]

    top_attackers_list = [(ip, len(times)) for ip, times in top_attackers]

    # -------- RISK SCORING --------
    for ip, times in failed_attempts.items():
        score = len(times) * 2

        if len(times) >= 5:
            score += 10

        if ip in [sip for sip, _ in successful_logins]:
            score += 15

        risk_scores[ip] = score

    top_risky_ips = sorted(
        risk_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # -------- GRAPH (Top 10 clean) --------
    if graph_attackers:
        ips = [ip for ip, _ in graph_attackers]
        counts = [len(times) for _, times in graph_attackers]

        plt.figure(figsize=(10, 6))
        plt.barh(ips, counts)
        plt.xlabel("Failed Attempts")
        plt.ylabel("IP Address")
        plt.title("Top 10 Attackers")
        plt.tight_layout()
        plt.savefig("static/graph.png")
        plt.close()

    # -------- TIME TREND (FIXED CLEAN) --------
    time_counter = Counter()

    for ip, times in failed_attempts.items():
        for t in times:
            minute_bucket = (t.minute // 5) * 5
            key = t.strftime(f"%H:{minute_bucket:02d}")
            time_counter[key] += 1

    if time_counter:
        sorted_times = sorted(time_counter.items())

        times = [t for t, _ in sorted_times]
        counts = [c for _, c in sorted_times]

        plt.figure(figsize=(10, 5))
        plt.plot(counts, marker='o')

        # reduce labels
        step = max(1, len(times)//10)
        plt.xticks(range(0, len(times), step), times[::step], rotation=45)

        plt.xlabel("Time (5-min intervals)")
        plt.ylabel("Attack Count")
        plt.title("Attack Trend Over Time")

        plt.tight_layout()
        plt.savefig("static/time_graph.png")
        plt.close()

    # -------- REPORT --------
    with open("report.txt", "w") as f:
        f.write("=== SECURITY REPORT ===\n\n")
        for alert in alerts:
            f.write(alert + "\n")

    total_ips = len(failed_attempts)

    return alerts, top_attackers_list, timeline, total_ips, top_risky_ips