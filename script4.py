from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
import re

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    BLUE   = "\033[34m"
    MAGENTA= "\033[35m"
    CYAN   = "\033[36m"
    GRAY   = "\033[90m"


def color(text: str, *styles: str) -> str:
    return "".join(styles) + text + C.RESET


def ok(msg="ok"):
    print(color(msg, C.GREEN))


def warn(msg):
    print(color(msg, C.YELLOW))


def err(msg):
    print(color(msg, C.RED, C.BOLD))


DefaultSettings = {
        "mode": "bruteforce",
        "paths": ["/var/log/auth.log", "/var/log/syslog"],
        "threshold": 5,
        "window_minutes": 5,
    }

IP_RX = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
TS_RX = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")  # "Jan  2 03:04:05"

FAILED_NEEDLE = "failed password"


def extract_ip(line: str):
    m = IP_RX.search(line)
    return m.group() if m else None


def extract_ts(line: str, year: int):
    m = TS_RX.search(line)
    if not m:
        return None
    ts_str = m.group()
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=year)
    except ValueError:
        return None


def parse_failed_event(line: str, year: int):
    """
    Returns (ts, ip) if line looks like a failed SSH login event and we can parse it.
    Otherwise returns None.
    """
    s = line.strip()
    if not s:
        return None
    if FAILED_NEEDLE not in s.lower():
        return None

    ip = extract_ip(s)
    if not ip:
        return None

    ts = extract_ts(s, year)
    if not ts:
        return None

    return ts, ip


def detect_bruteforce(events, window_minutes: int, threshold: int):
    window = timedelta(minutes=window_minutes)

    buckets = defaultdict(deque)  # ip -> deque[timestamps]
    alerts = []
    alerted = set()  # avoid repeated alerts per IP

    for ts, ip in events:
        q = buckets[ip]
        q.append(ts)

        cutoff = ts - window
        while q and q[0] < cutoff:
            q.popleft()

        if ip not in alerted and len(q) >= threshold:
            alerts.append((ip, len(q), q[0], q[-1]))
            alerted.add(ip)

    return alerts


def iter_events_from_paths(paths):
    year = datetime.now().year

    for p in paths:
        path = Path(p)
        if not path.exists() or not path.is_file():
            # You can replace prints with warn(...) if you have it
            print(f"[WARN] Missing or not a file: {path}")
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = parse_failed_event(line, year)
                    if ev is not None:
                        yield ev
        except PermissionError:
            print(f"[WARN] Permission denied: {path} (try sudo)")
        except OSError as e:
            print(f"[WARN] Error reading {path}: {e}")


def run_bruteforce(settings: dict):
    ok("Running detect bruteforce mode")
    """
    Bruteforce mode entry point.
    settings expects:
      - paths: list[str]
      - threshold: int
      - window_minutes: int
    """
    paths = settings.get("paths", [])
    threshold = int(settings.get("threshold", 5))
    window_minutes = int(settings.get("window_minutes", 5))

    events = list(iter_events_from_paths(paths))

    # Logs are usually chronological, but if multiple files are mixed, sort to be safe.
    events.sort(key=lambda e: e[0])

    alerts = detect_bruteforce(events, window_minutes=window_minutes, threshold=threshold)

    if not alerts:
        print(f"[OK] No brute-force alerts (>= {threshold} fails in {window_minutes} min).")
        return

    print(f"[ALERT] Brute-force detected (>= {threshold} fails in {window_minutes} min):\n")
    for ip, count, first_ts, last_ts in alerts:
        print(f"  {ip} -> {count} fails | {first_ts} .. {last_ts}")



def run_newip(mconfig):
    ok("Running newip mode")

    return


def print_settings(settings: dict) -> None:
    width = max(len(k) for k in settings)

    print(color("\nCurrent settings:", C.GREEN, C.BOLD))
    for k in sorted(settings):
        v = settings[k]

        k_fmt = color(f"{k:<{width}}", C.BLUE, C.BOLD)
        arrow = color("--->", C.GRAY)
        v_fmt = color(str(v), C.CYAN)

        print(f"{k_fmt} {arrow} {v_fmt}")
    print()


def repl(settings: dict):
    commands = {"show", "setthreshold", "setwindow", "addpath", "delpath", "default", "setmode", "help", "start", "quit", "q"}
    runmodes = {"bruteforce", "newip"}

    while True:
        raw = input("> ").strip()
        if not raw:
            continue

        cmd = raw.split(maxsplit=1)
        name = cmd[0].lower()
        arg = cmd[1] if len(cmd) > 1 else ""

        if name not in commands:
            warn("Unknown command. Type 'help' for available commands.")
            continue

        if name == "quit" or name == "q":
            return None

        if name == "start":
            return settings

        if name == "show":
            print_settings(settings)
            continue

        if name == "help":
            print("Commands:", ", ".join(sorted(commands)))
            continue

        if name == "setthreshold":
            if not arg:
                print("Usage: setthreshold <int>")
                continue
            try:
                settings["threshold"] = int(arg)
                ok("ok")
            except ValueError:
                warn("threshold must be an integer")
            continue

        if name == "setwindow":
            if not arg:
                warn("Usage: setwindow <minutes>")
                continue
            try:
                settings["window_minutes"] = int(arg)
                ok("ok")
            except ValueError:
                warn("window_minutes must be an integer")
            continue

        if name == "addpath":
            if not arg:
                warn("Usage: addpath <path>")
                continue
            settings["paths"].append(arg)
            ok("ok")
            continue

        if name == "delpath":
            if not arg:
                warn("Usage: delpath <path>")
                continue
            if arg in settings["paths"]:
                settings["paths"].remove(arg)
                ok("ok")
            else:
                warn("path not found in current paths")
            continue

        if name == "default":
            settings.clear()
            settings.update(DefaultSettings)
            ok("ok")
            continue

        if name == "setmode":
            if not arg:
                warn("Usage: setmode <mode>")
                continue
            if arg not in runmodes:
                warn("mode not found")
                continue
            settings["mode"]=arg
            ok("ok")
            continue


if __name__ == "__main__":
    settings = {
        "mode": "bruteforce",
        "paths": ["/var/log/auth.log", "/var/log/syslog"],
        "threshold": 5,
        "window_minutes": 5,
    }

    print(color("Mini SIEM (interactive)", C.MAGENTA, C.BOLD))
    print_settings(settings)

    final_settings = repl(settings)
    if final_settings is None:
        print(color("Bye.", C.MAGENTA, C.BOLD))
    else:
        cmode = final_settings["mode"]
        print(color("Starting up... ", C.MAGENTA, C.BOLD))
        if cmode == "bruteforce":
            run_bruteforce(final_settings)
        elif cmode == "newip":
            run_newip(final_settings)
        else:
            err("Mode unable to run. Terminating.")
            


        
        

