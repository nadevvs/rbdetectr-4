# rbdetectr-4 — Mini detector for malicious activity

lightweight, interactive, host-based log analysis tool for detecting unusual activity.

---

## Requirements
- Python 3.9+
- Linux system (tested on Ubuntu)
- Access to authentication logs (`/var/log/auth.log`, `/var/log/syslog`)
- `sudo` may be required

---

## To list commands type 'help' in console
addpath, default, delpath, help, q, quit, setmode, setthreshold, setwindow, show, start
- addpath: adds a new log file location
- default: sets defaul settings of a tool
- delpath: deletes provided log file location
- help: lists commands
- quit, q: terminates the script
- setmode: set a type of instructions for a script to run (yet only 1 mode developed)
- setthreshold: set amount of failed attempts to be marked as suspicious
- setwindow: set a timestamp inside which multiple entries may be marked as suspicious
- show: displays current settings
- start: runs selected mode (default: brute-force detector)

---

## Run
```bash
python3 script4.py
