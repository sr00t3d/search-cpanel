#!/usr/bin/env bash
# ==============================================================================
# search_cpanel.sh — cPanel/WHM Access Log Forensics & Action Parser CLI (v2.0.0)
# ==============================================================================
# Clean-room Bash + Python 3.6+ reimplementation inspired by search_cpanel
# (2011, Matthew Harris, HostGator.com, LLC).
#
# Eliminates zcat shell injection, dead CPAN dependencies (Date::Parse,
# URI::Escape), unanchored IP regexes, empty --reseller stub, and x3-only
# hardcoded patterns.
#
# Supports modern cPanel Jupiter / Paper Lantern / UAPI (/execute/), WHM API1
# (/json-api/), Webmail, File Manager, plus legacy x3 & XML-API events across
# live access_log and rotated .gz/.bz2/.xz archives.
#
# License: Apache-2.0
# Author:  Percio Castelo (https://perciocastelo.com.br)
# Repo:    https://github.com/sr00t3d/search-cpanel
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="search_cpanel.sh"
readonly SCRIPT_VERSION="2.0.0"

TARGET_USER=""
TARGET_IP=""
LIST_IPS_USER=""
RESELLER=""
SECTION=""
INCLUDE_ARCHIVE=0
RAW_MODE=0
LOG_OVERRIDE=""
SINCE_DATE=""
UNTIL_DATE=""
LIMIT_ROWS="200"
OUTPUT_FMT="table"
QUIET=0
NO_COLOR=0

C_RED=""
C_GREEN=""
C_YELLOW=""
C_CYAN=""
C_BOLD=""
C_RESET=""

init_colors() {
  if [[ "$NO_COLOR" -eq 0 && -t 1 && "$OUTPUT_FMT" == "table" ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_CYAN=$'\033[0;36m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
  fi
}

usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — cPanel/WHM Access Log Forensics & Action Parser CLI

Usage:
  ${SCRIPT_NAME} -u <user> [options]        Search cPanel/WHM actions by user
  ${SCRIPT_NAME} -i <ip> [options]          Search cPanel/WHM actions by client IP
  ${SCRIPT_NAME} -l <user> [options]        List unique client IPs that accessed <user>
  ${SCRIPT_NAME} -r <reseller> [options]    Search actions across all accounts of <reseller>

Options:
  -u, --user <user>         Filter by cPanel/WHM username
  -i, --ip <ip>             Filter by exact client IP address
  -l, --listips <user>      List unique IPs + hit counts for <user>
  -r, --reseller <user>     Search all accounts owned by reseller (/etc/trueuserowners)
  -s, --section <cat>       Filter category: ip, mail, db, software, acct, conf, domain, dns, ftp, ssl, file, auth
  -a, --archive             Include rotated archives (/usr/local/cpanel/logs/archive/access_log*.gz)
  --log <path>              Override default /usr/local/cpanel/logs/access_log path
  --since <YYYY-MM-DD>      Include events on/after UTC date
  --until <YYYY-MM-DD>      Include events on/before UTC date
  -n, --no-format, --raw    Show raw HTTP request path instead of decoded action summary
  --limit <N>               Max rows to display (default: 200, 0 = all)
  -o, --output <fmt>        Output format: table (default), json, csv
  -q, --quiet               Minimal output
  --no-color                Disable ANSI colors
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  ${SCRIPT_NAME} -u percio
  ${SCRIPT_NAME} -u percio -s mail -a
  ${SCRIPT_NAME} -i 198.51.100.10 --since 2026-11-01 -o json
  ${SCRIPT_NAME} -l percio
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help|--usage) usage; exit 0 ;;
      -v|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      -u|--user)
        [[ $# -ge 2 ]] || { printf '[ERR] --user requires a username.\n' >&2; exit 1; }
        TARGET_USER="$2"; shift 2 ;;
      -i|--ip|--ipsearch)
        [[ $# -ge 2 ]] || { printf '[ERR] --ip requires an IP address.\n' >&2; exit 1; }
        TARGET_IP="$2"; shift 2 ;;
      -l|--listips)
        [[ $# -ge 2 ]] || { printf '[ERR] --listips requires a username.\n' >&2; exit 1; }
        LIST_IPS_USER="$2"; shift 2 ;;
      -r|--reseller)
        [[ $# -ge 2 ]] || { printf '[ERR] --reseller requires a username.\n' >&2; exit 1; }
        RESELLER="$2"; shift 2 ;;
      -s|--section)
        [[ $# -ge 2 ]] || { printf '[ERR] --section requires a category.\n' >&2; exit 1; }
        SECTION="$2"; shift 2 ;;
      -a|--archive) INCLUDE_ARCHIVE=1; shift ;;
      -n|--no-format|--raw) RAW_MODE=1; shift ;;
      --log)
        [[ $# -ge 2 ]] || { printf '[ERR] --log requires a file path.\n' >&2; exit 1; }
        LOG_OVERRIDE="$2"; shift 2 ;;
      --since)
        [[ $# -ge 2 ]] || { printf '[ERR] --since requires YYYY-MM-DD.\n' >&2; exit 1; }
        SINCE_DATE="$2"; shift 2 ;;
      --until)
        [[ $# -ge 2 ]] || { printf '[ERR] --until requires YYYY-MM-DD.\n' >&2; exit 1; }
        UNTIL_DATE="$2"; shift 2 ;;
      --limit)
        [[ $# -ge 2 ]] || { printf '[ERR] --limit requires an integer.\n' >&2; exit 1; }
        LIMIT_ROWS="$2"; shift 2 ;;
      -o|--output)
        [[ $# -ge 2 ]] || { printf '[ERR] --output requires table|json|csv.\n' >&2; exit 1; }
        OUTPUT_FMT="$2"; shift 2 ;;
      -q|--quiet) QUIET=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      *)
        printf '[ERR] Unknown option: %s\n' "$1" >&2
        exit 1 ;;
    esac
  done

  if [[ -z "$TARGET_USER" && -z "$TARGET_IP" && -z "$LIST_IPS_USER" && -z "$RESELLER" ]]; then
    usage
    exit 0
  fi

  case "$OUTPUT_FMT" in
    table|json|csv) ;;
    *) printf '[ERR] Invalid --output: %s (expected table|json|csv)\n' "$OUTPUT_FMT" >&2; exit 1 ;;
  esac
}

main() {
  parse_args "$@"

  if ! command -v python3 >/dev/null 2>&1; then
    printf '[ERR] python3 is required.\n' >&2
    exit 1
  fi

  init_colors

  local ts_utc
  ts_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  local py_script
  py_script="$(cat <<'PYEOF'
import bz2
import collections
import csv
import datetime
import glob
import gzip
import io
import json
import lzma
import os
import re
import sys
import urllib.parse

(
    target_user, target_ip, list_ips_user, reseller, section,
    include_arch_s, raw_mode_s, log_override, since_date, until_date,
    limit_s, fmt, quiet_s, script_name, script_version, ts_utc,
    c_red, c_green, c_yellow, c_cyan, c_bold, c_reset
) = sys.argv[1:23]

include_arch = include_arch_s == "1"
raw_mode = raw_mode_s == "1"
limit_rows = int(limit_s)
quiet = quiet_s == "1"

LOG_LINE_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[(\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+([+-]\d{4})\]\s+"([A-Z]+)\s+(\S+)(?:\s+HTTP/[0-9.]+)?"\s+(\d{3})'
)

# Modern UAPI / WHM API1 / Jupiter + Legacy x3 / XML-API action rules
# Tuple: (action_key, section, regex, description_template)
ACTION_RULES = [
    # Auth
    ("login", "auth", re.compile(r'/login/?\b|\?post_login=|/login_only'), "cPanel/WHM: Login event"),
    ("logout", "auth", re.compile(r'/logout/?\b'), "cPanel/WHM: Logged out"),
    ("xfercpanel", "auth", re.compile(r'/xfercpanel/([^/?\s]+)'), "WHM: Switched to cPanel session for {0}"),
    # Mail
    ("addpop", "mail", re.compile(r'(?:Email/add_pop|addpop)[^"]*(?:email|user)=([^&\s]+).*?(?:domain=([^&\s]+))?'), "E-mail: Created mailbox {0}@{1}"),
    ("delpop", "mail", re.compile(r'(?:Email/delete_pop|delpop)[^"]*(?:email|user)=([^&\s]+)'), "E-mail: Deleted mailbox {0}"),
    ("passwdpop", "mail", re.compile(r'(?:Email/passwd_pop|passwdpop)[^"]*(?:email|user)=([^&\s]+)'), "E-mail: Changed mailbox password for {0}"),
    ("addfwd", "mail", re.compile(r'(?:Email/add_forwarder|doaddfwd\.html)[^"]*(?:email=([^&\s]+))?'), "E-mail: Added forwarder {0}"),
    ("delfwd", "mail", re.compile(r'(?:Email/delete_forwarder|dodelfwd\.html)[^"]*(?:email=([^&\s]+))?'), "E-mail: Deleted forwarder {0}"),
    ("webmail", "mail", re.compile(r'/(?:3rdparty/roundcube|horde|webmail)/'), "E-mail: Webmail access/action"),
    # Database
    ("adddb", "db", re.compile(r'(?:Mysql/create_database|sql/addb\.html)[^"]*(?:name=([^&\s]+)|db=([^&\s]+))?'), "Database: Created MySQL database {0}"),
    ("deldb", "db", re.compile(r'(?:Mysql/delete_database|sql/deldb\.html)[^"]*(?:name=([^&\s]+)|db=([^&\s]+))?'), "Database: Deleted MySQL database {0}"),
    ("adddbuser", "db", re.compile(r'(?:Mysql/create_user|sql/adduser\.html)'), "Database: Created MySQL user"),
    ("deldbuser", "db", re.compile(r'(?:Mysql/delete_user|deluser\.html)[^"]*(?:name=([^&\s]+)|user=([^&\s]+))?'), "Database: Deleted MySQL user {0}"),
    ("addipsql", "db", re.compile(r'(?:Mysql/add_host|sql/addhost\.html)[^"]*host=([^&\s]+)'), "Database: Added remote MySQL host {0}"),
    # FTP
    ("addftp", "ftp", re.compile(r'(?:Ftp/add_ftp|addftp)[^"]*user=([^&\s]+)'), "FTP: Added FTP account {0}"),
    ("delftp", "ftp", re.compile(r'(?:Ftp/delete_ftp|delftp)[^"]*user=([^&\s]+)'), "FTP: Deleted FTP account {0}"),
    # Domain
    ("addaddon", "domain", re.compile(r'(?:AddonDomain/addaddondomain|addon/doadddomain\.html)[^"]*(?:newdomain=([^&\s]+)|domain=([^&\s]+))?'), "Domain: Added addon domain {0}"),
    ("deladdon", "domain", re.compile(r'(?:AddonDomain/deladdondomain|addon/dodeldomain\.html)[^"]*domain=([^&\s]+)'), "Domain: Deleted addon domain {0}"),
    ("addsub", "domain", re.compile(r'(?:SubDomain/addsubdomain|subdomain/doadddomain\.html)[^"]*domain=([^&\s]+)'), "Domain: Added subdomain {0}"),
    ("delsub", "domain", re.compile(r'(?:SubDomain/delsubdomain|subdomain/dodeldomain\.html)[^"]*domain=([^&\s]+)'), "Domain: Deleted subdomain {0}"),
    ("addparked", "domain", re.compile(r'(?:Park/park|park/doaddparked\.html)[^"]*domain=([^&\s]+)'), "Domain: Added parked/alias domain {0}"),
    ("addredir", "domain", re.compile(r'(?:Mime/add_redirect|addredirect\.html)[^"]*domain=([^&\s]+)'), "Domain: Added redirect on {0}"),
    # DNS
    ("adddns", "dns", re.compile(r'(?:adddns|xml-api/adddns)[^"]*(?:zone|domain)=([^&\s]+)'), "DNS: Created zone {0}"),
    ("deldns", "dns", re.compile(r'(?:killdns|xml-api/killdns)[^"]*(?:killdns|domain)=([^&\s]+)'), "DNS: Deleted zone {0}"),
    ("editdns", "dns", re.compile(r'(?:DNS/mass_edit_zone|add_zone_record|remove_zone_record|addzonerecord|editzonerecord|addmx)[^"]*(?:zone|domain)=([^&\s]+)?'), "DNS: Modified DNS/MX records for {0}"),
    # SSL
    ("addssl", "ssl", re.compile(r'(?:SSL/install_ssl|installssl)[^"]*(?:domain=([^&\s]+))?'), "SSL: Installed certificate {0}"),
    ("delssl", "ssl", re.compile(r'(?:SSL/delete_ssl|dodelsslhost)[^"]*(?:host|domain)=([^&\s]+)?'), "SSL: Deleted certificate {0}"),
    # File Manager
    ("upload", "file", re.compile(r'(?:Fileman/upload_files|filemanager/upload|doupload\.html)'), "File Manager: Uploaded file(s)"),
    ("editfile", "file", re.compile(r'(?:Fileman/save_file_content|filemanager/editit\.html)[^"]*(?:file=([^&\s]+))?'), "File Manager: Edited file {0}"),
    ("listfiles", "file", re.compile(r'(?:Fileman/list_files|filemanager/index\.html)[^"]*(?:dir=([^&\s]+))?'), "File Manager: Listed directory {0}"),
    # Account / WHM
    ("createacct", "acct", re.compile(r'(?:createacct|wwwacct)[^"]*(?:username|user)=([^&\s]+)'), "WHM: Created account {0}"),
    ("killacct", "acct", re.compile(r'(?:removeacct|killacct)[^"]*(?:user|domain)=([^&\s]+)'), "WHM: Terminated account {0}"),
    ("suspend", "acct", re.compile(r'(?:suspendacct|suspend-domain)[^"]*user=([^&\s]+)'), "WHM: Suspended account {0}"),
    ("unsuspend", "acct", re.compile(r'(?:unsuspendacct|unsuspend-domain)[^"]*user=([^&\s]+)'), "WHM: Unsuspended account {0}"),
    ("changepw", "acct", re.compile(r'(?:passwd|changepass\.html|Passwd/change_password)[^"]*(?:user=([^&\s]+))?'), "Account: Password change {0}"),
    ("quota", "acct", re.compile(r'(?:editquota)[^"]*user=([^&\s]+)'), "WHM: Modified disk quota for {0}"),
    ("bwlimit", "acct", re.compile(r'(?:limitbw|dolimitbw)[^"]*user=([^&\s]+)'), "WHM: Modified bandwidth limit for {0}"),
    ("pkgch", "acct", re.compile(r'(?:changepackage)[^"]*user=([^&\s]+)'), "WHM: Changed package for {0}"),
    # IP & Conf & Software
    ("chgip", "ip", re.compile(r'(?:setsiteip|changeip)[^"]*user=([^&\s]+)'), "WHM: Changed site IP for {0}"),
    ("addip", "ip", re.compile(r'(?:addip\?|denyip/add\.html)[^"]*ip=([^&\s]+)'), "IP: Added/Denied IP {0}"),
    ("ressrv", "conf", re.compile(r'(?:restartservice|scripts/res)[^"]*(?:service=([^&\s]+))?'), "WHM: Restarted service {0}"),
    ("softaculous", "software", re.compile(r'(?:softaculous|fantastico|QuickInstall)'), "Software: Installer action"),
    ("fullbup", "acct", re.compile(r'(?:Backup/fullbackup|dofullbackup\.html|restoreaccount|quickrestore)'), "Backup: Full backup / restore action"),
]


def open_log_stream(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def resolve_log_files():
    if log_override:
        if not os.path.isfile(log_override):
            print(f"[ERR] Log file not found: {log_override}", file=sys.stderr)
            sys.exit(1)
        return [log_override]
    files = []
    main_log = "/usr/local/cpanel/logs/access_log"
    if os.path.isfile(main_log):
        files.append(main_log)
    if include_arch and os.path.isdir("/usr/local/cpanel/logs/archive"):
        for pat in ("access_log*.gz", "access_log*.bz2", "access_log*.xz", "access_log*"):
            for fp in sorted(glob.glob(os.path.join("/usr/local/cpanel/logs/archive", pat))):
                if fp not in files and os.path.isfile(fp):
                    files.append(fp)
    if not files:
        print("[ERR] No cPanel access_log found (use --log <path> for custom files).", file=sys.stderr)
        sys.exit(1)
    return files


def get_reseller_users(res):
    users = set()
    if os.path.isfile("/etc/trueuserowners"):
        with open("/etc/trueuserowners", "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ":" in ln:
                    u, own = ln.split(":", 1)
                    if own.strip() == res:
                        users.add(u.strip())
    return users


def classify_request(method, path):
    for key, sec, pat, tmpl in ACTION_RULES:
        m = pat.search(path)
        if m:
            groups = [urllib.parse.unquote_plus(g) if g else "" for g in m.groups()]
            msg = tmpl
            for idx, val in enumerate(groups):
                msg = msg.replace(f"{{{idx}}}", val)
            msg = re.sub(r'@$', '', msg).strip()
            return key, sec, msg
    return "other", "other", f"{method} {path[:64]}"


def parse_dt(ts_str):
    # cPanel access_log uses MM/DD/YYYY:HH:MM:SS
    try:
        return datetime.datetime.strptime(ts_str, "%m/%d/%Y:%H:%M:%S")
    except Exception:
        return None


since_dt = datetime.datetime.strptime(since_date, "%Y-%m-%d") if since_date else None
until_dt = (datetime.datetime.strptime(until_date, "%Y-%m-%d") + datetime.timedelta(days=1)) if until_date else None

log_files = resolve_log_files()
reseller_users = get_reseller_users(reseller) if reseller else set()
if reseller and not reseller_users:
    print(f"[ERR] No accounts found owned by reseller '{reseller}' in /etc/trueuserowners.", file=sys.stderr)
    sys.exit(1)

events = []
ip_counter = collections.Counter()

for lf in log_files:
    try:
        with open_log_stream(lf) as f:
            for line in f:
                m = LOG_LINE_RE.match(line)
                if not m:
                    continue
                ip, proxy_flag, user, ts_str, tz, method, req_path, status_code = m.groups()
                dt = parse_dt(ts_str)
                if not dt:
                    continue
                if since_dt and dt < since_dt:
                    continue
                if until_dt and dt >= until_dt:
                    continue

                if list_ips_user:
                    if user != list_ips_user:
                        continue
                    ip_counter[ip] += 1
                    continue

                if target_user and user != target_user:
                    continue
                if target_ip and ip != target_ip:
                    continue
                if reseller and user not in reseller_users:
                    continue

                act_key, act_sec, summary = classify_request(method, req_path)
                if section and act_sec.lower() != section.lower():
                    continue

                events.append({
                    "epoch": int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()),
                    "timestamp_utc": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "user": user,
                    "method": method,
                    "status": int(status_code),
                    "section": act_sec,
                    "action": act_key,
                    "summary": f"{method} {req_path}" if raw_mode else summary,
                    "raw_path": req_path,
                })
    except Exception as e:
        print(f"[WARN] Could not read {lf}: {e}", file=sys.stderr)


def emit_table(cols, rows, title):
    if not quiet:
        print("=" * 100)
        print(f" {c_bold}{script_name} v{script_version}{c_reset} | {title} | {ts_utc}")
        print("=" * 100)
    if not rows:
        print(f"{c_green}[CLEAN]{c_reset} No matching cPanel access log entries found.")
        return
    widths = [len(c) for c in cols]
    for r in rows:
        for i, v in enumerate(r):
            plain = re.sub(r'\033\[[0-9;]*m', '', str(v))
            if len(plain) > widths[i]:
                widths[i] = min(len(plain), 64)
    print(f"{c_bold}" + "  ".join(cols[i].ljust(widths[i]) for i in range(len(cols))) + f"{c_reset}")
    print("  ".join("-" * widths[i] for i in range(len(cols))))
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            s = str(v)
            plain = re.sub(r'\033\[[0-9;]*m', '', s)
            cells.append(s + (" " * max(0, widths[i] - len(plain))))
        print("  ".join(cells))


if list_ips_user:
    ranked = [{"ip": k, "hits": v} for k, v in ip_counter.most_common()]
    if limit_rows > 0:
        ranked = ranked[:limit_rows]
    payload = {
        "tool": script_name,
        "version": script_version,
        "action": "listips",
        "timestamp_utc": ts_utc,
        "user": list_ips_user,
        "log_files": log_files,
        "unique_ips": len(ip_counter),
        "ips": ranked,
    }
    if fmt == "json":
        print(json.dumps(payload, indent=2))
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["IP", "HITS"])
        for x in ranked:
            w.writerow([x["ip"], x["hits"]])
        sys.stdout.write(buf.getvalue())
    else:
        emit_table(["CLIENT_IP", "HITS"], [[x["ip"], str(x["hits"])] for x in ranked], f"Client IPs | {list_ips_user}")
        if not quiet:
            print(f"\nTotal unique IPs: {len(ip_counter)}")
    sys.exit(0)

events.sort(key=lambda x: x["epoch"])
shown = events[-limit_rows:] if (limit_rows > 0 and len(events) > limit_rows) else events

payload = {
    "tool": script_name,
    "version": script_version,
    "action": "search",
    "timestamp_utc": ts_utc,
    "log_files": log_files,
    "total_matched": len(events),
    "shown_count": len(shown),
    "events": shown,
}
if fmt == "json":
    print(json.dumps(payload, indent=2))
elif fmt == "csv":
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["TIMESTAMP_UTC", "IP", "USER", "STATUS", "SECTION", "ACTION", "SUMMARY"])
    for e in shown:
        w.writerow([e["timestamp_utc"], e["ip"], e["user"], e["status"], e["section"], e["action"], e["summary"]])
    sys.stdout.write(buf.getvalue())
else:
    rows = [[e["timestamp_utc"], e["ip"], e["user"], str(e["status"]), e["section"], e["summary"][:60]] for e in shown]
    scope = target_user or target_ip or f"reseller:{reseller}"
    emit_table(["TIMESTAMP_UTC", "CLIENT_IP", "USER", "HTTP", "SECTION", "ACTION_SUMMARY"], rows, f"cPanel Log Forensics | {scope}")
    if not quiet:
        print(f"\nLogs scanned: {len(log_files)} | Matched: {len(events)} | Shown: {len(shown)}")

sys.exit(0)
PYEOF
)"

  python3 -c "$py_script" \
    "$TARGET_USER" "$TARGET_IP" "$LIST_IPS_USER" "$RESELLER" "$SECTION" \
    "$INCLUDE_ARCHIVE" "$RAW_MODE" "$LOG_OVERRIDE" "$SINCE_DATE" "$UNTIL_DATE" \
    "$LIMIT_ROWS" "$OUTPUT_FMT" "$QUIET" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$ts_utc" \
    "$C_RED" "$C_GREEN" "$C_YELLOW" "$C_CYAN" "$C_BOLD" "$C_RESET"
}

main "$@"
