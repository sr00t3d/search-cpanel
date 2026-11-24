[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# search-cpanel

![search-cpanel cover](search-cpanel-cover.webp)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/search-cpanel/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requirements)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20WHM-lightgrey.svg)](#requirements)

**cPanel & WHM Access Log Forensics, Timeline & Action Parser CLI.**

`search_cpanel.sh` parses `/usr/local/cpanel/logs/access_log` and rotated `.gz`/`.bz2`/`.xz` archives to reconstruct chronological timelines of cPanel/WHM actions by **user (`-u`)**, **exact client IP (`-i`)**, **reseller (`-r`)**, or **unique IP frequency (`-l`)**. Decodes modern **Jupiter / Paper Lantern / UAPI (`/execute/`) / WHM API1 (`/json-api/`)** as well as legacy x3 and XML-API endpoints into human-readable summaries or JSON/CSV reports.

> **Historical Inspiration:** Clean-room Bash + Python 3.6+ `v2.0.0` reimplementation inspired by `search_cpanel` (2011, Matthew Harris, HostGator.com, LLC). Eliminates `/bin/zcat $log` shell injection, dead CPAN dependencies (`Date::Parse`, `URI::Escape`), unanchored IP matching (`1.2.3.4` matching `1.2.3.40`), an unimplemented `--reseller` stub, and x3-only regexes.

---

## Requirements

- Linux server running cPanel/WHM (or any Linux host analyzing exported `access_log` files via `--log`) with Bash 4.0+ and Python 3.6+ (standard library only)

---

## Direct Execution

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/search-cpanel/main/search_cpanel.sh -o search_cpanel.sh
chmod +x search_cpanel.sh
sudo ./search_cpanel.sh -u percio -a
```

---

## Usage

```bash
# 1. Reconstruct chronological cPanel/WHM action timeline for a user
sudo ./search_cpanel.sh -u percio

# 2. Filter mail actions across current + rotated .gz archives
sudo ./search_cpanel.sh -u percio -s mail -a

# 3. Search all actions from a suspicious IP since a specific date in JSON
sudo ./search_cpanel.sh -i 198.51.100.10 --since 2026-11-01 -o json

# 4. Rank unique IPs that accessed an account
sudo ./search_cpanel.sh -l percio -a
```

---

## Real Output Example

```text
====================================================================================================
 search_cpanel.sh v2.0.0 | cPanel Log Forensics | percio | 2026-11-24T03:38:10Z
====================================================================================================
TIMESTAMP_UTC        CLIENT_IP      USER    HTTP  SECTION  ACTION_SUMMARY
-------------------  -------------  ------  ----  -------  -----------------------------------------
2026-11-22 10:15:02  198.51.100.10  percio  200   auth     cPanel/WHM: Login event
2026-11-22 10:16:40  198.51.100.10  percio  200   mail     E-mail: Created mailbox suporte@percio.br
2026-11-22 10:18:11  203.0.113.55   percio  200   file     File Manager: Uploaded file(s)

Logs scanned: 2 | Matched: 3 | Shown: 3
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
