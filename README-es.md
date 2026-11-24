[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# search-cpanel

![search-cpanel cover](search-cpanel-cover.webp)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/search-cpanel/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requisitos)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20WHM-lightgrey.svg)](#requisitos)

**CLI de Análisis Forense de Logs de Acceso de cPanel & WHM.**

`search_cpanel.sh` analiza `/usr/local/cpanel/logs/access_log` y archivos rotados `.gz`/`.bz2`/`.xz` para reconstruir eventos por **usuario (`-u`)**, **IP exacto (`-i`)**, **reseller (`-r`)** o **IPs únicos (`-l`)**, decodificando rutas modernas **Jupiter / UAPI / WHM API1** y heredadas x3/XML-API en **Table, JSON o CSV**.

> **Inspiración Histórica:** Reimplementación limpia en Bash + Python 3.6+ (`v2.0.0`) inspirada en `search_cpanel` (2011, Matthew Harris, HostGator.com, LLC).

---

## Ejecución Directa

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/search-cpanel/main/search_cpanel.sh -o search_cpanel.sh
chmod +x search_cpanel.sh
sudo ./search_cpanel.sh -u percio -a
```

---

## Ejemplo de Salida Real

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

## Licencia

Licenciado bajo [Apache License 2.0](LICENSE).
