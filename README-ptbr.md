[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# search-cpanel

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/search-cpanel/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requisitos)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20WHM-lightgrey.svg)](#requisitos)

**CLI de Forense e Auditoria de Logs de Acesso do cPanel & WHM.**

O `search_cpanel.sh` analisa `/usr/local/cpanel/logs/access_log` e arquivos rotacionados (`.gz`/`.bz2`/`.xz`) para reconstruir a linha do tempo cronológica de ações por **usuário (`-u`)**, **IP exato (`-i`)**, **revenda (`-r`)** ou **ranking de IPs únicos (`-l`)**, decodificando chamadas modernas **Jupiter / UAPI / WHM API1** e legadas x3/XML-API com saída em **Table, JSON ou CSV**.

> **Inspiração Histórica:** Reimplementação limpa em Bash + Python 3.6+ (`v2.0.0`) inspirada no clássico `search_cpanel` (2011, Matthew Harris, HostGator.com, LLC).

---

## Execução Direta

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/search-cpanel/main/search_cpanel.sh -o search_cpanel.sh
chmod +x search_cpanel.sh
sudo ./search_cpanel.sh -u percio -a
```

---

## Exemplo de Saída Real

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

## Licença

Distribuído sob a licença [Apache License 2.0](LICENSE).
